import logging

import angr
import claripy
from angr import BP_AFTER, BP_BEFORE, SIM_PROCEDURES, SimProcedure

import ui.log_format
from explorer.enclave import buffer_entirely_inside_enclave
from explorer.taint import is_tainted
from sdks.common import SgxReport, write_struct_to_memory
from sdks.SDKManager import SDKManager
from utilities.angr_helper import (
    concretize_value_or_none,
    get_int_from_bytes,
    get_memory_value,
    get_reg_bit_size,
    get_reg_size,
    get_reg_value,
    get_sym_memory_value,
    get_sym_reg_value,
    set_memory_value,
    set_reg_value,
    symbolize_memory_value,
)

logger = logging.getLogger(__name__)

SIM_REPS_REPORT_NAME = "system-events"
SIM_REPS_REPORTER = None

"""
Useful links:
https://docs.angr.io/extending-angr/simprocedures
"""
x86_arch_regs = {"cmstart", "cmlen", "nraddr", "cs_seg", "ds_seg", "es_seg", "fs_seg", "ss_seg"}
x86_privileged_regs = {"cr0", "cr2", "cr3", "cr4", "cr8"}
x86_fpregs = {f"ymm{i}" for i in range(16)}.union({"sseround", "fpreg", "fptag", "fpround", "fc3210"})
x86_data_regs = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15", "fpreg"}
x86_data_non_fp_regs = x86_data_regs - x86_fpregs


def _get_rip_aware_reg_value(state, reg_name, inst_len):
    """
    Instruction opcodes that work on memory have an operand register.
    If this operand register is the rip, the logic changes slightly as the address is then rip + instruction length.
    This helper function is aware of this nuance.
    """
    rv = get_reg_value(state, reg_name)
    if reg_name == "rip":
        rv += inst_len
    return rv


def get_opstr_addr(state, opstr, inst_len):
    """
    Instruction opcodes decoded by VEX may be in either of these three forms:
     1 <..> ptr [ reg + 0xbeef ]
     2 <..> ptr [ reg - 0xbeef ]
     3 <..> ptr
     4 <..> ptr gs:[ 0xbeef ]
     5 <..> ptr fs:[ 0xbeef ]
     Case 1 and 2 mean that -0xbeef is to be added/subtracted from reg.
     Case 3 means reg is to be taken
     Case 4 and 5 mean to take 0xbeef as a relative offset to fs and gs
    """
    # opstr seems to be in format 'ptr [reg_name]. Maybe a nice regex would be better here.
    prefix = opstr.split("[")[0]
    source_reg = opstr.split("[")[1].split("]")[0]
    if len(prefix) > 0 and prefix[-1] == ":":
        # Source reg is a relative offset from fs or gs
        base = prefix[-3:-1]
        source_addr = get_reg_value(state, base) + int(source_reg, 0)
    elif " + " in source_reg:
        # Source reg is an addition. Split it by space and apply the relative positioning afterwards.
        components = source_reg.split(" + ")
        if not len(components) == 2:
            logger.error(f"Received a weird opcode that I can't decode. {source_reg}")
            exit(1)

        # First get reg value of the register and add that together
        # with the second value, parsed to int
        source_addr = _get_rip_aware_reg_value(state, components[0], inst_len) + int(components[1], 0)
    elif " - " in source_reg:
        # Source reg is a subtraction. Split it by space and apply the relative positioning afterwards.
        components = source_reg.split(" - ")
        if not len(components) == 2:
            logger.error(f"Received a weird opcode that I can't decode. {source_reg}")
            exit(1)

        # First get reg value of the register and add that together
        # with the second value, parsed to int
        source_addr = _get_rip_aware_reg_value(state, components[0], inst_len) - int(components[1], 0)
    else:
        source_addr = get_reg_value(state, source_reg)

    logger.debug(f"Opstr address points to {source_addr:#x}")
    return source_addr


class SimLdmxcsr(SimProcedure):
    """
    A hook for the ldmxcsr instruction that only interacts with the MXCSR
    https://www.felixcloutier.com/x86/ldmxcsr
    """

    def run(self, opstr="", bytes_to_skip=2, **kwargs):
        source_addr = get_opstr_addr(self.state, opstr, bytes_to_skip)
        try:
            mxcsr = get_memory_value(self.state, source_addr, 2, with_enclave_boundaries=True)
            mxcsr = get_int_from_bytes(mxcsr, 0, 2)
        except (angr.errors.SimUnsatError, angr.errors.SimValueError):
            mxcsr = get_sym_memory_value(self.state, source_addr, 2, with_enclave_boundaries=True)
            logger.critical(f"LDMXCSR: symbolic MXCSR={mxcsr} not supported; continuing with default MXCSR=0x3f80..")
            mxcsr = 0x3F80

        # sse rounding control is in bit 13/14 of the MXCSR starting @ byte 8+16 in xrstor data.
        logger.debug(f"storing Pandora shadow register MXCSR={mxcsr}")
        self.state.globals["pandora_mxcsr"] = mxcsr
        sseround_val = (mxcsr & 0x9FFF) >> 13
        set_reg_value(self.state, "sseround", claripy.BVV(sseround_val, 64))

        self.jump(self.state.addr + bytes_to_skip)


class SimFxrstor(SimProcedure):
    """
    A hook that simulates fxrstor
    https://www.felixcloutier.com/x86/fxrstor
    """

    def run(self, opstr="", bytes_to_skip=4, **kwargs):
        # Set logging level for this SimProcedure
        logging_criticality = logging.DEBUG

        # Print state before instruction
        logger.log(logging_criticality, f"hooking `fxrstor {opstr}`")
        # ui.log_format.dump_regs(self.state, logger, logging_criticality, header_msg='Regs before fxrstor:')

        if opstr.startswith("ptr [") or opstr.startswith("["):
            source_addr = get_opstr_addr(self.state, opstr, bytes_to_skip)

            """
            The XSAVE data is quite large and we do not fully support all features of XSAVE/XRSTOR.
            Instead, we focus on the essentials here:
             - Legacy XSAVE data: First 512 bytes that contain FPU/SSE register states.
             (see Section 13.4.1, “Legacy Region of an XSAVE Area” of Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 1)
             - XSAVE Header: 64 bytes following the legacy data. Containing:
             (see Section 13.4.2, “XSAVE Header” of Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 1)
               - XSTATE_BV ( bytes 0:7 ) : Sets the feature set used in the XSAVE data
             (see Section 13.1, “XSAVE Supported Features” of Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 1)
               - XCOMP_BV[63] determines whether the compacted form of XRSTOR is used
            Data style is https://www.felixcloutier.com/x86/fxsave#tbl-3-46
            Angr registers are initialized here https://github.com/angr/archinfo/blob/master/archinfo/arch_amd64.py
            """
            xrstor_data = get_memory_value(self.state, source_addr, 512 + 64, with_enclave_boundaries=True)
            logger.log(logging_criticality, f"XRSTOR data is: {ui.log_format.format_fields(xrstor_data.hex())}")

            """
            First parse XSAVE header
            NOTE: XSTATE_BV is a bit vector (bits 0=x87; 1=sse; 2=avx; 4:3=mpx; 7:5=avx512; etc).
            When bit i is set, component i is loaded from memory;
            else, component i is restored to the defaults of Section 13.6, “Processor tracking of XSAVE Managed State”
               of Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 1

            NOTE: We ignore XCOMP_BV[62:0] as this does only apply to the extended region of the XSAVE area and angr does not
             support any registers stored there anyway
            """
            xstate_bv = get_int_from_bytes(xrstor_data, 512, 8)
            xcomp_bv = get_int_from_bytes(xrstor_data, 512 + 8, 8)
            logger.debug(f"xrstor: read XSTATE_BV={xstate_bv:#x}; XCOMP_BV={xcomp_bv:#x}")

            if xstate_bv == 0:
                logger.debug("xrstor: all-zero xstate_bv; setting registers to defaults")

                # defaults from intel SDM 13.6 PROCESSOR TRACKING OF XSAVE-MANAGED STATE
                for reg_name in self.state.project.arch.register_names.values():
                    if reg_name in x86_fpregs:
                        reg_size = get_reg_bit_size(self.state, reg_name)
                        reg = claripy.BVV(0, reg_size)
                        set_reg_value(self.state, reg_name, reg)

                set_reg_value(self.state, "fc3210", 0x037F)
                set_reg_value(self.state, "fptag", 0xFFFF)
                set_reg_value(self.state, "fpround", 0x0)

            else:
                logger.warning("xrstor: partial non-zero xstate_bv not supported; ignoring and restoring supported registers from memory")

                # FC3210 is set to zero and the last four bytes are overwritten with FSW+FCW
                set_reg_value(self.state, "fc3210", claripy.BVV(get_int_from_bytes(xrstor_data, 0, 4), 64))

                # SSEROUND + FPUROUND are both 8byte large but only really consist of 2 bits each
                # fpu rounding control is bit 10/11 of FCW starting at byte 0 in xrstor data
                fpuround_val = (get_int_from_bytes(xrstor_data, 0, 2) & 0xF3FF) >> 10
                set_reg_value(self.state, "fpround", claripy.BVV(fpuround_val, 64))

                # FPU Tag Word: We set fptag to all available _only_ if this is also the case in the given data.
                # Else, we raise an exception since fptag is complicated and we don't really need it.
                ftw = get_int_from_bytes(xrstor_data, 4, 0)
                if self.state.solver.eval(ftw) == 0:
                    set_reg_value(self.state, "fptag", claripy.BVV(0xFF, 64))
                else:
                    raise ValueError(f"FXSAVE FTW field is not all zero but {ftw}. This is not supported. Aborting.")

                # x87 FPU: Set fpregs as the lower 8 byte of mm registers
                # (10 byte are stored due to Intel extended precision but angr only keeps 8 byte)
                for i in range(0, 8):
                    set_reg_value(self.state, f"mm{i}", get_int_from_bytes(xrstor_data, 32 + (i * 16), 8))

                # SSE: Set lower half of ymm registers (xmm) and upper half to 0
                # NOTE: We do not simulate YMM registers here in Pandora and it must suffice to simulate the XMM registers.
                for i in range(0, 16):
                    set_reg_value(self.state, f"ymm{i}", claripy.BVV(0, 32 * 8) + get_int_from_bytes(xrstor_data, 160 + (i * 16), 16))

            # NOTE: in the standard, non-compacted form of XRSTOR (XCOMP_BV[63] = 0), mxcsr is always read from memory, regardless of xstate_bv
            # sse rounding control is in bit 13/14 of the MXCSR starting @ byte 8+16 in xrstor data.
            if xcomp_bv & 0x8000000000000000:
                mxcsr = 0x1F80
            else:
                mxcsr = get_int_from_bytes(xrstor_data, 8 + 16, 2)
            logger.debug(f"xrstor: storing Pandora shadow register MXCSR={mxcsr:#x}")
            self.state.globals["pandora_mxcsr"] = mxcsr
            sseround_val = (mxcsr & 0x9FFF) >> 13
            set_reg_value(self.state, "sseround", claripy.BVV(sseround_val, 64))

        else:
            # Opcode is malformed or unexpected.
            logger.critical(f"Malformed opcode {opstr} in fxrstor64. Ignoring this and setting all FPU regs to zero.")

            for reg_name in self.state.project.arch.register_names.values():
                if reg_name in x86_fpregs:
                    reg_size = get_reg_bit_size(self.state, reg_name)
                    reg = claripy.BVV(0, reg_size)
                    set_reg_value(self.state, reg_name, reg)

        # ui.log_format.dump_regs(self.state, logger, logging_criticality, header_msg='Regs after fxrstor:')
        # logger.debug(f'skipping {bytes_to_skip} bytes; gonna jump to {self.state.addr + bytes_to_skip:#x}')

        self.jump(self.state.addr + bytes_to_skip)


class SimFxsave(SimProcedure):
    """
    A hook that simulates fxsave
    https://www.felixcloutier.com/x86/fxsave
    """

    def run(self, opstr="", bytes_to_skip=4, **kwargs):
        # Set logging level for this SimProcedure
        logging_criticality = logging.DEBUG

        # Print state before instruction
        logger.log(logging_criticality, f"hooking fxsave with opcode {opstr}")
        ui.log_format.dump_regs(self.state, logger, logging_criticality, header_msg="Regs for fxsave:")

        if opstr.startswith("ptr ["):
            dest_addr = get_opstr_addr(self.state, opstr, bytes_to_skip)

            xsave_bitsize = 512 * 8
            xsave_data = claripy.BVV(0, xsave_bitsize)

            # Data style is https://www.felixcloutier.com/x86/fxsave#tbl-3-46
            # Angr registers are initialized here https://github.com/angr/archinfo/blob/master/archinfo/arch_amd64.py

            # FSW+FCW are stored in fc3210 and go to the first location (byte 0)
            xsave_data += get_sym_reg_value(self.state, "fc3210").zero_extend(xsave_bitsize - get_reg_bit_size(self.state, "fc3210"))  # << 0

            # MXCSR: In xsave_data, mxcsr is at byte 7 in the second block (offset 16) - shift accordingly
            # mxcsr = get_sym_reg_value(self.state, 'mxcsr').zero_extend(xsave_bitsize - get_reg_bit_size(self.state, 'mxcsr'))
            # xsave_data += (mxcsr << (16 + 7) * 8)

            # FPU Tag Word: This is calculated based on the values of fptag:
            # fptag bits == 11 -> Tag word = 0
            #       else       -> Tag word = 1
            ftw = get_reg_value(self.state, "fptag")
            stored_tw = 0
            for i in range(0, 8):
                if not ftw & (0b11 << 2 * i):
                    stored_tw |= 0b1 << i
            xsave_data += claripy.BVV(stored_tw, xsave_bitsize) << 4

            # x87 FPU: mmX data is stored in xsave_data at byte 32 at the zero offsets of each successive 16byte row
            for i in range(0, 8):
                reg = get_sym_reg_value(self.state, f"mm{i}").zero_extend(xsave_bitsize - get_reg_bit_size(self.state, f"mm{i}"))
                xsave_data += reg << (32 + 16 * i) * 8

            # SSE: xmmX data is stored at byte offset 160 in each successive 16byte row
            for i in range(0, 16):
                reg = get_sym_reg_value(self.state, f"xmm{i}").zero_extend(xsave_bitsize - get_reg_bit_size(self.state, f"xmm{i}"))
                xsave_data += reg << (160 + 16 * i) * 8

            # lastly, save xsave data at the given memory location
            set_memory_value(self.state, dest_addr, xsave_data, with_enclave_boundaries=True)

            logger.debug("Completed (F)XSAVE")

        else:
            # Opcode is malformed or unexpected.
            logger.critical(f"Malformed opcode {opstr} in fxsave64. Ignoring this and doing nothing.")

        # In either case, we can now skip the fxrstor64 instruction
        self.jump(self.state.addr + bytes_to_skip)


class SimEnclu(SimProcedure):
    """
    Simulate ENCLU. Initial version from Guardian but heavily extended for Pandora.
    """

    IS_FUNCTION = False

    def run(self, **kwargs):
        logger.debug("hooking ENCLU")
        enclu_length_in_bytes = 3
        if self.state.solver.eval(self.state.regs.eax == 0x0):
            """
            EREPORT: Intel manual Volume 3 §35.16 and §38.4
            EREPORT takes output buffer address in RDX and writes a 521 byte buffer to it
            We completley symbolize this buffer here.
            """
            logger.debug("EREPORT")
            report_dest = get_reg_value(self.state, "rdx")
            report_data_pt = get_reg_value(self.state, "rcx")

            # First create an initial report from the SECS data
            secs = SDKManager().get_secs()
            report = SgxReport()
            for k, v in secs._fields_:
                if "reserved" not in k and hasattr(report, k):
                    v = getattr(secs, k)
                    setattr(report, k, v)
            write_struct_to_memory(self.state, report_dest, report, with_enclave_boundaries=True)

            # Copy the provided report data to the generated report
            report_data = get_sym_memory_value(self.state, report_data_pt, 64, with_enclave_boundaries=True)
            set_memory_value(self.state, report_dest + 320, report_data, with_enclave_boundaries=True)

            # Now symbolize selected fields: key_id and mac at end of report
            symbolize_memory_value(self.state, report_dest + 384, 32 + 16)

            self.jump(self.state.addr + enclu_length_in_bytes)

        elif self.state.solver.eval(self.state.regs.eax == 0x1):
            logger.debug("EGETKEY")

            # simulate a successful egetkey, so the enclave runtime does not abort
            dest_addr = get_reg_value(self.state, "rcx")
            key_data = claripy.BVV(0xDEADBEEFCAFEBABEC0DEFEEDDEFEC8ED, 128)
            set_memory_value(self.state, dest_addr, key_data, with_enclave_boundaries=True)
            set_reg_value(self.state, "rax", claripy.BVV(0, 64))
            self.state.regs.cc_op = 0  # OP_COPY
            self.state.regs.cc_dep1 = 0

            self.jump(self.state.addr + enclu_length_in_bytes)
        elif self.state.solver.eval(self.state.regs.eax == 0x2):
            logger.critical("Unexpected EENTER")
            self.exit(1)
        elif self.state.solver.eval(self.state.regs.eax == 0x4):
            logger.debug("EEXIT")

            # Call EEXIT BEFORE breakpoint
            self.state._inspect("eexit", BP_BEFORE)

            # Mark state as eexited
            self.state.globals["eexit"] = True
            # Do not actively exit this state but just make it jump back to entry.
            # Engine will take care to reset the successor before stepping it.
            self.successors.add_successor(self.state, SDKManager().get_entry_addr(), claripy.true(), "Ijk_Boring")

            # Lastly, call eexit breakpoint again (AFTER)
            self.state._inspect("eexit", BP_AFTER)

        elif self.state.solver.eval(self.state.regs.eax == 0x5):
            logger.debug("EACCEPT")
            # Intel SDK expects EAX to be 0 after a successful EACCEPT, otherwise it will abort.
            set_reg_value(self.state, "rax", claripy.BVV(0, 64))
            self.jump(self.state.addr + enclu_length_in_bytes)
        else:
            logger.critical(f"Unexpected ENCLU with rax {self.state.regs.eax}")
            self.exit(1)


class SimVzeroall(SimProcedure):
    """
    Simulate VZeroall. https://www.felixcloutier.com/x86/vzeroall
    """

    IS_FUNCTION = False

    def run(self, bytes_to_skip=3, **kwargs):
        logger.debug("hooking VZEROALL. Zeroing YMM registers 0-15")

        for i in range(0, 16):
            set_reg_value(self.state, f"ymm{i}", claripy.BVV(0, 32))

        self.jump(self.state.addr + bytes_to_skip)


class SimAbort(SimProcedure):
    IS_FUNCTION = False
    NEEDS_ENDBR = False

    def run(self, **kwargs):
        logger.debug("Reached UD2/INT3")

        # Mark state as failed
        self.exit(-1)


class SimMemcpy(SimProcedure):
    IS_FUNCTION = False
    NEEDS_ENDBR = True

    def run(self, **kwargs):
        dst = self.state.regs.rdi
        src = self.state.regs.rsi
        size = self.state.regs.rdx

        if buffer_entirely_inside_enclave(self.state, dst, size) and buffer_entirely_inside_enclave(self.state, src, size):
            # dst_val = self.state.solver.eval_one(dst)
            # size_val = self.state.solver.eval_one(size)
            ## Only speed up memcpy if both src and dest are entirely inside the enclave.
            ## If either is not fully inside the enclave, we must account for aepic-style issues and not speed up performance
            # src_mem = get_sym_memory_value(self.state, src, size_val, with_enclave_boundaries=True)
            # set_memory_value(self.state, dst_val, src_mem, with_enclave_boundaries=True)
            # self.ret(dst)
            memcpy = SIM_PROCEDURES["libc"]["memcpy"]
            logger.debug(f"calling memcpy {dst} {src} {size}")
            memcpy().execute(self.state, arguments=[dst, src, size])
            self.ret(dst)

        # The else case just returns the SimProc and still performs the hooked memcpy
        else:
            succ = self.state.addr + 4
            logger.debug(f"memcpy from {src} to {dst} ({size} bytes) touches untrusted memory. Fully executing function at {succ} to validate AEPIC alignment requirements.")

            # NOTE: we cannot simply jump back to the same address as this makes angr infinetely call our simprocedure. Thus, we rely on te first instruction being a `endbr64` and jump over that.
            self.jump(succ)


class SimMemcmp(SimProcedure):
    IS_FUNCTION = False
    NEEDS_ENDBR = True

    def run(self, **kwargs):
        s1 = self.state.regs.rdi
        s2 = self.state.regs.rsi
        size = self.state.regs.rdx

        if buffer_entirely_inside_enclave(self.state, s1, size) and buffer_entirely_inside_enclave(self.state, s2, size):
            # Only speed up memcpy if both src and dest are entirely inside the enclave.
            # If either is not fully inside the enclave, we must account for aepic-style issues and not speed up performance
            logger.debug(f"memcmp between {s1} and {s2} ({size} bytes)")
            memcmp = SIM_PROCEDURES["libc"]["memcmp"]
            memcmp().execute(self.state, arguments=[s1, s2, size])
            self.ret()

        # The else case just returns the SimProc and still performs the hooked memcmp
        else:
            succ = self.state.addr + 4
            logger.debug(f"memcmp between {s1} and {s2} ({size} bytes) touches untrusted memory. Fully executing function at {succ} to validate AEPIC alignment requirements.")

            # NOTE: we cannot simply jump back to the same address as this makes angr infinetely call our simprocedure. Thus, we rely on te first instruction being a `endbr64` and jump over that.
            self.jump(succ)


class SimRet(SimProcedure):
    IS_FUNCTION = False
    NEEDS_ENDBR = False

    def run(self, **kwargs):
        logger = logging.getLogger(__name__)
        logger.warning(f"Skipping function at {self.state.regs.rip}: returning 0x0 dummy value..")
        self.ret(0x0)


def _enclave_handle_memset(state, dst, val, size):
    """
    Internal function used by both SimMemset and SimRep->stos
    If memset buffer is entirely inside the enclave, we can fasten up the memset possibly.
    Requires concrete arguments, no symbolic ones
    """
    if val == 0:
        if SDKManager().addr_in_unmeasured_uninitialized_page(dst, size):
            SDKManager().initialize_unmeasured_page(dst, size)
            logger.debug(f"SimMemset: Performing smart memset to {dst:#x} with {val:#x} with size of {size} by marking this as initialized.")
        else:
            logger.debug(f"SimMemset: Ignoring redundant memset to {dst:#x} with {val:#x} with size of {size} as it is in measured enclave memory (which is already zero-initialized).")
    else:
        logger.debug(f"SimMemset: Performing memset to {dst} with {val} with size of {size}")
        memset = SIM_PROCEDURES["libc"]["memset"]
        # Memset expects val to be a BV of size 8 so cast it into a BVV
        memset().execute(state, arguments=[dst, claripy.BVV(val, 8), size])


class SimMemset(SimProcedure):
    IS_FUNCTION = False
    NEEDS_ENDBR = True

    def run(self, **kwargs):
        dst = self.state.regs.rdi
        char = self.state.regs.rsi
        size = self.state.regs.rdx

        # We can do an optimization if the memset is setting unmeasured pages to zero.
        char_val = self.state.solver.eval_one(char)
        dst_val = self.state.solver.eval_one(dst)
        size_val = self.state.solver.eval_one(size)
        if buffer_entirely_inside_enclave(self.state, dst_val, size_val):
            # Potentially fasten up this call
            _enclave_handle_memset(self.state, dst_val, char_val, size_val)
            # Return from hooked function
            self.ret(dst)
        else:
            # Partially untrusted call --> Return to have it simulated in full
            succ = self.state.addr + 4
            logger.debug(f"memset  to {dst_val:#x} ({size} bytes with val {char_val:#x}) touches untrusted memory. Fully executing function at {succ}  to validate AEPIC alignment requirements.")
            # NOTE: we cannot simply jump back to the same address as this makes angr infinetely call our simprocedure. Thus, we rely on te first instruction being a `endbr64` and jump over that.
            self.jump(succ)


x86_rep_map = {
    "b": (1, "al"),
    "w": (2, "ax"),
    "d": (4, "eax"),
    "q": (8, "rax"),
}


class SimRep(SimProcedure):
    """
    Simulate a Rep. A SimProcedure version of the Rep enhancement in the Tracer Technique:
    https://github.com/angr/angr/blob/493cba6b8883fa694be167c9386682c6c157824b/angr/exploration_techniques/tracer.py#L39
    """

    IS_FUNCTION = False

    def run(self, inst=None, **kwargs):
        # Set logging level for this SimProcedure
        logging_criticality = logging.DEBUG
        # logger.log(logging_criticality, 'SimRep: Hooking rep')

        if inst is None:
            raise RuntimeError("SimRep: Rep simulation requires to be called with the capstone instruction.")

        dst = get_sym_reg_value(self.state, "rdi")

        if not inst.mnemonic.startswith("rep"):
            raise RuntimeError(f"SimRep: Incorrectly hooked rep instruction {inst.mnemonic}")

        # Here, simulate a read of the D flag so that breakpoints on DF trigger (e.g. if it is attacker tainted)
        df = get_reg_value(self.state, "d", disable_actions=False, inspect=True)
        if is_tainted(df):
            logger.critical("SimRep: With tainted DF")
        if type(df) is int and df != 1:
            raise ValueError(f"Support for DF=={df} not implemented! (Expected DF==1)")

        inst_stem = inst.insn_name()[:-1]
        inst_qualifier = inst.insn_name()[-1]

        if inst_qualifier not in x86_rep_map:
            # The qualifier for b/w/d/q should be defined above
            raise NotImplementedError("Unsupported size %s" % inst.mnemonic)

        # Take qualifier and get the register value
        multiplier, val_reg_name = x86_rep_map[inst_qualifier]

        rep_count = get_reg_value(self.state, "rcx")

        # Check that rep_count is a concrete value
        rep_count_concrete = concretize_value_or_none(self.state, rep_count)
        if rep_count_concrete is not None:
            rep_count = rep_count_concrete
        else:
            # Rep count is symbolic. This can be a REAL issue!
            # We simulate this with a potential brute force approach: Picking the MAXIMUM value for rep_count

            logger.warning(f"Reached a rep count @ addr {self.state.regs.rip} that appears to be symbolic. This can be a real issue! I will simulate the largest rep count possible and MAY COMPLETELY BREAK this state, but at least we get some plugin fireworks out of it if there is a real issue.")
            rep_count_concrete = self.state.solver.max_int(rep_count)

            # Also send this to the reporter as a system event that we want to keep track of
            if SIM_REPS_REPORTER:
                SIM_REPS_REPORTER.report(
                    "Symbolic rep count",
                    self.state,
                    logger,
                    SIM_REPS_REPORT_NAME,
                    logging.WARNING,
                    extra_info={
                        "Proceeding with max count": str(rep_count_concrete),
                        "instruction": str(inst),
                        "register value": str(rep_count),
                    },
                )

            rep_count = rep_count_concrete

        size = rep_count * multiplier

        if inst_stem == "stos":  # Form of stosb/w/d/q
            val = get_reg_value(self.state, val_reg_name)
            logger.log(logging_criticality, f"SimRep: Simulating stos to {dst} with val {val} and size of {size}")

            if buffer_entirely_inside_enclave(self.state, dst, size):
                # Buffer is entirely inside the enclave -> we can optimize this possibly and fasten it up
                dst_val = self.state.solver.eval_one(dst)
                _enclave_handle_memset(self.state, dst_val, val, size)
            else:
                # Partially untrusted memory. Simulate each individual step to catch aepic style leaks
                for i in range(rep_count):
                    set_memory_value(self.state, dst, val, with_enclave_boundaries=True)

        elif inst_stem == "movs":
            src = get_sym_reg_value(self.state, "rsi")
            logger.log(logging_criticality, f"SimRep: Simulating movs from {src} to {dst} with size of {size}")

            if buffer_entirely_inside_enclave(self.state, dst, size) and buffer_entirely_inside_enclave(self.state, src, size):
                # load and store data as a block
                src_mem = get_sym_memory_value(self.state, src, size)
                set_memory_value(self.state, dst, src_mem, with_enclave_boundaries=True)
            else:
                """
                If the buffer is not _entirely_ inside the enclave, simulate the rep with the number
                of requested slices to allow plugins the chance of reporting one of those individual loads/stores
                """
                for slice in range(rep_count):
                    slice_offset = slice * multiplier
                    src_mem = get_sym_memory_value(self.state, src + slice_offset, multiplier, with_enclave_boundaries=True)
                    set_memory_value(self.state, dst + slice_offset, src_mem, with_enclave_boundaries=True)

            # movs-specific register side effects
            # rsi -= size
            set_reg_value(self.state, "rsi", get_reg_value(self.state, "rsi") - size)

        else:
            raise NotImplementedError(f"Unsupported mnemonic rep type {inst.mnemonic}")

        # Common register side effects
        # rdi += size
        set_reg_value(self.state, "rdi", get_reg_value(self.state, "rdi") + size)
        # rcx = 0
        set_reg_value(self.state, "rcx", 0)

        # And skip to the next instruction
        self.jump(self.state.addr + inst.size)


class Rdrand(angr.SimProcedure):
    """
    Rdrand https://www.felixcloutier.com/x86/rdrand
    """

    IS_FUNCTION = False

    def run(self, opstr="", bytes_to_skip=3, **kwargs):
        # Set CF to 1 to signify RDRAND worked
        self.state.regs.cc_op = 0  # OP_COPY
        self.state.regs.cc_dep1 = 1

        # Check register size and set the register accordingly
        reg_size = get_reg_size(self.state, opstr)
        hex_vals = {2: 0xDEAD, 4: 0xDEADBEEF, 8: 0xDEADBEEFCAFEBABE}
        if reg_size not in hex_vals.keys():
            raise ValueError(f"rdrand on unknown register size {reg_size} (opcode {opstr})")
        val = claripy.BVV(hex_vals[reg_size], reg_size * 8)
        logger.debug(f"hooking rdrand by setting {opstr} to {val}")
        set_reg_value(self.state, opstr, val)

        # Add normal successor after this instruction
        self.jump(self.state.addr + bytes_to_skip)
