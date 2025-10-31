import logging

import claripy
from angr import SimProcedure

import ui
from explorer.enclave import buffer_entirely_inside_enclave, buffer_touches_enclave
from sdks.SDKManager import SDKManager
from utilities.angr_helper import (
    get_reg_value,
    get_sym_memory_value,
    set_memory_value,
    set_reg_value,
)

logger = logging.getLogger(__name__)

SM_ID_UNPROTECTED = 0
SM_ID_ENCLAVE = 1


# clear ZF to indicate Sancus instruction succeeded
def clear_zf(s):
    (sr_offset, sr_size) = s.project.arch.registers["r2"]
    s.registers.store(sr_offset, s.registers.load(sr_offset, sr_size) & ~(0x1 << 1))


def print_info(state, name, opcode, params, desc, criticality=logging.INFO):
    args = "; ".join(f"r{15 - i}={v}" for i, v in enumerate(reversed(params)))
    logger.log(criticality, f"hooking {ui.log_format.format_inline_header(name)} (.word {opcode:#x}) @{state.addr:#x} {args} --> {desc}")


"""
if (opcode==16'h1380)
    inst_full = "SM_DISABLE";
"""


class SimUnprotect(SimProcedure):
    def run(self, opstr="", bytes_to_skip=2, **kwargs):
        print_info(self.state, "sancus_disable", 0x1380, [], "aborting execution path")

        # TODO: this only makes sure the explorer filters these states from the active stash
        # Would be a good idea to throw a BP here for ABISan
        self.state.globals["protections_disabled"] = True
        clear_zf(self.state)

        self.jump(self.state.addr + bytes_to_skip)


"""
if (opcode==16'h1381)
    inst_full = "SM_ENABLE";
"""


class SimProtect(SimProcedure):
    def run(self, opstr="", bytes_to_skip=2, **kwargs):
        print_info(self.state, "sancus_enable", 0x1381, [], "SKIPPING (NOT IMPLEMENTED)", criticality=logging.WARNING)

        clear_zf(self.state)
        self.jump(self.state.addr + bytes_to_skip)


"""
if (opcode==16'h1382)
    inst_full = "SM_VERIFY_ADDR";
"""


class SimAttest(SimProcedure):
    def run(self, opstr="", bytes_to_skip=2, **kwargs):
        print_info(self.state, "sancus_verify", 0x1382, [], "SKIPPING (NOT IMPLEMENTED)", criticality=logging.WARNING)

        clear_zf(self.state)
        self.jump(self.state.addr + bytes_to_skip)


"""
if (opcode==16'h1383)
    inst_full = "SM_VERIFY_PREV";
"""
# DEPRECATED
# https://github.com/sancus-tee/sancus-compiler/blob/dd96baa790ba5bf26c85596568daf9f7818708fd/src/sancus_support/sm_support.h#L466

"""
if (opcode==16'h1384)
    inst_full = "SM_AE_WRAP";
https://github.com/sancus-tee/sancus-compiler/blob/dd96baa790ba5bf26c85596568daf9f7818708fd/src/sancus_support/sm_support.h#L494

Used for wrapping but also for calculating MAC
"""


class SimEncrypt(SimProcedure):
    def run(self, opstr="", bytes_to_skip=2, **kwargs):
        key = get_reg_value(self.state, "r9", False)
        ad_start = get_reg_value(self.state, "r10", False)
        ad_end = get_reg_value(self.state, "r11", False)
        plain = get_reg_value(self.state, "r12", False)
        plain_end = get_reg_value(self.state, "r13", False)
        body = get_reg_value(self.state, "r14", False)
        tag = get_reg_value(self.state, "r15", False)
        params = [key, ad_start, ad_end, plain, plain_end, body, tag]
        print_info(self.state, "sancus_encrypt", 0x1384, params, "symbolizing output state")

        to_encrypt_data = get_sym_memory_value(self.state, plain, plain_end, True)
        mac = get_sym_memory_value(self.state, tag, 2, True)
        # SHOULD DO SOME ENCRYPT WITH KEY HERE
        set_memory_value(self.state, body, to_encrypt_data, True)
        set_memory_value(self.state, tag, mac, True)

        clear_zf(self.state)
        self.jump(self.state.addr + bytes_to_skip)


"""
if (opcode==16'h1385)
    inst_full = "SM_AE_UNWRAP";
https://github.com/sancus-tee/sancus-compiler/blob/dd96baa790ba5bf26c85596568daf9f7818708fd/src/sancus_support/sm_support.h#L587
"""


class SimDecrypt(SimProcedure):
    def run(self, opstr="", bytes_to_skip=2, **kwargs):
        key = get_reg_value(self.state, "r9", False)
        ad_start = get_reg_value(self.state, "r10", False)
        ad_end = get_reg_value(self.state, "r11", False)
        cipher = get_reg_value(self.state, "r12", False)
        cipher_end = get_reg_value(self.state, "r13", False)
        body = get_reg_value(self.state, "r14", False)
        tag = get_reg_value(self.state, "r15", False)
        params = [key, ad_start, ad_end, cipher, cipher_end, body, tag]
        print_info(self.state, "sancus_decrypt", 0x1385, params, "symbolizing output state")

        to_decrypt_data = get_sym_memory_value(self.state, cipher, cipher_end, True)
        # SHOULD DO SOME DECRYPT WITH KEY HERE
        set_memory_value(self.state, body, to_decrypt_data, True)

        clear_zf(self.state)
        self.jump(self.state.addr + bytes_to_skip)


"""
if (opcode==16'h1386)
    inst_full = "SM_ID";
https://github.com/sancus-tee/sancus-compiler/blob/dd96baa790ba5bf26c85596568daf9f7818708fd/src/sancus_support/sm_support.h#L641
"""


class SimGetID(SimProcedure):
    def run(self, opstr="", bytes_to_skip=2, **kwargs):
        addr = get_reg_value(self.state, "r15")
        print_info(self.state, "sancus_get_id", 0x1386, [addr], "constraining r15 inside/outside enclave")

        rv = claripy.BVS("sancus_get_id_rv", 16, explicit_name=False)
        if buffer_entirely_inside_enclave(self.state, addr, 15):
            """
            Case: addr that fully lies inside the enclave
            """
            self.state.add_constraints(rv == SM_ID_ENCLAVE)
        elif buffer_touches_enclave(self.state, addr, 15):
            """
            Case: addr that can lie outside OR inside the enclave
            """
            (text_start, text_end) = SDKManager().get_enclave_range()[0]
            (unprotected_entry, _) = SDKManager().get_exec_ranges()[1]
            self.state.add_constraints(claripy.Or(claripy.And(rv == SM_ID_ENCLAVE, claripy.And(addr.UGE(text_start), addr.ULE(text_end))), claripy.And(rv == SM_ID_UNPROTECTED, addr == unprotected_entry)))
        else:
            """
            Case: addr fully in untrusted memory
            """
            self.state.add_constraints(rv == SM_ID_UNPROTECTED)

        set_reg_value(self.state, "r15", rv)
        clear_zf(self.state)
        self.jump(self.state.addr + bytes_to_skip)


"""
if (opcode==16'h1387)
    inst_full = "SM_CALLER_ID";
"""


class SimGetCallerID(SimProcedure):
    def run(self, opstr="", bytes_to_skip=2, **kwargs):
        print_info(self.state, "sancus_get_caller_id", 0x1387, [], f"returning {SM_ID_UNPROTECTED} (SM_ID_UNPROTECTED)")

        self.jump(self.state.addr + bytes_to_skip)
        set_reg_value(self.state, "r15", SM_ID_UNPROTECTED)


"""
if (opcode==16'h1388)
    inst_full = "SM_STACK_GUARD";
"""

"""
if (opcode==16'h1389)
    inst_full = "CLIX";
"""


class SimClix(SimProcedure):
    IS_FUNCTION = False
    NEEDS_ENDBR = False

    def run(self, opstr="", bytes_to_skip=2, mnemonic="", **kwargs):
        print_info(self.state, "sancus_clix", 0x1389, [], "skipping (checking for nested clix exceptions)")

        # nested clix not allowed: results in runtime exception by Sancus hardware
        # --> used in sancus-support ASSERT/BUG_ON/EXIT macros before infinite loop
        prev_skipped = self.state.globals["prev_skipped_inst"]
        if prev_skipped and (prev_skipped["opcode"] == "CLIX" and prev_skipped["addr"] == self.state.addr - bytes_to_skip):
            logger.warning(f"Aborting path due to nested CLIX @{self.state.addr:#x}")
            self.state.globals["enclave_fault"] = True
        else:
            self.state.globals["prev_skipped_inst"] = {"opcode": "CLIX", "addr": self.state.addr, "len": bytes_to_skip, "opstr": opstr}
            self.jump(self.state.addr + bytes_to_skip)
