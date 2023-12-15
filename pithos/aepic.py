import angr
from claripy import BVV

from explorer import taint
from explorer.enclave import buffer_entirely_inside_enclave, buffer_touches_enclave
from ui.report import Reporter
from pithos.BasePlugin import BasePlugin
from ui.action import UserAction
import ui.log_format
import logging

from ui.log_format import format_ast
from utilities.angr_helper import concretize_value_or_fail

logger = logging.getLogger(__name__)

# Global variables used by the hooks. Initialized in PointerSanitizationPlugin
taint_action = UserAction.NONE
plugin_shortname = 'aepic'


class AepicPlugin(BasePlugin):
    """
    Plugin for the Aepic leak:
    
    - https://aepicleak.com/aepicleak.pdf
    - https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/stale-data-read-from-xapic.html
    - https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00657.html
    - https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/processor-mmio-stale-data-vulnerabilities.html
    - https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/processor-mmio-stale-data-vulnerabilities.html
    - https://github.com/openenclave/openenclave/security/advisories/GHSA-wm9w-8857-8fgj
    - https://github.com/openenclave/openenclave/security/advisories/GHSA-v3vm-9h66-wm76
    - https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/SecurityGuideForMMIOVulnerabilities.md#vulnerable-area

    Summary AEPIC: check that all *reads* are 8-byte aligned and size <=8 (ie 2/4/8):
    - "Note that naturally aligned 8-byte loads are not affected by this behavior"
    - "reads data from outside the enclave’s ELRANGE at a size and alignment of [minimum] 8 bytes"
    - this seems to be an instance of Shared Buffers Data Read (SBDR): "In processors affected by SBDR, any read that is wider than 4 bytes could potentially have stale data returned from a transaction buffer."

    Summary MMIO stale data:
    - "all *writes* to untrusted memory must either be preceded by the VERW instruction and followed by the MFENCE; LFENCE instruction sequence or must be in multiples of 8 bytes [so def not smaller! -- DRPW], aligned to an 8-byte boundary"
    - "An MFENCE;LFENCE sequence or a serializing instruction after the write can ensure that younger operations that touch secret data do not put that data into a fill buffer entry before the older write uses that fill buffer entry."

    ------------------------------------------------------------------------
    #1 modify `memcpy/memset/memmv/etc` simprocedure optimization:
        1. catch all functions that have `memcpy` in the name
        2. done. make sure src and dst are entirely inside enclave
            2.1 yes: proceed with the simprocedure (fast path)
            2.2 no: proceed with the assembly (slow path)
    
    #2 for every *untrusted* memory access check:    
        1. done reads (AEPIC, SBDR): always 8-byte aligned and size in [1,2,4,8]
        2. writes (DRPW): check either
            * 8-byte aligned and size in [8,16,32,64]; or
            * disassembly and check preceded directly by `VERW` and directly followed by a pair `LFENCE; MFENCE`, then downgrade severity to debug
    ------------------------------------------------------------------------

    Detects whether data is stored outside the first 4 byte of each 16 byte block.
    """

    @staticmethod
    def get_help_text():
        return 'Validates MMIO buffer leaks when interacting with untrusted memory.'

    def init_globals(self):
        global taint_action, plugin_shortname
        taint_action = self.action
        plugin_shortname = self.shortname

    def init_angr_breakpoints(self, init_state):
        init_state.inspect.b('untrusted_mem_read', when=angr.BP_BEFORE, action=check_aepic_read)
        init_state.inspect.b('inside_or_outside_mem_read', when=angr.BP_BEFORE, action=check_aepic_read)
        init_state.inspect.b('untrusted_mem_write', when=angr.BP_BEFORE, action=check_aepic_write)
        init_state.inspect.b('inside_or_outside_mem_write', when=angr.BP_BEFORE, action=check_aepic_write)

def check_aepic_read(state):
    """
    Reports all (AEPIC, SBDR) reads from untrusted memory that are not 8-byte aligned and size is not in [1,2,4,8]
    """
    addr = state.inspect.mem_read_address
    length = state.inspect.mem_read_length

    if type(addr) is int:
        addr = BVV(addr, length)

    logger.debug(f'AEPIC hook: Read from {addr} for {length}')
    if type(length) is not int and length.symbolic:
        # fully ignore symbolic lengths for now
        logger.cricial(f'AEPIC: Ignoring  read with symbolic length {length}; this should never happen in angr')
        return

    concrete_length = concretize_value_or_fail(state, length)

    if state.solver.satisfiable(extra_constraints=[addr[2:0] != BVV(0, 3)]) or concrete_length not in [1,2,4,8]:
        info = f'SBDR read from untrusted memory with length {concrete_length}'
        severity = logging.CRITICAL

        extra = {
            'Address': addr,
            'Length': length,
            'Concretized length' : concrete_length,
        }

        Reporter().report(info, state, logger, plugin_shortname, severity, extra)

    else:
        logger.debug(f'Properly aligned read from untrusted memory.')


def check_aepic_write(state):
    """
    Reports all (DRPW) writes to untrusted memory that are not 8-byte aligned and size is not in [8,16,32,64]
    EXCEPTION: This is safe if write is:
      1. Preceded by 'verw'
      2. Proceeded by 'lfence; mfence' (2 instructions)
    --> Exceptions downgraded to debug
    """
    addr = state.inspect.mem_write_address
    length = state.inspect.mem_write_length
    data = state.inspect.mem_write_expr

    logger.debug(f'AEPIC hook: write to {addr} for {length} with {data}')

    if type(addr) is int:
        addr = BVV(addr, length)

    # Length may be None. In that case, take the size from data
    if length is None:
        length = len(data)

    if type(length) is not int and length.symbolic:
        # fully ignore symbolic lengths for now
        logger.cricial(f'AEPIC: Ignoring  write with symbolic length {length}; this should never happen in angr')
        return

    concrete_length = concretize_value_or_fail(state, length)
    if state.solver.satisfiable(extra_constraints=[addr[2:0] != BVV(0, 3)]) or concrete_length not in [8,16,32,64]:
        info = f'DRPW write to untrusted memory with length {concrete_length}'
        severity = logging.CRITICAL

        extra = {
            'Address': addr,
            'Length': length,
            'Concretized length' : concrete_length,
            'Data' : str(data),
            'Touches enclave' : buffer_touches_enclave(state, addr, length),
            'Entirely inside enclave': buffer_entirely_inside_enclave(state, addr, length)
        }

        """
        There is an exception to the above issue: Instruction is
            1. Preceded by 'verw'
            2. Followed by either 'lfence; mfence' or 'mfence; lfence' (2 instructions)
        """
        # Get current basic block (history will always have the addr of the basic block, even during stepping)
        bb_addr = state.history.addr
        blck = state.project.factory.block(bb_addr)

        # Get current instruction in this basic block
        # we use scratch here since we should always be called during an execution context...
        # If this is ever not the case, we can also as a backup use state.addr. Just be careful to default to
        # state.scratch.ins_addr since that will be the only correct addr during stepping
        prev_okay = False
        next_okay = False
        scratch_ip = state.scratch.ins_addr
        if scratch_ip in blck.instruction_addrs:
            # Only work if the IP we look for is actually in the blck
            ins_index = blck.instruction_addrs.index(scratch_ip)
            ins = blck.disassembly.insns[ins_index]

            # NOTE: verw is not supported by angr, so we have to hook it and
            # keep track in the state.globals if it has been executed.
            prev_ins = state.globals['prev_skipped_inst']
            if prev_ins:
                opcode = prev_ins['opcode']
                opstr = prev_ins['opstr']
                addr = prev_ins['addr']
                size = prev_ins['len']

                # Any instruction hooked by angr will be in its own basic
                # block, so we simply check here if it's directly preceding the
                # current basic block.
                if opcode == 'verw' and (addr + size) == bb_addr:
                    prev_okay = True 
                    extra['VERW'] = f'preceding {opcode} {opstr} instruction executed at {addr:#x}'
                    if ins_index != 0:
                        warn = f'verw not directly preceding {ins.mnemonic} ' + \
                               f'(instruction {ins_index+1} in basic block at {bb_addr:#x})'
                        logger.warning(warn)
                        extra['VERW warning'] = warn

            if ins_index < blck.instructions - 2:
                # This block also contains the next 2 instructions:
                next_inst = blck.disassembly.insns[ins_index + 1]
                next_next_inst = blck.disassembly.insns[ins_index + 2]
                if (next_inst.mnemonic == 'lfence' and next_next_inst.mnemonic == 'mfence') or \
                   (next_inst.mnemonic == 'mfence' and next_next_inst.mnemonic == 'lfence'):
                    next_okay = True

        if prev_okay and next_okay:
            severity = logging.DEBUG

        Reporter().report(info, state, logger, plugin_shortname, severity, extra)
