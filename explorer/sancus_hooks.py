from angr import SimProcedure
import ui
from utilities.angr_helper import set_reg_value, get_reg_value, get_sym_memory_value, set_memory_value
import logging
logger = logging.getLogger(__name__)

"""
if (opcode==16'h1380)
    inst_full = "SM_DISABLE";
"""
class SimUnprotect(SimProcedure):
    def run(self, opstr='', bytes_to_skip=2, **kwargs):
        #TODO: this only makes sure the explorer filters these states from the active stash
        # Would be a good idea to throw a BP here for ABISan
        self.state.globals['protections_disabled'] = True

        logger.warning('hooking sancus_disable, 0x1380 ---> NOT IMPLEMENTED')
        self.jump(self.state.addr + bytes_to_skip)

"""
if (opcode==16'h1381)
    inst_full = "SM_ENABLE";
"""
class SimProtect(SimProcedure):
    def run(self, opstr='', bytes_to_skip=2, **kwargs):
        logger.warning('hooking sancus_enable, 0x1381 ---> NOT IMPLEMENTED')
        self.jump(self.state.addr + bytes_to_skip)

"""
if (opcode==16'h1382)
    inst_full = "SM_VERIFY_ADDR";
"""
class SimAttest(SimProcedure):
    def run(self, opstr='', bytes_to_skip=2, **kwargs):
        logger.warning('hooking verify_address, 0x1382 ---> NOT IMPLEMENTED')
        self.jump(self.state.addr + bytes_to_skip)

"""
if (opcode==16'h1383)
    inst_full = "SM_VERIFY_PREV";
"""
#DEPRECATED
#https://github.com/sancus-tee/sancus-compiler/blob/dd96baa790ba5bf26c85596568daf9f7818708fd/src/sancus_support/sm_support.h#L466

"""
if (opcode==16'h1384)
    inst_full = "SM_AE_WRAP";
https://github.com/sancus-tee/sancus-compiler/blob/dd96baa790ba5bf26c85596568daf9f7818708fd/src/sancus_support/sm_support.h#L494

Used for wrapping but also for calculating MAC
"""
class SimEncrypt(SimProcedure):
    def run(self, opstr='', bytes_to_skip=2, **kwargs):
        logger.warning(f'hooking sancus_encrypt at {hex(self.state.addr)}, 0x1384 ---> NOT IMPLEMENTED')
        self.jump(self.state.addr + bytes_to_skip)

"""
if (opcode==16'h1385)
    inst_full = "SM_AE_UNWRAP";
https://github.com/sancus-tee/sancus-compiler/blob/dd96baa790ba5bf26c85596568daf9f7818708fd/src/sancus_support/sm_support.h#L587
"""
class SimDecrypt(SimProcedure):
    def run(self, opstr='', bytes_to_skip=2, **kwargs):
        logger.warning(f'hooking sancus_decrypt at {hex(self.state.addr)}, 0x1385 ---> NOT IMPLEMENTED')
        key = get_reg_value(self.state, 'r9', False)
        ad_start = get_reg_value(self.state, 'r10', False)
        ad_end = get_reg_value(self.state, 'r11', False)
        cipher = get_reg_value(self.state, 'r12', False)
        cipher_end = get_reg_value(self.state, 'r13', False)
        body = get_reg_value(self.state, 'r14', False)
        tag = get_reg_value(self.state, 'r15', False)

        to_decrypt_data = get_sym_memory_value(self.state, cipher, cipher_end, True)
        ad = get_sym_memory_value(self.state, ad_start, ad_end, True)
        mac = get_sym_memory_value(self.state, tag, 2, True)
        #SHOULD DO SOME DECRYPT WITH KEY HERE
        set_memory_value(self.state, body, to_decrypt_data, True)

        #set_memory_value()
        self.jump(self.state.addr + bytes_to_skip)

"""
if (opcode==16'h1386)
    inst_full = "SM_ID";
https://github.com/sancus-tee/sancus-compiler/blob/dd96baa790ba5bf26c85596568daf9f7818708fd/src/sancus_support/sm_support.h#L641
"""
class SimGetID(SimProcedure):
    def run(self, opstr='', bytes_to_skip=2, **kwargs):
        logger.debug('hooking sancus_get_id, 0x1386 ---> NOT IMPLEMENTED')
        
        set_reg_value(self.state, 'r15', 0)

        #NOTE
        #SEE sm_entry.s
        # https://github.com/sancus-tee/sancus-compiler/blob/dd96baa790ba5bf26c85596568daf9f7818708fd/src/stubs/sm_entry.s#L109-L118
        #WE SAY THAT THE UNTRUSTED CONTEXT PASSED A VALID RETURN ADDRESS (set r15 to 0 which is the ID of untrusted context), 
        #BUT OUR SYMBOLIC MODEL DOESNT KNOW THIS YET, SO R7 HAS TO BE CONSTRAINED HERE
        #SOMETHING LIKE THIS: 
        #outside_text = solver.Or(state.regs.r7 < text_min, state.regs.r7 > text_max)
        #outside_data = solver.Or(state.regs.r7 < data_min, state.regs.r7 > data_max)

        #BUT this will also be reported as a critical issue see:
        #CFSAN: Symbolic -> (if buffer_entirely_inside_enclave? else report CRITICAL!)
        #To avoid these critical issues entirely we set this continuation point 
        #just hardcoded to the address of the main function

        #inspecting object dumps pointed out that our main function always starts at 0x5c3e, for our tests at least
        set_reg_value(self.state, 'r7', 0x5c3e)

        self.jump(self.state.addr + bytes_to_skip)

"""
if (opcode==16'h1387)
    inst_full = "SM_CALLER_ID";
"""
class SimGetCallerID(SimProcedure):
    def run(self, opstr='', bytes_to_skip=2, **kwargs):
        logger.debug('hooking sancus_get_caller_id, 0x1387 ---> NOT IMPLEMENTED')
        self.jump(self.state.addr + bytes_to_skip)
        set_reg_value(self.state, 'r15', 0)



"""
if (opcode==16'h1388)
    inst_full = "SM_STACK_GUARD";
"""

"""
if (opcode==16'h1389)
    inst_full = "CLIX";
"""

class SimNop(SimProcedure):
    IS_FUNCTION = False
    NEEDS_ENDBR = False

    def run(self, opstr='', bytes_to_skip=2, mnemonic='', **kwargs):
        logger.info(f'skipping over {bytes_to_skip}-byte instruction {ui.log_format.format_inline_header(f"{mnemonic} {opstr}")} at {self.state.addr:#x}')
        self.state.globals['prev_skipped_inst'] = {'opcode': mnemonic, 'addr': self.state.addr, 'len': bytes_to_skip, 'opstr': opstr}

        self.jump(self.state.addr + bytes_to_skip)