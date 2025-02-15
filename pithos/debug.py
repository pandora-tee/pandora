import logging

import angr
from sdks.SDKManager import SDKManager
from sdks.SymbolManager import SymbolManager
from sdks.common import create_versioned_struct, load_struct_from_memory
from sdks.intel_linux_sgx_structs import GlobalData

from ui.report import Reporter
from utilities.angr_helper import get_memory_value, get_reg_value
from pithos.BasePlugin import BasePlugin

logger = logging.getLogger(__name__)

debug_shortname = 'dbg'

class DebugPlugin(BasePlugin):

    def init_globals(self):
        global debug_shortname
        debug_shortname = self.shortname

    @staticmethod
    def is_default_plugin():
        return False

    @staticmethod
    def get_help_text():
        return 'Debug plugin.'

    def init_angr_breakpoints(self, init_state):
        #init_state.inspect.b('constraints', when=angr.BP_BEFORE, action=constraints_hook)
        #init_state.inspect.b('address_concretization', when=angr.BP_AFTER, action=concretization_hook)
        # init_state.inspect.b('exit', when=angr.BP_BEFORE, action=jmp_hook)
        init_state.inspect.b('eexit', when=angr.BP_BEFORE, action=eexit_hook)
        logger.debug(f'Debug plugin enabled')

def _prettify_state(dict, key, default=None):
    if key in dict:
        return f'{key:#x} = {dict[key]}'
    elif default:
        return default
    return hex(key)

eexit_count = 0
def eexit_hook(state: angr.sim_state.SimState):
    """
    Dump the g_global_data struct if it appears and Intel SDK binary.
    """
    extra_sec = None
    global_data_pt = SymbolManager().symbol_to_addr('g_global_data')
    if global_data_pt is not None:
        #NOTE: this is for now hardcoded to v2.19, but could also be retrieved via the SymbolManager (`SGX_TRTS_VERSION_` or so)
        global_data_type = create_versioned_struct(GlobalData, 2, 19)
        global_data = load_struct_from_memory(state, global_data_pt, global_data_type)

        enclave_state_pt = SymbolManager().symbol_to_addr('g_enclave_state')
        enclave_state = int.from_bytes(get_memory_value(state, enclave_state_pt, 4), 'little')
        enclave_state = _prettify_state( {
            0x0: 'ENCLAVE_INIT_NOT_STARTED',
            0x1: 'ENCLAVE_INIT_IN_PROGRESS',
            0x2: 'ENCLAVE_INIT_DONE',
            0x3: 'ENCLAVE_CRASHED',
        }, enclave_state)    
        
        rv = get_reg_value(state, 'rsi')
        rv = _prettify_state( {
            0x0: 'SGX_SUCCESS',
            0x1: 'SGX_ERROR_UNEXPECTED',
            0x1006: 'SGX_ENCLAVE_CRASHED',
        }, rv)

        reason = get_reg_value(state, 'rdi')
        reason = _prettify_state( {
            0xffffffffffffffff: 'OCMD_ERET',
        }, reason, default=f'ECMD_OCALL nb #{reason:#x}')

        extra_sec = {'Intel SDK-specific info': [
                    ('', {
                        'g_enclave_state': enclave_state,
                        'EEXIT reason': reason,
                        'EENTER return value': rv,
                    },'table'),
                    ('Enclave global data', str(global_data), 'verbatim'),
                    ]}

    """
    Debug report every state that eexits. Make them unique by giving each an individual ID on the info
    """
    global eexit_count, debug_shortname
    Reporter().report(
        f'State {eexit_count} eexited',
        state,
        logger,
        debug_shortname,
        logging.INFO,
        #extra_info={'symbol table': SymbolManager().symbol_table},
        extra_sections=extra_sec
    )

    eexit_count += 1


def jmp_hook(state: angr.sim_state.SimState):
    ip = state.scratch.ins_addr
    logger.info(f'Jump hook: {str(state.inspect.exit_target)} @{ip}')

def constraints_hook(state: angr.sim_state.SimState):
    constraints = state.inspect.added_constraints

    # Break whenever a constraint is added and print the constraint
    ip = get_reg_value(state, 'ip')
    # sym = state.project.loader.find_symbol(ip, fuzzy=True)
    logger.info(f'Constraints hook: {str(constraints)} @{ip}')
    # state.block().pp() # Do not use this, for some weird reason it breaks stuff?


#    # Investigation: check if current block contains a conditional jump
#    block = state.block()
#    for stmt in block.vex.statements:
#        if isinstance(stmt, pyvex.IRStmt.Exit):
#           logger.debug(f'Condition added on statement: {stmt} with guard {stmt.guard} and target {stmt.dst}')
#           block.pp()


# HACK: for some reason angr runs into unexplainable unsat states with symbolic
# RFLAGS.DF, so we simply intercept and override these below in a clean
# solver with the constraint that attaker-controlled DF=1, so we can proceed
# and explore sanely past `rep stos`
def concretization_hook(state):
    addr = state.inspect.address_concretization_expr
    res = state.inspect.address_concretization_result
    op = state.inspect.address_concretization_action
    stra = state.inspect.address_concretization_strategy
    con = state.inspect.address_concretization_add_constraints
    ip = state.regs.ip

    # TODO perhaps strategy to concretize as close as possible to the enclave range?!
    if type(res) is list:
        res_str = ','.join([f"{r:#x}" for r in res])
        logger.info(f'concretizing {op} @{ip} from {addr} to [{res_str}] with extra constraints {con}')
    else:
        logger.info(f'concretizing {op} @{ip} from {addr} to {res} with extra constraints {con}')
    logger.info(f'strategy {stra}')
#   if res is None and not state.solver.satisfiable():
#       logger.critical(f'hooking unsat {op} address concretization')
#       s = state.project.factory.blank_state()
#       s.solver.add(state.regs.d == 1)
#       dump_attacker_constraints(s, logger)
#       dump_solver(s, addr, logger)
#       state.inspect.address_concretization_result = [s.solver.eval_one(addr)]
