import logging

import archinfo
import explorer.taint as taint

logger = logging.getLogger(__name__)

def get_current_opcode(state):
    # Get current instruction in this basic block
    # we use scratch here since we should always be called during an execution context...
    # If this is ever not the case, we can also as a backup use state.addr. Just be careful to default to
    # state.scratch.ins_addr since that will be the only correct addr during stepping
    scratch_ip = state.scratch.ins_addr

    # Get current basic block (history will always have the addr of the basic block, even during stepping)
    bb_addr = state.history.addr
    blck = state.project.factory.block(bb_addr)

    try:
        ins_index = blck.instruction_addrs.index(scratch_ip)
        ins = blck.disassembly.insns[ins_index]
        return ins.mnemonic 
    except:
        return ''

def pretty_print_state_stack(state, logger=logging.getLogger()):
    proj = state.project
    s = state.callstack
    i = 0
    addr_list = []
    logger.debug('Address backtrace:')
    while i < state.callstack.__len__():
        addr = s.current_function_address
        addr_list.append(addr)
        logger.debug(f'{hex(addr)}')
        s = s.next
        i += 1

    logger.debug('Full backtrace (reversed --> from start to end):')
    for a in addr_list[::-1]:
        if a != 0:
            proj.factory.block(a).pp()

def concretize_value_or_fail(state, value):
    """
    Concretizes a value to an int if it is not already an int.
    Runs into a runtime exception if there is more than one solution.
    :param state: The state to work on
    :param value: The value to concretize to an int
    """
    if type(value) is int:
        concrete_val = value
    else:
        concrete_val = state.solver.eval_one(value)

    return concrete_val

def concretize_value_or_none(state, value):
    """
    Attempt to return the concrete value of a BV. Return none if more than one solution exists.
    :param state: The state to work on
    :param value: The value to concretize to an int
    :return: int | None
    """
    try:
        concrete_val = concretize_value_or_fail(state, value)
    except:
        concrete_val = None

    return concrete_val


def get_sym_reg_value(state, reg_name, disable_actions=True, inspect=False):
    '''
    Returns the SYMBOLIC value of the register specified by name in
    the current state, taking care to not trigger any reg_read breakpoints.

    https://docs.angr.io/core-concepts/simulation#caution-about-mem_read-breakpoint
    '''
    (reg_offset, reg_size) = state.project.arch.registers[reg_name]
    return state.registers.load(reg_offset, reg_size, disable_actions=disable_actions, inspect=inspect)

def get_reg_value(state, reg_name, disable_actions=True, inspect=False):
    '''
    If only one solution possible for this register, returns the CONCRETE
    value. Else returns the SYMBOLIC value of the register specified by name in
    the current state, taking care to not trigger any reg_read breakpoints.

    https://docs.angr.io/core-concepts/simulation#caution-about-mem_read-breakpoint
    :return: int | BVV | BVS
    '''
    reg_sym = get_sym_reg_value(state,reg_name,disable_actions,inspect)
    try:
        reg = state.solver.eval_one(reg_sym)
    except:
        reg = reg_sym
    return reg

def get_sym_memory_value(state, address, size, with_enclave_boundaries=False):
    """
    Returns the SYMBOLIC value of the memory without triggering the mixin.

    Size is in bytes.
    :param size: Size in bytes
    :return: BVS
    """
    if type(address) is int:
        address = state.solver.BVV(address, 64)
    bvs = state.memory.load(address, size, disable_actions=True, inspect=False, with_enclave_boundaries=with_enclave_boundaries)
    return bvs

def get_memory_value(state, address, size, with_enclave_boundaries=False):
    """
    Note on endianness: Angr stores BVVs always in Big Endian, no matter what the architecture normally does.
    """
    bv_bytes = state.solver.eval_one(
        get_sym_memory_value(state, address, size, with_enclave_boundaries=with_enclave_boundaries),
        cast_to=bytes)
    return bv_bytes


def set_memory_value(state, address, value, with_enclave_boundaries=False):
    """
    Note on endianness: Angr stores BVVs always in Big Endian, no matter what the architecture normally does.
    """
    state.memory.store(address, value, endness=archinfo.Endness.BE, with_enclave_boundaries=with_enclave_boundaries)

def symbolize_memory_value(state, address, size_bytes, with_enclave_boundaries=False):
    """
    Overwrites the memory at the provided address/size with symbolic values.

    Size is in bytes(!)
    """
    bvs = state.solver.BVS('symbolized_memory', size_bytes*8)
    state.memory.store(address, bvs, with_enclave_boundaries=with_enclave_boundaries)

def memory_is_tainted(state, address, size):
    bvs = state.memory.load(address, size, disable_actions=True, inspect=False)
    rv = taint.is_tainted(bvs)
    logger.debug(f'Memory at {address} with size={size} --> tainted={rv}')
    return rv

def get_int_from_bytes(bytestring, offset, size):
    return int.from_bytes(bytestring[offset:offset+size], "little") #intel bytes use LE


def set_reg_value(state, reg_name, value):
    '''
    Writes the value to the register without triggering the reg_write breakpoints
    '''
    (reg_offset, reg_size) = state.project.arch.registers[reg_name]
    state.registers.store(reg_offset, value)


def get_reg_size(state, reg_name):
    """
    Returns the size of the register IN BYTES!
    """
    (_, reg_size) = state.project.arch.registers[reg_name]
    return reg_size

def get_reg_bit_size(state, reg_name):
    """
    Returns the size of the register in bits
    """
    return get_reg_size(state, reg_name) * 8

def get_reg_name(state, reg_offset):
    '''
    Returns the register name for a given offset. If this is a subregister, returns the name of the parent register.
    '''
    reg_dict = state.project.arch.register_names
    if reg_offset in reg_dict:
        return reg_dict[reg_offset]

    # this is subregister, find the parent register at the closest smaller offset
    parent_offset = max([x for x in reg_dict.keys() if x < reg_offset])
    parent_name = reg_dict[parent_offset]
    return parent_name
