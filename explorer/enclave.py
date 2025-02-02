from __future__ import annotations
import ctypes

import logging

from angr import BP_BEFORE, BP_AFTER, SimValueError

from sdks.SDKManager import SDKManager
from explorer import taint
from utilities.angr_helper import set_reg_value, get_reg_size
from functools import lru_cache

logger = logging.getLogger(__name__)

# TODO some sanity checks here would help catching sdk bugs: e.g., assert tcs_addr in enclave range(!)
def eenter(eenter_state):
    logger.info(f' --- Initializing state and making it ready for eenter.')

    # First, call the eenter breakpoint
    eenter_state._inspect(
        "eenter",
        BP_BEFORE
    )

    # Start the setup by marking the state global as not active. This should disable all breakpoints like tainting
    eenter_state.globals['pandora_active'] = False

    # Initialize all registers as being attacker tainted
    for reg_name in eenter_state.project.arch.register_names.values():
        size = get_reg_size(eenter_state, reg_name)
        reg = taint.get_tainted_reg(eenter_state, reg_name, size*8)
        set_reg_value(eenter_state, reg_name, reg)

    # After tainting all registers, fill registers that are overwritten by EENTER
    SDKManager().init_eenter_state(eenter_state)
    
    # Set the eexit global to False
    eenter_state.globals['eexit'] = False

    # At the moment no hooked instruction has been skipped
    eenter_state.globals['prev_skipped_inst'] = None

    # Finalize the setup by marking the state global as active
    eenter_state.globals['pandora_active'] = True
    logger.info(f' --- State initialization completed.')

    # Lastly, call the eenter breakpoint again
    eenter_state._inspect(
        "eenter",
        BP_AFTER
    )

def get_enclave_range():
    """
    Enclave range [min_addr,max_addr], i.e., both are *inclusive*.
    """
    min_addr = SDKManager().get_base_addr()
    # we do minus 1 here because min_addr+size is the first address _outside_
    # the enclave, and we want to have the range _inclusive_.
    max_addr = min_addr + SDKManager().get_encl_size() - 1
    return min_addr, max_addr

"""
To speed things up, wrap the rest of the function in an inner function that utilizes lru_caching
Unfortunately, states are not always hashable (sometimes they are weak proxies). This is why we 
restrict the caching to addr and length plus the enclave range.
"""
@lru_cache(maxsize=256, typed=False)
def _check_touches(addr, length, enclave_min_addr, enclave_max_addr, solver):
    if type(addr) is int:
        bv_addr = solver.BVV(addr, 64)
    else:
        # If addr is not an int, we can assume it is a BV
        bv_addr = addr

    if type(length) is not int:
        if not solver.symbolic(length):
            length = solver.eval_one(length)
        else:
            length_max = solver.max_int(length)
            logger.debug(
                f'Concretized symbolic length in touches enclave check. Length is {length} and I concretized to {length_max}')
            length = length_max

    """
    Next, we calculate the maximum address that the buffer may have BEFORE the enclave range.
    This is naturally the last address that even with the full length of the buffer does NOT touch the enclave yet.
      Note, we do not do +1 here as we do a strictly larger than comparison later.
      (i.e., the enclave_min_addr-len is the last address that is OKAY to use before the enclave memory)
    """
    max_addr_before_enclave = enclave_min_addr - length

    # The simplest check is max_addr_before_enclave < addr < enclave_max_addr
    touches_enclave = solver.And(bv_addr.UGT(max_addr_before_enclave), bv_addr.ULE(enclave_max_addr))

    if max_addr_before_enclave < 0:
        # We have to be careful about overflow here
        # Specifically, we can not use the max_addr_before_enclave anymore as that underflows

        # Either, the addr wraps the address space (overflows): Then, check whether the end reaches around
        does_wrap = bv_addr.UGE(bv_addr + length)
        wrap_and_touches_enclave = solver.And(bv_addr.UGT(max_addr_before_enclave), does_wrap)

        # If the addr does not wrap, then do the normal check with an overwritten max_addr_before_enclave
        does_not_wrap = bv_addr.ULT(bv_addr + length)
        bv_addr_end = bv_addr + length - 1 # Inclusive end
        touches_enclave = solver.Or(
            # Either the buffer start is inside the enclave range
            solver.And(bv_addr.UGE(enclave_min_addr), bv_addr.ULE(enclave_max_addr)),
            # Or the buffer end is inside the enclave range
            solver.And(bv_addr_end.UGE(enclave_min_addr), bv_addr_end.ULE(enclave_max_addr)),
            # Or the start is before the enclave start AND the end is after the enclave end (encapsulates the enclave)
            solver.And(bv_addr.ULE(enclave_min_addr), bv_addr_end.UGE(enclave_max_addr))
        )
        no_wrap_and_touches = solver.And(does_not_wrap, touches_enclave)

        e = solver.Or(wrap_and_touches_enclave, no_wrap_and_touches)

    else:
        # No overflow into enclave possible. Do the normal check
        e  = touches_enclave

    return solver.satisfiable(extra_constraints=[e])

def buffer_touches_enclave(state, addr, length, use_enclave_range : None | tuple = None):
    """
    Function to determine whether the buffer [addr, addr+length[ *touches* the enclave range.
    --> Checks whether: enclave_min-len < addr && addr <= enclave_max

    :param state: Any state to run this on. Only used to access the solver.
    :param addr: The start address of the buffer (inclusive)
    :param length: The length of the buffer so that addr + length is the first address AFTER the buffer.
    :param use_enclave_range: An OPTIONAL tuple to overwrite the enclave range or None to use the default enclave range. Use for testing only.
    """
    if not use_enclave_range:
        use_enclave_range = get_enclave_range()
    (enclave_min, enclave_max) = use_enclave_range

    # Call this inner function (depending on cache, this call will be fast)
    return _check_touches(addr, length, enclave_min, enclave_max, state.solver)

"""
To speed things up, wrap the rest of the function in an inner function that utilizes lru_caching
Unfortunately, states are not always hashable (sometimes they are weak proxies), so we pass the solver.
Typed is set to default False to get the speedup and not incur additional checks.
"""
@lru_cache(maxsize=256, typed=False)
def _check_entirely_inside(addr, length, enclave_min_addr, enclave_max_addr, solver):
    if type(length) is not int:
        if not solver.symbolic(length):
            length = solver.eval_one(length)
        else:
            length_max = solver.max_int(length)
            logger.debug(f'Concretized symbolic length in entirely inside enclave check. Length is {length} and I concretized to {length_max}')
            length = length_max

    """
    Now calculate the maximum allowed address for the buffer to still fully lie in the enclave.
    This is the address with which the last byte of the buffer is also the last byte of the enclave.
    With enclave_max_addr being inclusive, we add 1 to get there after subtracting the length.
    """
    max_allowed_addr_inside_enclave = enclave_max_addr - length + 1

    """
    We can abort immediately if the length of the buffer is larger than the size of the enclave.
    These buffers can never fully lie inside the enclave. 
    """
    if enclave_min_addr >= max_allowed_addr_inside_enclave:
        return False

    if type(addr) is int:
        bv_addr = solver.BVV(addr, 64)
    else:
        # If addr is not an int, we can assume it is a BV
        bv_addr = addr

    can_lie_outside = solver.Or(bv_addr.ULT(enclave_min_addr), bv_addr.UGT(max_allowed_addr_inside_enclave))

    """
    The buffer can wrap around (overflow), if the last byte in the buffer (inclusive) may be smaller than the address.
    We subtract one since addr + length is EXCLUSIVE and off by one.
    """
    can_wrap = bv_addr.UGT(bv_addr + length - 1)

    e = solver.Or(can_lie_outside, can_wrap)
    return not solver.satisfiable(extra_constraints=[e])


def buffer_entirely_inside_enclave(state, address, buffer_length, use_enclave_range : None | tuple = None):
    """
    Function to determine whether the buffer [addr, addr+length[ always lies *entirely* inside the enclave.
    --> Checks whether: enclave_min <= addr && addr+len-1 <= enclave_max

    :param state: Any state to run this on. Only used to access the solver.
    :param address: The start address of the buffer (inclusive)
    :param buffer_length: The length of the buffer so that addr + length is the first address AFTER the buffer.
    :param use_enclave_range: An OPTIONAL tuple to overwrite the enclave range or None to use the default enclave range. Use for testing only.
    """
    if not use_enclave_range:
        use_enclave_range = get_enclave_range()
    (enclave_min, enclave_max) = use_enclave_range

    return _check_entirely_inside(address, buffer_length, enclave_min, enclave_max, state.solver)
