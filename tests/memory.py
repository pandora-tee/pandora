import logging

from explorer.enclave import get_enclave_range
from explorer.taint import is_tainted
from sdks.SDKManager import SDKManager
from utilities.angr_helper import get_sym_memory_value

logger = logging.getLogger(__name__)

num_issues = 0
def _check(assertion, bv, test_name, description):
    """
    Checks whether the given BVV adheres to expectations
    """
    global num_issues
    if not assertion:
        logger.error(f'[{test_name}] {description} '
                     f'bv {str(bv)}.'
                     f' Expected True but got {assertion}')
        num_issues += 1
    else:
        logger.debug(f'[{test_name}] {description} '
                     f'bv {str(bv)}. Success.')

def test_default_memory(state):
    """
    Tests the default memory filler mixin.
    1. Tests that default memory inside measured pages is concrete/zero-filled
    2. Tests that default memory inside non-measured pages is symbolic
    3. Tests that default memory outside the enclave is symbolic
   :return: Number of issues during this test.
    """
    global num_issues
    enclave_min, enclave_max = get_enclave_range()

    # Test 1
    # TODO: Not sure how to find this...

    # Test 2
    unmeasured_pages = SDKManager().get_measured_page_information()
    if len(unmeasured_pages) > 0:
        bv = get_sym_memory_value(state, unmeasured_pages[0][0], 100)
        _check(state.solver.symbolic(bv) and is_tainted(bv), bv, 'default_memory', 'Non-measured memory is attacker tainted before initialization:')

    # Test 3
    bv = get_sym_memory_value(state, enclave_min-0x1000, 0x10) # Lies outside enclave, potentially with integer underflow.
    _check(state.solver.symbolic(bv) and is_tainted(bv), bv, 'default_memory', 'Untrusted memory is attacker tainted:')

    return num_issues
