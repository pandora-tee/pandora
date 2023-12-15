"""
Tests for enclave.py to ensure that the enclave range checks return the correct results.
"""


import logging

import ui.log_format
from explorer.enclave import buffer_entirely_inside_enclave, buffer_touches_enclave, _check_entirely_inside, \
    _check_touches

logger = logging.getLogger(__name__)

UINT64_MAX = 1 << 64


num_issues = 0
def _check_one(state, func, case_str, expect, test_addr, test_length, test_enclave_range):
    """
    Performs the check on the given function
    """
    global num_issues
    result = func(state, test_addr, test_length, test_enclave_range)

    if type(test_addr) is int:
        str_addr = hex(test_addr)
    else:
        str_addr = str(test_addr)

    if result != expect:
        logger.error(f'[{str(func.__name__)}] [{case_str}] for '
                     f'addr {str_addr if str_addr else str(test_addr)}, '
                     f'length {test_length}({test_length:#x}), '
                     f'enclave range [{test_enclave_range[0]:#x},{test_enclave_range[1]:#x}].'
                     f' Expected {expect} but got {result}. State constraints are: {ui.log_format.format_fields(state.solver.constraints)}')
        num_issues += 1
    else:
        logger.log(logging.TRACE, f'{func.__name__} {case_str} -- addr:{test_addr}, length:{test_length}, range {test_enclave_range}, expected {expect}, got {result}')

    return result

def _check(state, func, inner_func, case_str, expect, test_addr, test_length, test_enclave_range, ignore_cache_asserts=False):
    ci0 = inner_func.cache_info()
    rv0 = _check_one(state, func, case_str, expect, test_addr, test_length, test_enclave_range)
    ci1 = inner_func.cache_info()
    if not ignore_cache_asserts:
        assert ci1.misses == ci0.misses + 1

    # Now do some checks symbolically
    sym = state.solver.BVS('symbolic', 64)
    s2 = state.copy()
    s2.solver.add(sym == test_addr)
    rv1 = _check_one(s2, func, case_str, expect, sym, test_length, test_enclave_range)
    ci2 = inner_func.cache_info()
    rv2 = _check_one(s2, func, case_str, expect, sym, test_length, test_enclave_range)
    ci3 = inner_func.cache_info()
    if not ignore_cache_asserts:
        assert ci2.misses == ci1.misses + 1 and ci3.hits == ci2.hits + 1
        assert rv0 == rv1 == rv2

def test_buffer_touches_enclave(state):
    """
    Performs tests of the buffer_touches_enclave method.
    The test ONLY uses a _check and _check_both helper function to perform the test but _on purpose_
      does otherwise _NOT_ employ coding practices such as using common functions for tests.
      This is to ensure that the tests below remain easily readable.
      Otherwise, a fully parameterized test of the enclave range functions would easily be too complicated to revisit.
    :return: Number of issues during this test.
    """

    global num_issues
    num_issues = 0
    logger.info('Beginning test buffer_touches_enclave.')
    sym = state.solver.BVS('symbolic', 64)

    def _check_touches_enclave(case_str, expect, test_addr, test_length, test_enclave_range):
        _check(state, buffer_touches_enclave, _check_touches, case_str, expect, test_addr, test_length, test_enclave_range)
        # Now check symbolic value with original state.
        # This should always succeed (should always touch)
        _check_one(state, buffer_touches_enclave, case_str, True, sym, test_length, test_enclave_range)
        # Let's not make assumptions here whether it hits or misses
        # ci4 = _check_entirely_inside.cache_info()
        # assert ci4.misses == ci3.misses + 1

        logger.debug(f'Cache info after this test: {_check_touches.cache_info()}')

    """
    First batch of states will use a simple default enclave address range from 0x1000 - (0x2000-1). 
    This tests the following expectations with their descriptions:
     1. True: Buffer is fully symbolic
     Complete overlaps:
     2. False: Buffer fully lies before the enclave
     3. True: Buffer fully lies inside the enclave
     3.1 True: Buffer IS the enclave
     3.2 True: Buffer fully lies inside the enclave but is only 1 byte large
     4. True: Buffer encapsulates the enclave
     5. False: Buffer fully lies after the enclave
     Partial overlaps:
     6. True: Buffer partially touches the enclave at the start
     7. True: Buffer partially touches the enclave at the end
     Single byte overlaps:
     8. True: The last byte of the buffer touches the enclave
     9. False: The last byte of the buffer is the last byte BEFORE the enclave
     10. True: The first byte of the buffer touches the enclave
     11. False: The first byte of the buffer is the first byte AFTER the enclave
     Overflows:
     12. False: A buffer that overflows the address range but ends BEFORE the enclave
     13. True: A buffer that overflows the address range and ends INSIDE the enclave
     14. True: A buffer that overflows the address range and ends AFTER the enclave
    """
    enclave_range = (0x1000, 0x3000-1)
    logger.info(f'Testing for enclave range [{enclave_range[0]:#x}, {enclave_range[1]:#x}]')

    # 1. Symbolic
    _check_touches_enclave('Case 01', True, state.solver.BVS('symbolic',64), 10, enclave_range)

    # 2-5. Outside/Inside
    _check_touches_enclave('Case 02', False, 0, 10, enclave_range)
    _check_touches_enclave('Case 03', True, enclave_range[0], 10, enclave_range)
    _check_touches_enclave('Case 03.1', True, enclave_range[0], enclave_range[1] - enclave_range[0], enclave_range)
    _check_touches_enclave('Case 03.2', True, enclave_range[0] + 30, 1, enclave_range)
    _check_touches_enclave('Case 04', True, 0, 0x5000, enclave_range)
    _check_touches_enclave('Case 05', False, 0x5000, 10, enclave_range)

    # 6.-7. Partial overlap
    _check_touches_enclave('Case 06', True, enclave_range[0] - 0x1000, 0x2000, enclave_range)
    _check_touches_enclave('Case 07', True, enclave_range[1] - 0x1000, 0x2000, enclave_range)

    # 8.-11. One byte overlap/non-overlap
    _check_touches_enclave('Case 08', True, enclave_range[0] - 19, 20, enclave_range)
    _check_touches_enclave('Case 09', False, enclave_range[0] - 20, 20, enclave_range)
    _check_touches_enclave('Case 10', True, enclave_range[1], 20, enclave_range)
    _check_touches_enclave('Case 11', False, enclave_range[1] + 1, 20, enclave_range)

    # 12.-14. Overflows
    _check_touches_enclave('Case 12', False, UINT64_MAX - 0x500, 0x1000, enclave_range)
    _check_touches_enclave('Case 13', True, UINT64_MAX - 0x1000, 0x3000, enclave_range)
    _check_touches_enclave('Case 14', True, UINT64_MAX - 0x1000, 0xF000, enclave_range)

    """
    Second batch of tests will test enclaves loaded at the start of the address range.
    It performs the same checks (with the same values) as the first batch but partially expects different results:
    Case 9 and 12 are now True since the enclave starts at 0.
    Case 6 and 8 remain True but the overlap is not partial anymore.
    """
    enclave_range = (0, 0x3000 -1)
    logger.info(f'Testing for enclave range [{enclave_range[0]:#x}, {enclave_range[1]:#x}]')

    # 1. Symbolic
    _check_touches_enclave('Case 01', True, state.solver.BVS('symbolic',64), 10, enclave_range)

    # 2-5. Outside/Inside
    _check_touches_enclave('Case 02', True, 0, 10, enclave_range) # NOW TRUE
    _check_touches_enclave('Case 03', True, 0x1000, 10, enclave_range)
    _check_touches_enclave('Case 03.1', True, enclave_range[0], enclave_range[1] - enclave_range[0], enclave_range)
    _check_touches_enclave('Case 04', True, 0, 0x5000, enclave_range)
    _check_touches_enclave('Case 05', False, 0x5000, 10, enclave_range)

    # 6.-7. Partial overlap
    _check_touches_enclave('Case 06', True, enclave_range[0] - 0x1000, 0x2000, enclave_range)
    _check_touches_enclave('Case 07', True, enclave_range[1] - 0x1000, 0x2000, enclave_range)

    # 8.-11. One byte overlap/non-overlap
    _check_touches_enclave('Case 08', True, enclave_range[0] - 19, 20, enclave_range)
    _check_touches_enclave('Case 09', False, enclave_range[0] - 20, 20, enclave_range)
    _check_touches_enclave('Case 10', True, enclave_range[1], 20, enclave_range)
    _check_touches_enclave('Case 11', False, enclave_range[1] + 1, 20, enclave_range)

    # 12.-14. Overflows
    _check_touches_enclave('Case 12', True, UINT64_MAX - 0x500, 0x1000, enclave_range) # NOW TRUE
    _check_touches_enclave('Case 13', True, UINT64_MAX - 0x1000, 0x3000, enclave_range)
    _check_touches_enclave('Case 14', True, UINT64_MAX - 0x1000, 0xF000, enclave_range)

    """
    Third batch of tests will test for enclaves loaded at the end of the address range.
    The addresses in this third batch are different and adjusted to accommodate the high enclave range.
    Differences in expectations:
    Case 5 is now True since there is nothing after the enclave.
    Cases 7,11 overflow now but should stay the same
    Cases 12-14 are skipped since the enclave is at the end.
    """
    enclave_range = (UINT64_MAX - 0x3000, UINT64_MAX - 1 )
    logger.info(f'Testing for enclave range [{enclave_range[0]:#x}, {enclave_range[1]:#x}]')

    # 1. Symbolic
    _check_touches_enclave('Case 01', True, state.solver.BVS('symbolic',64), 10, enclave_range)

    # 2-5. Outside/Inside
    _check_touches_enclave('Case 02', False, 0, 10, enclave_range)
    _check_touches_enclave('Case 03', True, UINT64_MAX - 0x2000, 10, enclave_range)
    _check_touches_enclave('Case 03.1', True, enclave_range[0], enclave_range[1] - enclave_range[0], enclave_range)
    _check_touches_enclave('Case 04', True, 0, UINT64_MAX - 1, enclave_range)
    _check_touches_enclave('Case 05', True, UINT64_MAX - 11, 10, enclave_range) # NOW TRUE

    # 6.-7. Partial overlap
    _check_touches_enclave('Case 06', True, enclave_range[0] - 0x1000, 0x2000, enclave_range)
    _check_touches_enclave('Case 07', True, enclave_range[1] - 0x1000, 0x2000, enclave_range)

    # 8.-11. One byte overlap/non-overlap
    _check_touches_enclave('Case 08', True, enclave_range[0] - 19, 20, enclave_range)
    _check_touches_enclave('Case 09', False, enclave_range[0] - 20, 20, enclave_range)
    _check_touches_enclave('Case 10', True, enclave_range[1], 20, enclave_range)
    _check_touches_enclave('Case 11', False, enclave_range[1] + 1, 20, enclave_range)

    logger.info(f'Done with test buffer_touches_enclave. Had {num_issues} issues.')
    return num_issues
def test_buffer_entirely_inside_enclave(state):
    """


    :return: Number of issues during this test.
    """
    global num_issues
    num_issues = 0
    logger.info('Beginning test buffer_entirely_inside_enclave.')
    sym = state.solver.BVS('symbolic', 64)

    def _check_inside(case_str, expect, test_addr, test_length, test_enclave_range):
        _check(state, buffer_entirely_inside_enclave, _check_entirely_inside, case_str, expect, test_addr, test_length, test_enclave_range)

        # if a buffer lies inside, it should definitely also touch it. Just to add more tests, perform the check_touches if inside is true
        # We do ignore the cache for this as the touches enclave tests have already run and we may run duplicates here
        if expect:
            _check(state, buffer_touches_enclave, _check_touches, case_str, True, test_addr, test_length, test_enclave_range, ignore_cache_asserts=True)

        # Now check symbolic value with original state.
        # This should always fail
        _check_one(state, buffer_entirely_inside_enclave, case_str, False, sym, test_length, test_enclave_range)
        # Let's not make assumptions here whether it hits or misses
        # ci4 = _check_entirely_inside.cache_info()
        # assert ci4.misses == ci3.misses + 1

        logger.debug(f'Cache info after this test: {_check_entirely_inside.cache_info()}')


    """
    First batch of states will use a simple default enclave address range from 0x1000 - (0x2000-1). 
    This tests the following expectations with their descriptions:
    NOTE: The cases differ SLIGHTLY to the ones above for buffer_touches_enclave (especially the partial overlaps)
     1. False: Buffer is fully symbolic
     Complete overlaps:
     2. False: Buffer fully lies before the enclave
     3. True: Buffer fully lies inside the enclave
     3.1 True: Buffer IS the enclave
     4. False: Buffer encapsulates the enclave
     5. False: Buffer fully lies after the enclave
     Partial overlaps:
     6. False: Buffer partially touches the enclave at the start
     7. False: Buffer partially touches the enclave at the end
     Single byte overlaps:
     8. True: The first byte of the buffer is the first byte of the enclave
     9. False: The first byte of the buffer is the last byte BEFORE the enclave
     10. True: The last byte of the buffer is the last byte of the enclave
     11. False: The last byte of the buffer is the first byte AFTER the enclave
     Overflows:
     12. False: A buffer that overflows the address range but ends BEFORE the enclave
     13. False: A buffer that overflows the address range and ends INSIDE the enclave
     14. False: A buffer that overflows the address range and ends AFTER the enclave
    """
    enclave_range = (0x1000, 0x3000-1)
    logger.info(f'Testing for enclave range [{enclave_range[0]:#x}, {enclave_range[1]:#x}]')

    # 1. Symbolic
    _check_inside('Case 01', False, sym, 10, enclave_range)

    # 2-5. Outside/Inside
    _check_inside('Case 02', False, 0, 10, enclave_range)
    _check_inside('Case 03', True, enclave_range[0] + 0x100, 0x100, enclave_range)
    _check_inside('Case 03.1', True, enclave_range[0], enclave_range[1] - enclave_range[0], enclave_range)
    _check_inside('Case 04', False, 0, 0x5000, enclave_range)
    _check_inside('Case 05', False, 0x5000, 10, enclave_range)

    # 6.-7. Partial overlap
    _check_inside('Case 06', False, enclave_range[0] - 0x1000, 0x2000, enclave_range)
    _check_inside('Case 07', False, enclave_range[1] - 0x1000, 0x2000, enclave_range)

    # 8.-11. One byte fit/non-fit
    _check_inside('Case 08', True, enclave_range[0], 20, enclave_range)
    _check_inside('Case 09', False, enclave_range[0] - 1, 20, enclave_range)
    _check_inside('Case 10', True, enclave_range[1] - 19, 20, enclave_range)
    _check_inside('Case 11', False, enclave_range[1] - 18, 20, enclave_range)

    # 12.-14. Overflows
    _check_inside('Case 12', False, UINT64_MAX - 0x500, 0x1000, enclave_range)
    _check_inside('Case 13', False, UINT64_MAX - 0x1000, 0x3000, enclave_range)
    _check_inside('Case 14', False, UINT64_MAX - 0x1000, 0xF000, enclave_range)

    """
    Second batch of tests will test enclaves loaded at the start of the address range.
    It performs the same checks (with the same values) as the first batch but partially expects different results:
    Case 2 is now True since the enclave starts at 0.
    """
    enclave_range = (0, 0x3000 -1)
    logger.info(f'Testing for enclave range [{enclave_range[0]:#x}, {enclave_range[1]:#x}]')

    # 1. Symbolic
    _check_inside('Case 01', False, state.solver.BVS('symbolic', 64), 10, enclave_range)

    # 2-5. Outside/Inside
    _check_inside('Case 02', True, 0, 10, enclave_range) # NOW TRUE
    _check_inside('Case 03', True, 0x1000, 10, enclave_range)
    _check_inside('Case 03.1', True, enclave_range[0], enclave_range[1] - enclave_range[0], enclave_range)
    _check_inside('Case 04', False, 0, 0x5000, enclave_range)
    _check_inside('Case 05', False, 0x5000, 10, enclave_range)

    # 6.-7. Partial overlap
    _check_inside('Case 06', False, enclave_range[0] - 0x1000, 0x2000, enclave_range) # now underflows
    _check_inside('Case 07', False, enclave_range[1] - 0x1000, 0x2000, enclave_range)

    # 8.-11. One byte fit/non-fit
    _check_inside('Case 08', True, enclave_range[0], 20, enclave_range)
    _check_inside('Case 09', False, enclave_range[0] - 1, 20, enclave_range)
    _check_inside('Case 10', True, enclave_range[1] - 19, 20, enclave_range)
    _check_inside('Case 11', False, enclave_range[1] - 18, 20, enclave_range)

    # 12.-14. Overflows
    _check_inside('Case 12', False, UINT64_MAX - 0x500, 0x1000, enclave_range)
    _check_inside('Case 13', False, UINT64_MAX - 0x1000, 0x3000, enclave_range)
    _check_inside('Case 14', False, UINT64_MAX - 0x1000, 0xF000, enclave_range)

    """
    Third batch of tests will test for enclaves loaded at the end of the address range.
    The addresses in this third batch are different and adjusted to accommodate the high enclave range.
    """
    enclave_range = (UINT64_MAX - 0x3000, UINT64_MAX - 1 )
    logger.info(f'Testing for enclave range [{enclave_range[0]:#x}, {enclave_range[1]:#x}]')

    # 1. Symbolic
    _check_inside('Case 01', False, state.solver.BVS('symbolic', 64), 10, enclave_range)

    # 2-5. Outside/Inside
    _check_inside('Case 02', False, 0, 10, enclave_range)
    _check_inside('Case 03', True, UINT64_MAX - 0x2000, 10, enclave_range)
    _check_inside('Case 03.1', True, enclave_range[0], enclave_range[1] - enclave_range[0], enclave_range)
    _check_inside('Case 04', False, 0, UINT64_MAX - 1, enclave_range) # Large buffer
    _check_inside('Case 05', True, UINT64_MAX - 11, 10, enclave_range) # NOW TRUE

    # 6.-7. Partial overlap
    _check_inside('Case 06', False, enclave_range[0] - 0x1000, 0x2000, enclave_range)
    _check_inside('Case 07', False,  enclave_range[1] - 0x1000, 0x2000, enclave_range) # now overflows

    # 8.-11. One byte overlap/non-overlap
    _check_inside('Case 08', True, enclave_range[0], 20, enclave_range)
    _check_inside('Case 09', False, enclave_range[0] - 1, 20, enclave_range)
    _check_inside('Case 10', True, enclave_range[1] - 19, 20, enclave_range)
    _check_inside('Case 11', False, enclave_range[1] - 18, 20, enclave_range)

    logger.info(f'Done with test buffer_entirely_inside_enclave. Had {num_issues} issues.')
    return num_issues
