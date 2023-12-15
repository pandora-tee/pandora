"""
This file maintains all methods that are used to investigate whether an enclave state is unique.
This is not only useful for enclave reentries to only reenter unique states that we did not enter already,
but it will also be useful for pickling only those states that are worth keeping.
"""
import itertools
import logging

from utilities.angr_helper import get_reg_value


def get_reg_diff_summary(state_list, register_list):
    """
    Returns a dictionary of all differences in register values (with count) across the state list given.
    Useful to get an overview of register values across a whole stash.
    """
    reg_vals = {}
    for r in sorted(register_list):
        vals = {}
        for s in state_list:
            val = get_reg_value(s, r)
            if val in vals:
                vals[val] = vals[val] + 1
            else:
                vals[val] = 1
        reg_vals[r] = vals

    return reg_vals


def get_mem_diffs(stash_list, reference_state):
    """
    Returns a dictionary of number of changes to a list of states with this number of changes in comparison
    to the reference state.
    """
    logger = logging.getLogger()
    diff_sizes = {}
    for i in range(len(stash_list)):
        if i % 100 == 0:
            logger.debug(f'Mem diff: Calculated {i} diffs. {len(stash_list) - i} still to go.')
        changed_bytes = list(reference_state.memory.changed_bytes(stash_list[i].memory))
        if len(changed_bytes) > 0:
            diff_str = str(list(reduce_list_to_ranges(changed_bytes)))
            if diff_str in diff_sizes:
                diff_sizes[diff_str].append(stash_list[i])
            else:
                diff_sizes[diff_str] = [stash_list[i]]
    return diff_sizes


def reduce_list_to_ranges(i):
    """
    Reduces a list of integers (e.g. addresses) to a list of tuples of their range (both inclusive).
    Example: print(list(ranges([0, 1, 2, 3, 4, 7, 8, 9, 11])))
    Output: [(0, 4), (7, 9), (11, 11)]
    Taken from: https://stackoverflow.com/questions/4628333/converting-a-list-of-integers-into-range-in-python
    """
    for a, b in itertools.groupby(enumerate(i), lambda pair: pair[1] - pair[0]):
        b = list(b)
        yield b[0][1], b[-1][1]


def get_unique_states(stash_list, reference_state, existing_uniques=None):
    """
    Reduces the stash list to a set of unique states.
    This computation is based on the differences in memory state
    The given reference_state is used to compute the first iteration of differences in memory state and give a
    first grouping of states to reduce complexity.
    """
    if existing_uniques is None:
        existing_uniques = set()

    logger = logging.getLogger()
    logger.debug('Unique state calculation. Generating memory difference buckets...')
    # Split stash intp subgroups of specific changes based from reference state
    unique_state_list = existing_uniques.copy()
    mem_diffs = get_mem_diffs(stash_list, reference_state)
    logger.debug(f'Mem diff bucket sizes: { [len(v) for v in mem_diffs.values()]}')

    # Next iterate through each bucket and only keep unique memory situations
    for changes_group in mem_diffs.values():
        sub_uniques = []
        sub_group_sizes = []
        for s in changes_group:
            found = False
            for i in range(len(sub_uniques)):
                if len(sub_uniques[i].memory.changed_bytes(s.memory)) == 0:
                    found = True
                    sub_group_sizes[i] = sub_group_sizes[i] + 1
                    break
            if not found:
                sub_uniques.append(s)
                sub_group_sizes.append(1)

        unique_state_list.update(sub_uniques)
        logger.debug(f'Current bucket had {len(sub_uniques)} unique states. Group sizes are {sub_group_sizes}')

    # Return the unique set but without the old known uniques
    return unique_state_list - existing_uniques
