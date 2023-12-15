import logging

import angr
from angr import ExplorationTechnique

import ui
from explorer.enclave import eenter
from explorer.unique import get_mem_diffs, get_unique_states
from ui.action import UserAction
from ui.log_format import log_always

logger = logging.getLogger(__name__)
class EnclaveReentry(ExplorationTechnique):
    """
    Performs the reentry of the enclave for states that are marked as eexited AND are unique.
    """
    def __init__(self, enclave_reentry_count: int, init_state: angr.SimState, unique_state_list: set, user_action: UserAction):
        super().__init__()

        self.enclave_reentry_count = enclave_reentry_count
        self.initial_state = init_state
        self.performed_reentries = 0
        self.unique_states = unique_state_list
        self.action = user_action

    def _is_contained(self, state, stash):
        """
        Returns true if state is already contained as a unique state in the stash. False otherwise.
        """
        for unique_state in stash:
            changed_bytes = list(unique_state.memory.changed_bytes(state.memory))
            if len(changed_bytes) == 0:
                reverse_changes = list(state.memory.changed_bytes(unique_state.memory))
                if len(reverse_changes) == 0:
                    return True

    def step(self, simgr, **kwargs):

        # Only once before first step, put the init state into the uniques
        if len(simgr.stashes['uniques']) == 0:
            simgr.populate('uniques', [self.initial_state])

        simgr = simgr.step(**kwargs)

        """
        After stepping, remove the eexited stash by putting all eexited states either into the new_uniques stash
        or by dropping them if they are not unique 
        """
        if self.enclave_reentry_count > 0 and len(simgr.stashes['eexited']) > 0:
            new_count = 0
            for s in simgr.stashes['eexited']:
                is_new_unique = True
                if self._is_contained(s, simgr.stashes['new_uniques']):
                    is_new_unique = False

                if is_new_unique and self._is_contained(s, simgr.stashes['all_uniques']):
                    is_new_unique = False

                if is_new_unique:
                    new_count += 1
                    simgr.move(from_stash='eexited', to_stash='new_uniques', filter_func=lambda x: x is s)

            # Clean up eexit stash after removing uniques
            logger.info(f'Cleaned up {len(simgr.stashes["eexited"])} eexited states, we got {new_count} new uniques for a total of ({len(simgr.stashes["new_uniques"])},{len(simgr.stashes["uniques"])}) new/old uniques')
            simgr.drop(stash='eexited')
            simgr._copy_stashes()

        """
        After stepping, our active stash may be empty so we check whether we may want to reenter some of the states
        """
        states_exhausted = len(simgr.active) == 0
        if states_exhausted and self.performed_reentries < self.enclave_reentry_count and len(simgr.stashes['new_uniques']) > 0:
            self.performed_reentries += 1
            log_always(logger, f'--- Exhausted all my states. Restarting all new unique states...')

            for state in simgr.stashes['new_uniques']:
                eenter(state)

            # restart all new unique states (the ones that we did not restart)
            simgr.move(from_stash='new_uniques', to_stash='active')
            # And copy all new uniques to the uniques stash
            simgr.populate('uniques', simgr.stashes['active'])

            # new_uniques = get_unique_states(simgr.stashes['eexited'], self.initial_state, existing_uniques=simgr.stashes['uniques'])
            # logger.debug(f'Found {len(new_uniques)} unique states.')
            # if len(new_uniques) > 0:
            #     logger.debug(f'Their diffs:\n{ui.log_format.format_fields(get_mem_diffs(list(new_uniques), self.initial_state))}')
            #
            #     # Call eenter on all unique states that we did not encounter yet
            #     logger.info(f' --- Preparing {len(new_uniques)} states for reentry...')
            #     for state in new_uniques:
            #         eenter(state)
            #
            #     # Add the new uniques to the existing unique list
            #     self.unique_states.update(new_uniques)
            #     logger.info(f'Set of unique states now has a size of {len(self.unique_states)} to reduce state set for next round.')
            #
            #     # And move those states that are now restored back to the active stash (i.e. the unique states)
            #     simgr.move(from_stash='eexited', to_stash='active',
            #                     filter_func=lambda s: s.globals['eexit'] is False)
            #
            #     logger.info(f'successors of {len(new_uniques)} unique states have moved to the '
            #                  f'active states (now size {len(simgr.active)}).')
            #
            # else:
            #     logger.info('Doing nothing. Not reentering enclave, we are done.')

            log_always(logger, f'--- Done with this reentry. Active stash now has size {len(simgr.active)}')

            self.action(state={'active': simgr.active, 'init_state': self.initial_state}, info='[enclave reentry]')

        return simgr