import logging

from angr import ExplorationTechnique, SimState

import ui
from explorer.taint import is_tainted
from sdks.SymbolManager import SymbolManager
from ui.action_manager import ActionManager
from ui.log_format import log_always
from ui.report import Reporter, SYSTEM_EVENTS_REPORT_NAME
from utilities.angr_helper import get_reg_value, get_sym_memory_value

logger = logging.getLogger(__name__)
class PandoraLoopSeer(ExplorationTechnique):
    """
    Attempts to break out of obvious infinite loops. Not smart but tries its best.
    """
    def __init__(self, bound:int = None, deferred_stash = 'deferred'):
        super().__init__()

        self.bound = bound
        self.deferred_stash = deferred_stash
        self.sm = SymbolManager()
        self.log_level = logging.INFO
        self.important_log_level = logging.WARNING

    def step(self, simgr, **kwargs):
        """
        Before stepping, check whether the state has been in this loop for a while
        'This loop' refers to the last 2 encountered symbols
        """

        stuck_states = []
        for s in simgr.active:
            ip = get_reg_value(s, 'ip')
            symbol = self.sm.get_symbol(ip)

            """
            We keep two lists that each contain:
             - symbol name
             - count
             - whether this list is the most recently added list (allows to easily swap their recentness)
            """
            if 'loop_stats' in s.globals:
                loop_stats = s.globals['loop_stats']
            else:
                loop_stats = [['', 0, True],['', 0, False]]

            # Go through the list and increment the symbol we are at
            latest = 0
            looped = False
            for idx, symbol_contents in enumerate(loop_stats):
                if symbol_contents[0] == symbol:
                    # We have found our symbol, increment its count
                    looped = True
                    loop_stats[idx][1] = loop_stats[idx][1] + 1
                    loop_stats[idx][2] = True

                    # Set the other most_recent flag to False
                    loop_stats[(idx + 1) % 2][2] = False

                    # Now, also do a check whether the combined count is over the maximum that we want
                    if loop_stats[0][1] + loop_stats[1][1] > self.bound:
                        stuck_states.append(s)
                        logger.log(self.log_level,
                                   f'Possibly stuck state {s} details: {ui.log_format.format_fields(s.globals["loop_stats"])}')

                        # Reset counts for states that are stuck
                        loop_stats[0][1] = 0
                        loop_stats[1][1] = 0

                if symbol_contents[2]:
                    latest = idx

            if not looped:
                # symbol did not exist in our list

                # Swap out the not-most-recently-used one
                loop_stats[(latest + 1) % 2][0] = symbol
                loop_stats[(latest + 1) % 2][1] = 1
                loop_stats[(latest + 1) % 2][2] = True

                # And also swap latest again
                loop_stats[latest][2] = False

            # Update state
            s.globals['loop_stats'] = loop_stats


        if len(stuck_states) > 0 and len(simgr.stashes['deferred']) > 0:
            # Only move states if we have some to move AND we can also swap some back in.
            if len(simgr.active) == len(stuck_states):
                # if we would empty active stash, attempt to move up to as many states back from stuck as we had in active
                before_count = len(simgr.active)
                diff = abs(before_count - len(stuck_states))
                to_move = before_count - diff

                # Select the states to move
                move_stash = simgr.stashes[self.deferred_stash][:to_move]

                # Move the states
                simgr.move(from_stash=self.deferred_stash, to_stash='active', filter_func=lambda x: x in move_stash)

            # And move stuck states from active to stuck stash
            simgr.move(from_stash='active', to_stash=self.deferred_stash, filter_func=lambda x: x in stuck_states)

            logger.log(self.important_log_level , f'Deferred the following states as I believe they are stuck in a loop (stuck in same symbol for > {self.bound} steps): {stuck_states}')

        simgr = simgr.step(**kwargs)
        return simgr