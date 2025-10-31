import logging

from angr import ExplorationTechnique

import ui
from ui.log_format import get_state_backtrace_formatted

logger = logging.getLogger(__name__)

class TraceLogger(ExplorationTechnique):

    """
    Exploration technique to trace log states.
    """
    def step(self, simgr, **kwargs):
        """
        Performs some trace logging for states.
        """

        # Only print states if they are less than 10 and the logger would even print this
        if logger.getEffectiveLevel() <= logging.TRACE:
            if len(simgr.active) < 10:
                for s in simgr.active:
                    ui.log_format.dump_asm(s, logger, logging.TRACE,
                                           header_msg="Assembly code of the current basic block:")
                    ui.log_format.dump_regs(s, logger, logging.TRACE, only_gen_purpose=False)
                    logger.log(logging.TRACE,'BACKTRACE: ' + ui.log_format.format_fields(get_state_backtrace_formatted(s)))
            else:
                logger.log(logging.TRACE, f'Not printing detailed states since there are too many ({len(simgr.active)})')

        # Nothing to be done for stepping
        simgr = simgr.step(**kwargs)
        return simgr
