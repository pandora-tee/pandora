import logging

from angr import ExplorationTechnique

from sdks.SymbolManager import SymbolManager
from ui.report import Reporter, SYSTEM_EVENTS_REPORT_NAME
from utilities.angr_helper import get_reg_value

logger = logging.getLogger(__name__)
class ExplorationStatistics(ExplorationTechnique):
    """
    Statistics exploration technique that reports a symbol count at the end of each run
    """
    def __init__(self, init_state):
        super().__init__()

        self.sm = SymbolManager()
        self.log_level = logging.INFO
        self.symbol_stats = {}
        self.init_state = init_state

    def step(self, simgr, **kwargs):
        """
        Before stepping, keep statistics of the symbol this step will be in.
        """
        for s in simgr.active:
            ip = get_reg_value(s, 'ip')
            symbol = self.sm.get_symbol(ip)

            if symbol == 'UNKNOWN':
                symbol += f' <{ip:#x}>'

            if symbol in self.symbol_stats:
                self.symbol_stats[symbol] = self.symbol_stats[symbol] + 1
            else:
                self.symbol_stats[symbol] = 1

        simgr = simgr.step(**kwargs)
        return simgr

    def report_stats(self):

        Reporter().report("Runtime statistics of hit symbols by time of occurrence",
                          self.init_state,
                          logger,
                          SYSTEM_EVENTS_REPORT_NAME,
                          logging.INFO,
                          extra_sections= {
                              'Runtime statistics': [(
                                 'Hit symbols ordered by time of occurrence',
                                 self.symbol_stats, # Dicts preserve insertion order in Python 3.7+
                                 'table'
                              )]
                          })

        Reporter().report("Runtime statistics of hit symbols by count",
                          self.init_state,
                          logger,
                          SYSTEM_EVENTS_REPORT_NAME,
                          logging.INFO,
                          extra_sections= {
                              'Runtime statistics': [(
                                 'Hit symbols ordered by count',
                                 dict(sorted(self.symbol_stats.items(), key=lambda item: item[1])),
                                 'table'
                              )]
                          })
