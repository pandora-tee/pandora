import angr


class BaseScase:
    """
    An abstract base class specifying the interface for Scase Explorers.
    """

    def __init__(self, cftrace, dftrace, shortname=''):
        self.shortname = shortname

        self.cftrace_file = cftrace
        self.dftrace_file = dftrace

        # Register this plugin with the Reporter
        self.name = self.__class__.__name__


    @staticmethod
    def get_help_text():
        """
        Scase explorers can be activated via the commandline by their short name. For
        each Scase explorer, a short help text can be queried.
        """
        return (
            "The Basic Scase Explorer should never be included as it does nothing."
        )

    @staticmethod
    def is_default_scase():
        """
        By default, all Scase exlporers are off.
        """
        return False

    @staticmethod
    def supports_arch(angr_arch):
        """
        By default, Scase Explorers are supposed to be architecture-independent, but this can be
        overriden so they are only activated on selected architectures.
        """
        return True
    

    @staticmethod
    def need_cftrace():
        return True
    
    
    @staticmethod
    def need_dftrace():
        return True
      

    def prune_states(self, step_size, simgr: angr.SimulationManager):
        """
        This function is called by the explorer to prune states during the basic block exploration
        """
        pass
