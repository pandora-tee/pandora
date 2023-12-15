from ui.action import UserAction
from ui.report import Reporter


class BasePlugin:
    """
    An abstract base class specifying the interface for Pandora plugins.
    """

    def __init__(self, init_state, encl_size, reporter, usr_act=UserAction.NONE, shortname=''):
        self.action = usr_act
        self.encl_size = encl_size
        self.reporter = reporter
        self.shortname = shortname

        # Register this plugin with the Reporter
        self.name = self.__class__.__name__
        desc = self.get_help_text()
        self.reporter.register_plugin(self.name, desc, self.shortname)

        # Init this plugin
        self.init_globals()
        self.init_angr_breakpoints(init_state)

    def init_angr_breakpoints(self, init_state):
        """
        Plugins may override this method to register custom callback functions
        that implement their functionality via angr breakpoints on the passed
        init_state parameter, i.e., as follows:

        init_state.inspect.b('event_name', when=angr.BP_AFTER, action=callback_function)

        @see https://docs.angr.io/core-concepts/simulation#breakpoints
        """
        pass

    def init_globals(self):
        """
        Plugins may override this method to save the UserAction to be called on
        plugin-specific events in a global variable for use in angr breakpoint
        callbacks.
        """
        pass

    @staticmethod
    def get_help_text():
        """
        Plugins can be activated via the commandline by their short name. For
        each each plugin, a short help text can be queried.
        """
        return (
            "The Base Plugin should never be included as it does nothing."
        )

    @staticmethod
    def is_default_plugin():
        """
        By default, all plugins are seen as default plugins. However some blow up
        runtime so much that they exclude themselves from that list. If this is set to
        false, then the plugin is still included when the all option is set though.
        """
        return True