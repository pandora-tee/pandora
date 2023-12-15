import explorer
import ui.log_format as log_fmt
from pithos import abisan, ptrsan, cfsan, debug, aepic

plugins = {
    'abi'      : abisan.ABISanitizationPlugin,
    'ptr'      : ptrsan.PointerSanitizationPlugin,
    'cf'       : cfsan.ControlFlowSanitizationPlugin,
    'dbg'      : debug.DebugPlugin,
    'aepic'    : aepic.AepicPlugin
}

import logging

logger = logging.getLogger(__name__)


class PluginManager:

    def __init__(self, init_state, requested_plugins : list, plugin_actions, reporter, encl_size):

        if 'all' in requested_plugins:
            logger.info(f'Activating {log_fmt.format_warning("all")} plugins...')
            requested_plugins = plugins.keys()

        if 'default' in requested_plugins:
            requested_plugins = set(requested_plugins)
            requested_plugins.remove('default')
            for name, plug in plugins.items():
                if plug.is_default_plugin():
                    requested_plugins.add(name)

        self.active_plugins = {}
        for p in requested_plugins:
            action = plugin_actions[p]
            self.active_plugins[p] = plugins[p](init_state, encl_size, reporter, action, shortname=p)
            logger.info(f"\tActivated plugin {log_fmt.format_inline_header(p)} "
                         f"with user action {log_fmt.format_inline_header(action.name)}")

        # Lastly, also inform the x86 SimProcedures about the reporter object to use.
        # We have to do this only now since otherwise we have a circular import
        explorer.x86.SIM_REPS_REPORTER = reporter

    @staticmethod
    def get_plugin_help():
        """
        Returns a dict of all plugin short names and their help text.
        Adds the special plugins.
        """
        help_dict = PluginManager.get_special_plugins()
        for name, plugin in plugins.items():
            help_dict[name] = plugin.get_help_text()
        return help_dict

    @staticmethod
    def get_plugin_names():
        """
        Returns a list of all plugin short names
        """
        return list(plugins.keys())

    @staticmethod
    def get_special_plugins():
        return {
            'default' : 'Shorthand for ' + ','.join([n for n,p in plugins.items() if p.is_default_plugin()]),
            'all' : 'Shorthand for all plugins'
        }
