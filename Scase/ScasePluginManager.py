import explorer
from sdks.SDKManager import SDKManager
import ui.log_format as log_fmt

from Scase import NemesisOpenIPE

plugins = {
    'nemesis'      : NemesisOpenIPE.NemesisOpenIPE,
}

import logging

logger = logging.getLogger(__name__)


class ScasePluginManager:
    def __init__(self, requested_plugins : list, cftraces: list, dftraces):
        if 'all' in requested_plugins:
            logger.info(f'Activating {log_fmt.format_warning("all")} plugins...')
            requested_plugins = plugins.keys()

        if 'default' in requested_plugins:
            requested_plugins = set(requested_plugins)
            requested_plugins.remove('default')
            for name, plug in plugins.items():
                if plug.is_default_scase():
                    requested_plugins.add(name)
                    
        angr_arch = SDKManager().get_angr_arch()
        self.active_plugins = {}
        for p in requested_plugins:
            if not plugins[p].supports_arch(angr_arch):
                logger.warning(f"\tPlugin {log_fmt.format_inline_header(p)} unsupported "
                               f"for arch {angr_arch}; skipping..")
                continue
            if plugins[p].need_cftrace():
                if plugins[p].need_dftrace():
                    self.active_plugins[p] = plugins[p](cftraces.pop(0), dftraces.pop(0),shortname=p)
                else:
                    self.active_plugins[p] = plugins[p](cftraces.pop(0), [],shortname=p)
            else:
                if plugins[p].need_dftrace():
                    self.active_plugins[p] = plugins[p]([], dftraces.pop(0),shortname=p)
                else:
                    self.active_plugins[p] = plugins[p]([], [],shortname=p)

    


    @staticmethod
    def get_plugin_help():
        """
        Returns a dict of all plugin short names and their help text.
        Adds the special plugins.
        """
        help_dict = ScasePluginManager.get_special_plugins()
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
            'default' : 'None',
            'all' : 'Shorthand for all scase plugins'
        }
