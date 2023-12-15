from collections import defaultdict

from pithos.PluginManager import PluginManager
from ui.action import UserAction

import logging

from utilities.Singleton import Singleton

logger = logging.getLogger(__name__)

system_events = {
    'error'    : 'Upon termination with error states.',
    'explorer' : 'For each symbolic execution step.',
    'start'    : 'Once before explorer starts symbolic execution.',
    'reentry'  : 'Every time the enclave is reentered after an EEXIT',
    'exit'     : 'Once after the explorer finished symbolic execution',
    'system'   : 'On important pandora system events (like internal errors or warnings)'
}


def default_action():
    return UserAction.NONE


class ActionManager(metaclass=Singleton):
    """
    The action manager takes the list of action requests from the command line
    and parses it into UserAction objects mapped to their respective plugin or
    system event.
    """

    def __init__(self, act_events=[]):
        """
        Registers user actions based on a list of tuples (event, action)
        """
        self.actions = defaultdict(default_action)

        if act_events:
            logger.debug("Loading requested actions:")
            for (event, action) in act_events:
                self.actions[event] = UserAction(action)
                logger.debug(f"\tRegistered user action {action} for {event}")
        else:
            logger.debug("No special user actions requested. Reverting do default action NONE.")

    @staticmethod
    def get_system_events():
        return system_events

    @staticmethod
    def get_event_names():
        return list(system_events.keys()) + PluginManager.get_plugin_names()

    @staticmethod
    def get_action_names():
        return UserAction.get_action_names()
