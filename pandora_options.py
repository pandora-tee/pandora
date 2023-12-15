# Global variable in Pandora to be able to stop execution from anywhere without needing dependencies
PANDORA_USER_REQUESTED_EXIT = False

from utilities.Singleton import Singleton

# Options for enclave-aware symbolic execution
PANDORA_ENCLAVE_MIXIN_ENABLE = 'PANDORA_ENCLAVE_MIXIN_ENABLE'

# Options for Multithreading
PANDORA_EXPLORE_THREAD_COUNT = 'PANDORA_EXPLORE_THREAD_COUNT'
PANDORA_EXPLORE_THREADING_COUNT_DEFAULT = 1

# Options for enclave reentries:
PANDORA_EXPLORE_REENTRY_COUNT = 'PANDORA_EXPLORE_REENTRY_COUNT'
PANDORA_EXPLORE_REENTRY_COUNT_DEFAULT = 0

# Selfmodifying code option in the angr Project initialization
PANDORA_EXPLORE_ENABLE_SELFMODIFYING_CODE = 'PANDORA_EXPLORE_ENABLE_SELFMODIFYING_CODE'
PANDORA_EXPLORE_ENABLE_SELFMODIFYING_CODE_DEFAULT = False

# Depth first option
PANDORA_EXPLORE_DEPTH_FIRST = 'PANDORA_EXPLORE_DEPTH_FIRST'
PANDORA_EXPLORE_DEPTH_FIRST_DEFAULT = False

# Experimental loop seer limits the depth of loops
PANDORA_EXPLORE_USE_LOOP_SEER = 'PANDORA_EXPLORE_USE_LOOP_SEER'
PANDORA_EXPLORE_USE_LOOP_SEER_DEFAULT = False
PANDORA_EXPLORE_LOOP_SEER_BOUND = 'PANDORA_EXPLORE_LOOP_SEER_BOUND'
PANDORA_EXPLORE_LOOP_SEER_BOUND_DEFAULT = 100

# Option to restrict Pandora to only report unique events (unique IP per plugin)
PANDORA_REPORT_ONLY_UNIQUE = 'PANDORA_REPORT_ONLY_UNIQUE'
PANDORA_REPORT_ONLY_UNIQUE_DEFAULT = False

# Option to remove attacker constraints from the reports. This is useful if they explode in size for long runs and debloats the reports
PANDORA_REPORT_OMIT_ATTACKER_CONSTRAINTS = 'PANDORA_REPORT_OMIT_ATTACKER_CONSTRAINTS'
PANDORA_REPORT_OMIT_ATTACKER_CONSTRAINTS_DEFAULT = False

DEFAULT_PANDORA_OPTIONS = {
    PANDORA_ENCLAVE_MIXIN_ENABLE : True,

    PANDORA_EXPLORE_THREAD_COUNT : PANDORA_EXPLORE_THREADING_COUNT_DEFAULT,
    PANDORA_EXPLORE_REENTRY_COUNT : PANDORA_EXPLORE_REENTRY_COUNT_DEFAULT,
    PANDORA_EXPLORE_DEPTH_FIRST : PANDORA_EXPLORE_DEPTH_FIRST_DEFAULT,
    PANDORA_EXPLORE_USE_LOOP_SEER : PANDORA_EXPLORE_USE_LOOP_SEER_DEFAULT,
    PANDORA_EXPLORE_LOOP_SEER_BOUND : PANDORA_EXPLORE_LOOP_SEER_BOUND_DEFAULT,
    PANDORA_EXPLORE_ENABLE_SELFMODIFYING_CODE : PANDORA_EXPLORE_ENABLE_SELFMODIFYING_CODE_DEFAULT,

    PANDORA_REPORT_ONLY_UNIQUE : PANDORA_REPORT_ONLY_UNIQUE_DEFAULT,
    PANDORA_REPORT_OMIT_ATTACKER_CONSTRAINTS : PANDORA_REPORT_OMIT_ATTACKER_CONSTRAINTS_DEFAULT,

}

class PandoraOptions(metaclass=Singleton):
    """
    This is a wrapper for the options defined in this file above. This file only defines the defaults that can
    be overwritten at runtime. To do so:
    - Call PandoraOptions().set_option(name,val) (e.g. PandoraOptions().set_option(PANDORA_EXPLORE_THREADING_COUNT, 10)
    To read an option:
    - Call PandoraOptions().get_option(PANDORA_EXPLORE_THREADING_COUNT)
    To get a dict of all options:
    - Call PandoraOptions().get_options_dict()
    """
    options = {}
    ctx = None
    # Add all globals as long as they start with PANDORA_
    all_options = list(DEFAULT_PANDORA_OPTIONS.keys())

    def __init__(self):
        # print(pandora.pandora_state['ctx'])
        # Start with a set of default options
        self.options = DEFAULT_PANDORA_OPTIONS.copy()

    def get_options_dict(self):
        return self.options

    def get_option(self, name):
        return self.options[name]

    def set_option(self, name, val):
        self.options[name] = val
