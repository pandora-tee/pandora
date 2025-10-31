import logging
import sys

import angr

import pandora_options as po
import ui.log_format as log_format
import ui.log_setup
from explorer.engine.PandoraEngine import PandoraEngine
from ui.action import UserAction
from ui.action_manager import ActionManager
from ui.log_format import get_state_backtrace_compact, get_state_backtrace_formatted
from utilities.Singleton import Singleton

from .breakpoints import PANDORA_EVENT_TYPES, PANDORA_INSPECT_ATTRIBUTES
from .memory.EnclaveAwareMemory import EnclaveAwareMemory
from .techniques.ControlFlow import ControlFlowTracker
from .techniques.EnclaveReentry import EnclaveReentry
from .techniques.ExplorationStatistics import ExplorationStatistics
from .techniques.PandoraDFS import PandoraDFS
from .techniques.PandoraLoopSeer import PandoraLoopSeer
from .techniques.TraceLogger import TraceLogger

logger = logging.getLogger(__name__)

class AbstractExplorer(metaclass=Singleton):
    def __init__(self, binary_path='', action=UserAction.NONE, base_addr=0, angr_backend='elf', angr_arch='x86_64'):
        self.action = action
        self.binary_path = str(binary_path)
        self.base_addr = base_addr

        """
        Initialize angr settings
        """
        # First, register enclave memory as default memory in simstate
        from angr.sim_state import SimState
        SimState.register_default('sym_memory', EnclaveAwareMemory)

        # Second, register Pandora event_types and Pandora inspect_attributes with angrs inspect module
        angr.state_plugins.inspect.event_types = angr.state_plugins.inspect.event_types.union(PANDORA_EVENT_TYPES)
        angr.state_plugins.inspect.inspect_attributes = angr.state_plugins.inspect.inspect_attributes.union(
            PANDORA_INSPECT_ATTRIBUTES)

        # Last, create angr project and initial state
        angr_main_opts = {'backend': angr_backend, 'arch': angr_arch}

        """
        Some enclaves write to executable pages. Angr by default does not support this and support has to be explicitly
        set via the selfmodifying_code paramenter which can have _big_ performance impacts.
        For some enclaves like libos, runtime randomization, or encrypted code - this use case however can be useful.
        For some use cases this is useful but it has performance impacts and has issues like not properly
        handling ud2. So we disable it by default
        """
        selfmodifying_code = po.PandoraOptions().get_option(po.PANDORA_EXPLORE_ENABLE_SELFMODIFYING_CODE)

        if base_addr >= 0:
            angr_main_opts['base_addr'] = base_addr
            angr_main_opts['force_rebase'] = True
        logger.debug(f'Creating angr project with selfmodifying_code={selfmodifying_code} and extra options\n{log_format.format_fields(angr_main_opts)}')
        if selfmodifying_code:
            logger.warning('Pandora/angr support for selfmodifying code is experimental, expect issues (e.g., UD2 is incorrectly skipped over)!')
        self.proj = angr.Project(binary_path, main_opts=angr_main_opts, engine=PandoraEngine, selfmodifying_code=selfmodifying_code)
        self.initial_state = None
        self.simgr = None
        logger.debug('Angr project created and Explorer initialized.')

    def get_init_state(self):
        if not self.initial_state:
            self.initial_state = self.proj.factory.blank_state()

            # Set angr options
            # Unconstrained registers should be symbolized. Setting ignored by EnclaveMemoryFillerMixin
            # self.initial_state.options['SYMBOL_FILL_UNCONSTRAINED_REGISTERS'] = True

            """
            Unconstrained memory does not really exist in Pandora:
             1. Non-enclave memory is symbolized by the EnclaveAwareMixin
             2. Enclave memory is either:
                - Non-measured : This is technically attacker-controlled and is symbolized by the EnclaveMemoryFillerMixin
                - Measured : This is zero filled by the EnclaveMemoryFillerMixin
            """
            # Zero fill measured enclave memory. Ignored by EnclaveMemoryFillerMixin
            # self.initial_state.options['ZERO_FILL_UNCONSTRAINED_MEMORY'] = True

            # Add all pandora options to initial state
            for k, v in po.PandoraOptions().get_options_dict().items():
                self.initial_state.options.register_option(k, {type(v)}, default=v)
                logger.debug(f'PandoraOptions: Registering {k} (type {type(v)}, value {str(v)}) with initial state.')

            logger.info(f'Pandora Options on start:\n{ui.log_format.format_fields(po.PandoraOptions().get_options_dict(), normal_format=True)}')

            # Optionally increase Python's recursion limit for exploring loops with symbolic upper bound
            stack_depth = po.PandoraOptions().get_option('PANDORA_EXPLORE_STACK_DEPTH')
            if stack_depth != po.PANDORA_EXPLORE_STACK_DEPTH_DEFAULT:
                logger.info(f'Setting maximum depth of the Python interpreter stack to {stack_depth}')
                sys.setrecursionlimit(stack_depth)

        return self.initial_state

    def make_step(self):
        """
        Performs a single step in the exploration.
        Should return a tuple of a boolean whether exploration is finished and a list of errored states.
        """
        raise 'Not implemented'

    def get_all_traces(self):
        s = []
        for state in self.simgr.eexited:
            s.append(get_state_backtrace_formatted(state))
        return s

    def get_running_statistics(self):
        stats = {
            'active': len(self.simgr.active),
        }

        if po.PandoraOptions().get_option(po.PANDORA_EXPLORE_DEPTH_FIRST):
            stats['deferred'] = len(self.simgr.stashes['deferred'])

        if po.PandoraOptions().get_option(po.PANDORA_EXPLORE_REENTRY_COUNT) > 0:
            stats['new_uniques'] = len(self.simgr.stashes['new_uniques'])
            stats['uniques'] = len(self.simgr.stashes['uniques'])
        else:
            stats['eexited'] = len(self.simgr.eexited)

        return stats

    def print_stash_sizes(self):
        if not self.simgr:
            return 'Stashes empty.'
        else:
            stash_state = ', '.join([
                f'{k} ({len(self.simgr.stashes.get(k))})' for k in filter(lambda k: k != "errored", self.simgr.stashes.keys())
            ])
            stash_state += f' errored ({len(self.simgr.errored)})'
            return stash_state

    def get_cfg_data(self):
        # Update cfg data
        active_addresses = []
        for s in self.simgr.active:
            # Register all first instruction addresses in the active stash with hit cfg addresses.
            active_addresses.append(s.block().addr)
        return active_addresses

    def get_active_traces(self):
        s = []
        if self.simgr:
            for state in self.simgr.active:
                s.append(get_state_backtrace_compact(state))
        return s

class BasicBlockExplorer(AbstractExplorer):

    def _init_simgr(self):
        if not self.simgr:
            ui.log_format.dump_regs(self.initial_state, logger, logging.INFO, header_msg='Initial register state')

            # Create the simulation manager on first step
            logger.info('Starting stepping. Creating simulation manager.')

            # Enable Pandora options on the init state
            pandora_options = po.PandoraOptions().get_options_dict()
            for k,v in pandora_options.items():
                self.initial_state.options[k] = v
                logger.debug(f'Set Pandora option {k} to {v}')

            # Now create the manager with the init state
            self.simgr = self.proj.factory.simgr(self.initial_state)  # , save_unsat=True)`


            """
            Set up the exploration techniques we want to use.
            """
            # This would allow to spill states to disk. Current issues are:
            # - Annotations seem to get lost
            # - Breakpoints for plugins have to be reapplied after loading states again (inspect.b are lost)
            # self.simgr.use_technique(Spiller(min=1, max=1, staging_max=1, vault=VaultDirShelf(d='./tmp')))
            if pandora_options[po.PANDORA_EXPLORE_DEPTH_FIRST]:
                self.simgr.use_technique(PandoraDFS())

            if pandora_options[po.PANDORA_EXPLORE_USE_LOOP_SEER]:
                self.simgr.use_technique(PandoraLoopSeer(bound=pandora_options[po.PANDORA_EXPLORE_LOOP_SEER_BOUND]))

            # To log basic blocks when logging is set to TRACE, we use the TraceLogger
            self.simgr.use_technique(TraceLogger())

            # We keep runtime statistics in a dict that logs each symbol to a count. This is reported in system events on end.
            self.statistics_technique = ExplorationStatistics(self.initial_state)
            self.simgr.use_technique(self.statistics_technique)

            # Enable the execution tracking to not jump to code pages that are not marked as executable
            self.simgr.use_technique(ControlFlowTracker(self.initial_state))

            # Enclave reentry has to be the last one to add
            self.simgr.use_technique(EnclaveReentry(
                    pandora_options[po.PANDORA_EXPLORE_REENTRY_COUNT], # Take reentry count from options
                    self.initial_state,
                    {self.initial_state}, # Prime the unique set with the init state
                    user_action=ActionManager().actions['reentry'])
            )

    def make_step(self):
        if not self.simgr:
            self._init_simgr()

        # Perform the step action if requested by the user
        self.action(state=self.simgr.active, info='[simgr.step]')

        # Move eexited states to the eexited stash (do this before stepping to enable the enclave reentry technique)
        self.simgr.move(from_stash='active', to_stash='eexited', filter_func=lambda s: s.globals['eexit'] is True)

        # Move states that would result in runtime exceptions generated by the hardware to errored list
        self.simgr.move(from_stash='active', to_stash='incorrect', filter_func=lambda s: s.globals['enclave_fault'] is True)

        # Move states where the enclave has disabled protections (sancus_disable / 0x1380)
        self.simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: s.globals['protections_disabled'] is True)

        # Do the step
        self.simgr.step()

        # Return whether we have exhausted all states and the errored list
        states_exhausted = len(self.simgr.active) == 0
        return states_exhausted, self.simgr.errored

    def wrap_up(self):
        """
        BasicBlockExplorer needs to perform a final reporting at the end of stepping to allow the statistics to
        report accurately.
        """
        self.statistics_technique.report_stats()
