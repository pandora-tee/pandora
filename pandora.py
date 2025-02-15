#!/usr/bin/env python3

import atexit
import logging
import sys
from dataclasses import dataclass
from itertools import count
# import shellingham # for auto completion of typer, usable with typer-cli
from pathlib import Path
from typing import List, Optional

import typer
import json

from rich.text import Text

import explorer.cfg as cfg
import ui.report
from explorer.explorer import BasicBlockExplorer
from sdks.SDKManager import SDKManager
from explorer import explorer, hooker
from explorer.enclave import eenter
from pithos.PluginManager import PluginManager
from tests.enclave import test_buffer_entirely_inside_enclave, test_buffer_touches_enclave
from tests.memory import test_default_memory
from ui import log_setup, log_format
from ui.action import UserAction
from ui.action_manager import ActionManager
from ui.log_format import log_always, format_rich, format_fields, get_state_backtrace_compact, format_header, format_bad, \
    format_good, format_table
from ui.log_setup import LogLevel
from ui.report_format import report_formats, ReportFormatter

from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, BarColumn, TaskProgressColumn, \
    TimeRemainingColumn, MofNCompleteColumn, ProgressColumn
from rich.live import Live

from ui import console

import pandora_options as po

logger = logging.getLogger(__file__)

pandora_state = {
    "only_reporting": False,
    "in_execution": False
}


@dataclass
class PandoraContext:
    ctx: typer.Context
    file_path: Path
    config_file: Path
    log_level: LogLevel
    report_level: LogLevel
    angr_log_level: LogLevel
    num_steps: int
    plugins: list
    pandora_options: list
    sdk_detection_type: str
    actions: List[str]
    report_fmt: str
    report_max_ips: int
    with_cfg: bool
    # Options for enclave memory dumps
    sdk_elf_file: Path
    sdk_json_file: Path


def pandora_setup(pandora_ctx: PandoraContext, binary_path: Path):
    """
    Setup for Pandora that loads the binary and registers all requested plugins and hooks.
    """
    console.print(f'{log_format.format_header("Pandora Setup.")}')
    console.print(f'{log_format.format_header("Pandora")}: Working on binary {log_format.format_warning(binary_path)}.')

    # Start a series of spinners
    console_progress = Progress(
        SpinnerColumn(finished_text=':white_check_mark:'),
        MofNCompleteColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
    )
    with Live(console_progress, console=console):
        task_pandora = console_progress.add_task(description=f'Setting up Pandora engine', total=None)
        task_sdks = console_progress.add_task(description=f'Parsing SDK from binary', total=None)
        task_hooker = console_progress.add_task(description=f'Hooking enclave-specific instructions', total=None)
        task_plugins = console_progress.add_task(description=f'Preparing symbolic execution and plugins', total=None)

        if pandora_state['ctx'].with_cfg:
            task_cfg = console_progress.add_task(description=f'Generating CFG', total=None)
            task_simplify = console_progress.add_task(description=f'Simplifying CFG to dag of enclave entry tree',
                                                      total=None)


        """
        Pandora setup
        """
        # init requested action choices
        action_mgr = ActionManager(pandora_ctx.actions)
        # This concludes the Pandora setup task.
        console_progress.update(task_pandora, total=1.0, completed=1.0)

        # Set the plugin relevant options in the PandoraOptions Singleton
        for (k,v) in pandora_ctx.pandora_options:
            po.PandoraOptions().set_option(k, v)

        """
        SDK Setup
        """
        # Init binary manager to detect sdk
        sdk_mgr = SDKManager(binary_path, pandora_ctx.sdk_detection_type, elf_file=pandora_ctx.sdk_elf_file, json_file=pandora_ctx.sdk_json_file)

        # Load binary in angr and initialize the state. Load binary with offset defined by detected SDK
        my_explorer = BasicBlockExplorer(binary_path, action_mgr.actions['explorer'],
                                                  sdk_mgr.get_load_addr(), angr_backend=sdk_mgr.get_angr_backend(), angr_arch=sdk_mgr.get_angr_arch())
        init_state = my_explorer.get_init_state()

        # Initialize sdk with specific initial state
        sdk_mgr.initialize_sdk(init_state)

        console_progress.update(task_sdks, total=1.0, completed=1.0)

        """
        Angr setup
        """
        # Run the hooker for SGX specific instructions and settings
        hooker.HookerManager(init_state, sdk_mgr.get_exec_ranges(), live_console=console_progress, task=task_hooker, angr_arch=sdk_mgr.get_angr_arch())

        # Simulate eenter on the init_state
        eenter(init_state)

        # Initialize the reporter that logs all issues
        reporter = ui.report.Reporter(binary_path, sdk_mgr.get_sdk_name(), pandora_ctx.report_level)

        # Init requested plugins
        plugin_mgr = PluginManager(init_state, pandora_ctx.plugins, action_mgr.actions, reporter)

        # Give SDKs one last chance to modify the init state
        sdk_mgr.prepare_init_state(init_state)

        console_progress.update(task_plugins, total=1.0, completed=1.0)

        if pandora_state['ctx'].with_cfg:
            # Generate CFGFast with the project of the init state
            my_cfg = cfg.prepare_cfg()
            console_progress.update(task_cfg, total=1.0, completed=1.0)

            # Based on initial basic block, get the call graph following this node
            pandora_state['cfg_nodes'] = cfg.simplify_cfg_to_tree(
                my_cfg.get_any_node(explorer.BasicBlockExplorer().get_init_state().addr)
            )

            # prepare a addr to node mapping for quick lookup of node addresses
            pandora_state['node_addr_dict'] = {n.addr: n for n in pandora_state['cfg_nodes'].keys()}

            console_progress.update(task_simplify, total=1.0, completed=1.0)

        log_format.log_always(logger, f'{log_format.format_header("Pandora")}: Working on log file {log_format.format_link(reporter.filepath, reporter.filepath)}')

        # This concludes the setup. Close live display and trigger start action
        logger.info('Angr setup complete.')

class StateProgressColumn(ProgressColumn):
    """
    Renders a human-readable statistics of the current state numbers.
    Based on https://github.com/Textualize/rich/blob/cba485f6c4bd181756ae944f032e942902d698ee/rich/progress.py#L903
    """

    def render(self, task: "Task") -> Text:
        """Show statistics."""
        fields = task.fields['fields'] # Weirdly double packed here
        if not 'active' in fields:
            raise RuntimeError()

        stats = f"Statistics: [{fields['active']:4d} active] "

        if po.PandoraOptions().get_option(po.PANDORA_EXPLORE_DEPTH_FIRST) and 'deferred' in fields:
            stats += f'[{fields["deferred"]: 4d} deferred] '

        if po.PandoraOptions().get_option(po.PANDORA_EXPLORE_REENTRY_COUNT) > 0 and 'uniques' in fields and 'new_uniques' in fields:
            stats += f'[{fields["new_uniques"]: 4d} new uniques] [{fields["uniques"]: 4d} old uniques]'
        else:
            stats += f"[{fields['eexited']: 4d} eexited]"

        return Text(stats)

def pandora_explore(pandora_ctx: PandoraContext):
    """
    Symbolic execution phase. Post setup.
    """
    console.print(f'{log_format.format_header("Pandora Symbolic Exploration.")}')

    # Get all Singleton manager objects for the local context:
    action_mgr = ActionManager()
    my_explorer = explorer.BasicBlockExplorer()
    sdk_mgr = SDKManager()

    action_mgr.actions['start'](info='System loaded. Start hook before symbolic execution starts.',
                                state={"init_state": my_explorer.get_init_state(),
                                       "sdk": sdk_mgr,
                                       "explorer": my_explorer,
                                       "hooker": hooker}
                                )

    logger.info("Starting symbolic execution..'")
    # Prepare an iterator that either counts upward for an unknown step count or that goes over the number of steps.
    if pandora_ctx.num_steps <= 0:
        it = count()
        console_progress = Progress(
            SpinnerColumn(finished_text=':white_check_mark:'),
            TextColumn("[progress.description]{task.description} {task.completed}"),
            TimeElapsedColumn(),
            StateProgressColumn()
        )
    else:
        it = iter(range(1, pandora_ctx.num_steps + 1))
        console_progress = Progress(
            TextColumn("[progress.description]{task.description} {task.completed}"),
            BarColumn(),
            TimeElapsedColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            StateProgressColumn()
        )

    current_step = next(it, None)
    is_done = False
    executed_num_steps = 0
    handled_error_states = 0
    pandora_state['in_execution'] = True
    with Live(console_progress, console=console) as progress:
        # Only spawn a progress or spinner if we do not have any user action.
        # This would be annoying to have the spinner there for user actions.
        using_task = False
        if all(ua == UserAction.NONE for ua in action_mgr.actions.values()):
            task = console_progress.add_task(description=f'Running symbolic execution at step ',
                                             total=None if pandora_ctx.num_steps == 0 else pandora_ctx.num_steps,
                                             fields={'active': 1, 'eexited':0})
            using_task = True
        else:
            progress.stop()

        # For 'with_cfg' option only: Keep track of unmapped addresses.
        unmapped_dict = {}

        # Then start a loop that keeps updating the iterator and performs an exploration step
        while not is_done and current_step is not None and not po.PANDORA_USER_REQUESTED_EXIT:
            # Remember the total number of steps made so far (We lose that if the iterator runs out)
            executed_num_steps = current_step

            # Print the stash sizes and active backtraces every 1000 steps
            log_level_active_backtraces = logging.INFO
            if executed_num_steps > 0 and executed_num_steps % 1000 == 0 and logger.getEffectiveLevel() > log_level_active_backtraces:
                log_always(logger, f'At step {executed_num_steps}. {my_explorer.print_stash_sizes()}')
                logger.log(log_level_active_backtraces, f'{format_header("=== BEGIN DUMP ACTIVE BACKTRACES ====")}')
                for t in my_explorer.get_active_traces():
                    logger.log(log_level_active_backtraces, 'Compact symbol call trace (most recent last):')
                    logger.log(log_level_active_backtraces, f'{format_fields(t)}')
                logger.log(log_level_active_backtraces, f'{format_header("=== END DUMP ACTIVE BACKTRACES ====")}')

            # Run a step
            is_done, errored_states = my_explorer.make_step()

            # If we are keeping track of the CFG, update the cfg addr dict
            if pandora_ctx.with_cfg:
                executed_addrs = my_explorer.get_cfg_data()
                for addr in executed_addrs:
                    if addr in pandora_state['node_addr_dict']:
                        node = pandora_state['node_addr_dict'][addr]
                        pandora_state['cfg_nodes'][node] = 1 + pandora_state['cfg_nodes'][node]
                    else:
                        if addr in unmapped_dict:
                            unmapped_dict[addr] = unmapped_dict[addr] + 1
                        else:
                            unmapped_dict[addr] = 1

            # Check for unhandled errors and pass them to the action manager
            unhandled_errors = errored_states[handled_error_states:]
            if unhandled_errors:
                logger.critical(f'Some states errored! Errored states: {unhandled_errors}')
                action_mgr.actions['error'](info='[errored states]', state=unhandled_errors)
                # Append the unhandled errors to the set of handled errors to ignore them in the next iteration.
                handled_error_states = len(errored_states)

            # Advance the progress bar / spinner
            if using_task:
                console_progress.update(task, fields=my_explorer.get_running_statistics())
                console_progress.advance(task)

            # Advance to the next step
            current_step = next(it, None)

            # If we terminate without having a num steps limit, update the spinner to be completed.
            if using_task and is_done and pandora_ctx.num_steps == 0:
                console_progress.update(task, completed=executed_num_steps, total=executed_num_steps, fields=my_explorer.get_running_statistics())

    """
    Wrap up.
    """
    my_explorer.wrap_up() # Run statistics

    if errored_states:
        log_always(logger, log_format.format_warning(
            f'\n\nPandora completed after taking {executed_num_steps} steps but had some errored states.'))
        log_always(logger, f'All errored states throughout the run: {log_format.format_fields(errored_states)}')
        for e in errored_states:
            bbt = get_state_backtrace_compact(e.state)
            logger.info(f'Errored states callbacks:\nTrace length: {len(bbt)}\n' + log_format.format_fields(bbt))
    else:
        log_always(logger, log_format.format_good(f'\n\nPandora completed after taking {executed_num_steps} steps.'))
        log_always(logger, log_format.format_good(f'Pandora completed gracefully, no errored states created.'))

    if not is_done:
        log_always(logger, log_format.format_warning(f'Discontinued execution as requested but still had states to explore.'))

    log_always(logger, f'Final stash sizes after step {executed_num_steps}: {my_explorer.print_stash_sizes()}')

    if pandora_ctx.with_cfg:
        # Generate filename
        path = ui.report.generate_basedir('log_folder', pandora_ctx.file_path)
        filepath = path / f'{ui.report.generate_filename("log_filename", pandora_ctx.file_path)}_cfg.dot'

        # export to dot file
        cfg.export_to_dot(pandora_state['cfg_nodes'], filepath)

        log_always(logger, f'Pandora CFG with annotations stored at {filepath}')

        if len(unmapped_dict) > 0:
            logger.warning(f'Could not map these addresses to their respective CFG nodes:{log_format.format_fields(unmapped_dict)}')

    # logger.debug('First 10 EEXITED states:\n' + log_format.format_fields(my_explorer.get_all_traces()[0:10]))

    exit_execution()

    if po.PANDORA_USER_REQUESTED_EXIT:
        log_always(logger, 'User requested exit. Exiting now..')
    else:
        # Only do exit action if user did not already request the exit themselves
        action_mgr.actions['exit'](info='Symbolic execution finished. Exit hook before shutting down.',
                                   state={
                                          "init_state": my_explorer.get_init_state(),
                                          "sdk": sdk_mgr,
                                          "explorer": my_explorer,
                                          'errored_states': errored_states
                                          }
                                   )

def pandora_report(pandora_ctx: PandoraContext, log_path: Path):
    """
    To be called after pandora_ctx is set up.
    Takes a path as a log file and creates a report from it based on requested format in report_fmt.
    """
    console.print(f'{log_format.format_header("Pandora Report Generator.")}')
    console.print(f'{log_format.format_header("Pandora")}: Working on log file {log_format.format_warning(log_path)}.')
    with open(log_path, 'r') as f:
        data = json.load(f)
    report_formatter = ReportFormatter(data, pandora_ctx.report_fmt, pandora_ctx.report_level, pandora_ctx.report_max_ips)
    report_formatter.write_reports()


def pandora_cfg(pandora_ctx: PandoraContext, binary_path: Path):
    """
    Can be used to create a cfg dotfile of the binary (DAG of entry function).
    """
    console.print(log_format.format_header(
        "Pandora CFG Generator. CAREFUL: This may take a VERY long time and may not even work depending on the binary. "
        "Only use it for troubleshooting Pandora on very small executables."))

    # Start a series of spinners
    console_progress = Progress(
        SpinnerColumn(finished_text=':white_check_mark:'),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
    )
    with Live(console_progress, console=console):
        task_export = console_progress.add_task(description=f'Exporting CFG to dotfile', total=None)

        # Generate filename
        path = ui.report.generate_basedir('log_folder', binary_path)
        filepath = path / f'{ui.report.generate_filename("log_filename", binary_path)}_cfg.dot'

        # Export to a dot graph based on the given nodes
        if 'cfg_nodes' in pandora_state:
            cfg.export_to_dot(pandora_state['cfg_nodes'], filepath)
            console.print(f'Wrote dot graph to {filepath}')
        else:
            console.print(format_bad('Error accessing CFG, aborted.'))

        console_progress.update(task_export, total=1.0, completed=1.0)

def pandora_selftest(pandora_ctx: PandoraContext):
    """
    Performs a series of selftests to verify certain assumptions of Pandora.
    """
    # get the init state
    init_state = BasicBlockExplorer().get_init_state()

    total_issues = 0
    num_tests = 0
    issue_list = {}

    def _run_test(name, issue_count):
        nonlocal num_tests,total_issues,issue_list
        num_tests += 1
        if issue_count > 0:
            issue_list[name] = issue_count
            total_issues += issue_count

    log_always(logger, format_header('Starting Pandora selftests...'))

    # as of now, only check the pointer range checks in enclave.py
    _run_test('buffer_touches_enclave', test_buffer_touches_enclave(init_state))
    _run_test('buffer_entirely_inside_enclave', test_buffer_entirely_inside_enclave(init_state))
    _run_test('default_memory', test_default_memory(init_state))

    if total_issues > 0:
        logger.info("Issue overview:\n" + format_table(issue_list, 'Test', 'Number of issues'))
        log_always(logger, format_bad(f'Warning: Had {total_issues} issues in total across {num_tests} tests.'))
    else:
        log_always(logger, format_good(f'Success! Had {total_issues} issues in total across {num_tests} tests.'))


    # Underline the test failure by exiting with the relevant status code
    sys.exit(0 if not total_issues else 1)



def exit_execution():
    if pandora_state['in_execution']:
        # Get reporter Singleton
        reporter = ui.report.Reporter()
        # First print a statistics table for all plugins
        reporter.report_severity_stats(logger)

        # Then write the individual plugin reports
        reporter.close_reports(logger)

        pandora_state['in_execution'] = False


def exit_proc():
    log_always(logger, log_format.format_header("\nExiting. Final stats:"))
    exit_execution()
    log_always(logger, log_format.format_header('Terminating program.'))


def validate_opt(opt, options, context=''):
    if opt not in options:
        raise typer.BadParameter(f"{context}'{opt}' not recognized; valid options are:\n{ui.log_format.format_fields(options)}")

def report_callback(ctx: typer.Context, value: str):
    if ctx.resilient_parsing:
        return

    validate_opt(value, list(report_formats.keys()))
    return value


def plugin_callback(ctx: typer.Context, value: str):
    if ctx.resilient_parsing:
        return

    plugins = value.split(',')
    for p in plugins:
        validate_opt(p, PluginManager.get_plugin_names() + ['all', 'default'])
    return plugins


def sdk_callback(ctx: typer.Context, value: str):
    if ctx.resilient_parsing:
        return

    validate_opt(value, SDKManager.get_sdk_names() + ['auto'])
    return value


def action_callback(ctx: typer.Context, value: List):
    if ctx.resilient_parsing:
        return

    action_list = []
    for i in value:
        split_val = i.split('=')
        if len(split_val) != 2:
            raise typer.BadParameter('Give --action only as a string of "<event>=<action>"')

        validate_opt(split_val[0], ActionManager.get_event_names())
        validate_opt(split_val[1], ActionManager.get_action_names(), context=f"'{split_val[0]}' action: ")

        action_list.append(split_val)
    return action_list

def plugin_options_callback(ctx: typer.Context, value: List):
    if ctx.resilient_parsing:
        return

    options_list = []
    for i in value:
        split_val = i.split('=')
        if len(split_val) != 2:
            raise typer.BadParameter('Give --plugin-options only as a string of "<option>=<value>"')

        validate_opt(split_val[0], list(po.PandoraOptions().get_options_dict().keys()))

        # Next, validate the value by first checking it and then typing it immediately
        option_type = type(po.PandoraOptions().get_option(split_val[0]))

        option_val = split_val[1]
        if option_type is bool:
            validate_opt(split_val[1].lower(), ['false', 'true'], context=f"'{split_val[0]}' option: ")
            option_val = True if split_val[1] == 'true' else False
        elif option_type is int:
            # Do manual opt checking in this case
            if not split_val[1].isdigit():
                raise typer.BadParameter(f"{split_val[0]}: '{split_val[1]}' is not a valid integer")
            option_val = int(split_val[1])
        else:
            raise typer.BadParameter("Can only support bool and integer plugin options thus far. Maybe expand the plugin_options_callback?")

        options_list.append((split_val[0], option_val))

    return options_list



def format_help_options(info, opts):
    """
    NOTE: do not use log_format.format*() here as this messes up the
    spacing and | delimitators in the help text..
    """
    s = f'Possible values for the [underline]{info} key[/] are:'
    maxname = len(max(opts.keys(), key=len))
    newline = '\n\n'
    s += newline
    for name, desc in opts.items():
        s += f':left_arrow_curving_right:  [bold]{name.ljust(maxname)}[/] -- {desc}' + newline
    return s


def main_callback(
        ctx: typer.Context,
        file_path: Path = typer.Argument(
            ..., help="Path to the binary or log file to open",
            exists=True, dir_okay=False, readable=True, resolve_path=True,
        ),
        config_file: Path = typer.Option(
            None, "-c", "--config-file",
            help="Path to optional config file",
            exists=True, dir_okay=False, readable=True, resolve_path=True,
        ),
        log_level: LogLevel = typer.Option(
            "warning", "-l", "--log-level",
            help="The log level for pandora",
        ),
        report_level: LogLevel = typer.Option(
            "info", "-L", "--report-level",
            help="The level for pandora reports. Set to debug to get all information.",
            rich_help_panel="Report generation"
        ),
        angr_log_level: LogLevel = typer.Option(
            "critical", "--angr-log-level",
            help="The log level for angr",
        ),
        num_steps: int = typer.Option(
            100, "-n", "--num-steps",
            help="Number of steps to execute in symbolic execution. 0 or negative allows to run to completion.",
            rich_help_panel="Exploration options"
        ),
        plugins: str = typer.Option(
            "default", "-p", "--plugins", callback=plugin_callback,
            metavar='[' + '|'.join(PluginManager.get_special_plugins().keys()) + '|' + '|'.join(
                PluginManager.get_plugin_names()) + ']',
            help="Define the plugins to activate, separated by a comma. "
                 + format_help_options('plugin', PluginManager.get_plugin_help()),
            rich_help_panel="Exploration options"
        ),
        pandora_options: Optional[List[str]] = typer.Option(
            None, "--pandora-option", callback=plugin_options_callback,
            help="Sets a specific advanced option via the format [bold]option=value[/]. Default values shown below. "
                 + format_help_options('option', po.PandoraOptions().get_options_dict() ),
            rich_help_panel="Exploration options"
        ),
        sdk_detection_type: str = typer.Option(
            "auto", "-s", "--force-sdk", callback=sdk_callback,
            metavar='[' + '|'.join(SDKManager.get_sdk_names()) + '|' + 'auto' + ']',
            help="Define the sdk to use. Overrides auto detection if set to a specific SDK.",
            rich_help_panel="Exploration options",
        ),
        sdk_json_file: Path = typer.Option(
            None, "--sdk-json-file",
            help="If using the 'dump' sdk, the layout json file must be included to understand enclave layout.",
            rich_help_panel="Options for enclave dumps",
            exists=True, dir_okay=False, readable=True, resolve_path=True,
        ),
        sdk_elf_file: Path = typer.Option(
            None, "--sdk-elf-file",
            help="If using the 'dump' sdk, an optional elf file may be passed to utilize its symbols. "
                 "This does not matter for exploration but is useful for investigating found issues.",
            rich_help_panel="Options for enclave dumps",
            exists=True, dir_okay=False, readable=True, resolve_path=True,
        ),
        actions: Optional[List[str]] = typer.Option(
            None, "-a", "--action", callback=action_callback,
            help="Adds an action bound to a specific event via the format [bold]event=action[/]. "
                 + format_help_options('event',
                                       {**ActionManager.get_system_events(),
                                        **{p: f"For events reported by the '{p}' plugin (see below)." for p in
                                           PluginManager.get_plugin_names()}
                                        }
                                       )
                 + format_help_options('action', UserAction.get_action_help()),
            rich_help_panel="Exploration options"
        ),
        report_fmt: str = typer.Option(
            "html", "-r", "--report", callback=report_callback,
            metavar='[' + '|'.join(report_formats.keys()) + ']',
            help="Define the format for all plugin reports.",
            rich_help_panel="Report generation"
        ),
        report_max_ips: int = typer.Option(
            0, "--report-ips",
            help="Maximum number of duplicate reports per unique IP for all plugin HTML reports. 0 or negative to report all.",
            rich_help_panel="Report generation"
        ),
        with_cfg: bool = typer.Option(
            False, "--with-cfg",
            help="EXPERIMENTAL: Exports a CFG on exit after finishing exploration. CFG will contain information on reached basic blocks. Feature may break or stall exploration completely, depending on binary..",
            rich_help_panel="Exploration options"
        ),
):
    '''
    Pandora: Principled vulnerability detection for SGX binaries.
    '''
    global pandora_state
    # Store the state as a pandora context object
    pandora_state['ctx'] = PandoraContext(**locals())

    # Switch to reporting mode and set up file type name based on subcommand used
    if ctx.info_name == 'report':
        pandora_state['only_reporting'] = True

    # If CFG subcommand is used, switch on CFG generation on setup
    if ctx.info_name == 'cfg':
        pandora_state['ctx'].with_cfg = True

    # Print general information
    if config_file is not None:
        console.print(f'Using config file {log_format.format_warning(config_file)}.')

    # Init Logger
    log_setup.init_logger(config_file, log_level, angr_log_level)
    # Register atexit
    atexit.register(exit_proc)

    log_always(logger, f'{format_rich(":white_check_mark:")} Setting up Pandora core')

    if ctx.info_name == 'report':
        pandora_report(pandora_state['ctx'], file_path)
    else:
        # All the remaining sub commands require a full setup of Pandora (with loading the binary)
        pandora_setup(pandora_state['ctx'], file_path)

        if ctx.info_name == 'cfg':
            pandora_cfg(pandora_state['ctx'], file_path)
        elif ctx.info_name == 'explore':
            pandora_explore(pandora_state['ctx'])
        elif ctx.info_name == 'run':
            pandora_explore(pandora_state['ctx'])
            console.print('\n')
            pandora_report(pandora_state['ctx'], ui.report.Reporter().get_filepath())
        elif ctx.info_name == 'selftest':
            pandora_selftest(pandora_state['ctx'])


# Now we can define the main app as it uses the main_callback
# This is slightly ugly since we want to have the same callback set for all three commands
# The easiest way to do this with typer is to generate them as individual typer subapps that each have the same callback
# Since we invoke these callbacks even without a command, all the magic happens in the lines above this comment where
#  the commands are distinguished and the proper method is dispatched.
COMMAND_EXPLORE_HELP = 'Perform an exploration on the given binary.'
COMMAND_REPORT_HELP = 'Generate a report for a given exploration log file.'
COMMAND_RUN_HELP = f'Shorthand for {log_format.format_inline_header("explore")} ' \
                   f'+ {log_format.format_inline_header("report")}'
COMMAND_CFG_HELP = f'EXPERIMENTAL: Create a control flow graph of this binary into the default log folder.'
COMMAND_SELFTEST_HELP = 'Performs a normal binary load (as for explore/run) but then performs a series of selftests.'
app = typer.Typer(add_completion=False, rich_markup_mode="rich", no_args_is_help=True)
app.command(name='explore', help=COMMAND_EXPLORE_HELP)(main_callback)
app.command(name='report', help=COMMAND_REPORT_HELP)(main_callback)
app.command(name='run', help=COMMAND_RUN_HELP)(main_callback)
app.command(name='cfg', help=COMMAND_CFG_HELP)(main_callback)
app.command(name='selftest', help=COMMAND_SELFTEST_HELP)(main_callback)

if __name__ == "__main__":
    app()
