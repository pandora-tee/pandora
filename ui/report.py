import datetime
import enum
import json
import logging
import timeit
from collections import defaultdict
from pathlib import Path

import pandora_options
import ui
from explorer.enclave import get_enclave_range
from sdks.SymbolManager import SymbolManager
from ui import log_setup, pandora_root_dir
from ui.log_format import format_log_level, format_header, log_always, format_table, format_link, format_asm, \
    format_regs, format_attacker_constraints, get_state_backtrace_formatted, format_inline_header
from ui.log_setup import LogLevel
from utilities.Singleton import Singleton

logger = logging.getLogger(__name__)


class JsonEntryId(enum.IntEnum):
    ENTRY_ID_METADATA = 1
    ENTRY_ID_PLUGIN = 2
    ENTRY_ID_DATA = 3

SYSTEM_EVENTS_REPORT_NAME = 'system-events'

def replace_string_path_arguments(str_path, binpath, logfile_timestamp=None, force_use_logfile_timestamp=False):
    # PANDORA_DIR is the base dir of pandora
    str_path = str_path.replace('$PANDORA_DIR$', pandora_root_dir)

    # TIMESTAMP is current timestamp
    # In some cases, like when only reporting on an old json file, we want to always use the logfile timestamp instead
    if force_use_logfile_timestamp and logfile_timestamp is not None:
        str_path = str_path.replace('$TIMESTAMP$', logfile_timestamp)
    else:
        str_path = str_path.replace('$TIMESTAMP$', ui.start_timestamp)

    # BINNAME is the name of the binary
    str_path = str_path.replace('$BINNAME$', binpath.stem)

    # Special folder $BINPATH$ is resolved to the folder of the binary.
    str_path = str_path.replace('$BINPATH$', str(binpath.parents[0]))

    # $TIMESTAMP_LOG$ should be replaced by the timestamp stored in the log file
    if logfile_timestamp is not None:
        str_path = str_path.replace('$LOG_TIMESTAMP$', logfile_timestamp)

    return str_path


def generate_basedir(config_name, binpath):
    """
    Generates a basedir Path object by reading config_name from the config file and
    parsing the given config. Creates the directory if it does not exist.
    """
    dir = ''
    if 'Logging' in log_setup.config:
        dir = log_setup.config['Logging'].get(config_name, dir)

    dir = replace_string_path_arguments(dir, binpath)

    basedir = Path(dir)
    basedir.mkdir(parents=True, exist_ok=True)

    return basedir


def generate_filename(config_name, binpath, logfile_timestamp=None, force_use_logfile_timestamp=False):
    """
    Generates a filename based on the given config_name in the config file and the parsed replaced string.
    """
    filename = '$TIMESTAMP$_$BINNAME$'
    if 'Logging' in log_setup.config:
        filename = log_setup.config['Logging'].get(config_name, filename)

    filename = replace_string_path_arguments(filename, binpath, logfile_timestamp, force_use_logfile_timestamp=force_use_logfile_timestamp)

    return filename


class Reporter(metaclass=Singleton):
    def __init__(self, binary='', sdk_name='auto', reporter_level=LogLevel.INFO):

        if binary == '':
            raise RuntimeError('binary to report is empty')

        self.reporter_level = logging.getLevelName(reporter_level.upper())

        # Open the initial file
        path = generate_basedir('log_folder', Path(binary))
        self.filepath = path / f'{generate_filename("log_filename", Path(binary))}.json'
        self.filename = self.filepath.resolve()
        self.file = open(self.filepath, 'w')

        self.start = timeit.default_timer()

        # Keep a list of plugins that we manage. Only used for statistics printing at the end.
        self.plugins = {}

        # Keep a set of unique issues that we do not want to duplicate. Dict keeps one set per plugin
        self.unique_issues = {}

        # Get enclave addresses to print as metadata
        enclave_min, enclave_max = get_enclave_range()

        # The first object in each json contains metadata
        metadata = {
            "type": JsonEntryId.ENTRY_ID_METADATA,
            "binary": Path(binary).name,
            "time": datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
            "start_timestamp": datetime.datetime.now().timestamp(),
            "sdk": sdk_name,
            "enclave_range" : f'[{enclave_min:#x}, {enclave_max:#x}]'
        }

        self.file.write('[\n')
        self.file.write(json.dumps(metadata))
        self.file.write(',\n')

        # Start the reporter by registering the system events plugin for relevant system events
        self.register_plugin('SystemEvents', 'Relevant events during Pandora execution.', SYSTEM_EVENTS_REPORT_NAME)


    def get_filepath(self):
        return self.filepath

    def register_plugin(self, name, desc, shortname):
        """
        Registers a plugin by appending a plugin entry to the log.
        """
        self.plugins[shortname] = {'name': name, 'rip': defaultdict(set)}

        plugin_data = {
            'type': JsonEntryId.ENTRY_ID_PLUGIN,
            'name': name,
            'desc': desc,
            'shortname': shortname
        }
        self.file.write(json.dumps(plugin_data))
        self.file.write(',\n')

        # also register this plugin with the unique issues
        self.unique_issues[shortname] = set()

    def close_reports(self, logger):
        """
        Write a summary of reported issues during runtime.
        Then write the final timestamp + closing bracket and close the file
        """
        for shortname, plug in self.plugins.items():
            lvl_summaries = []
            pretty_rips = {}
            rip = plug['rip']
            name = plug['name']
            for sev, rips in rip.items():
                num = len(rips)
                lvl = f'{format_log_level(num, sev)} unique {format_log_level(sev, sev)} issue{"s" if num > 1 else ""}'
                lvl_summaries.append(lvl)
                pretty_rips[sev] = '; '.join([f"'{info}' at {rip:#x}" for (rip, info) in rips])

            issues = f'{"; ".join(lvl_summaries)}.' if lvl_summaries else 'no issues.'

            log_always(logger, format_header(f'\n{name} summary:') + f' {name} reported {issues}')

            if lvl_summaries:
                log_always(logger, format_table(pretty_rips, key_hdr='Severity', val_hdr=f'Reports by {name}'))

        self.file.write(json.dumps({"type": JsonEntryId.ENTRY_ID_METADATA,
                                    "stop_timestamp": datetime.datetime.now().timestamp()}))
        self.file.write('\n]')
        self.file.close()
        log_always(logger, f'\n\nPandora log data stored at {format_link(self.filename, self.filename)}')

    def report_severity_stats(self, logger):
        """
        Reports the summary per severity level for all plugins that this reporter manages.
        Output is directly to console in rich format
        """
        severity_dict = {}

        for shortname, plug in self.plugins.items():
            # Map the dict as a length of each value
            lvl_summaries = defaultdict(int, dict(map(lambda x: (x[0], len(x[1])), plug['rip'].items())))

            # And get a tuple from that in the order (critical, warning, debug)
            lvl_tuple = (lvl_summaries[logging.getLevelName(logging.CRITICAL)],
                         lvl_summaries[logging.getLevelName(logging.WARNING)],
                         lvl_summaries[logging.getLevelName(logging.DEBUG)]
                         )

            if lvl_tuple == (0, 0, 0):
                return 'No issues reported.'

            s = f'{lvl_tuple[0]} CRITICAL issues' + ', '
            s += f'{lvl_tuple[1]} WARNING  issues' + ', and '
            s += f'{lvl_tuple[2]} DEBUG issues'

            severity_dict[plug['name']] = s

        log_always(logger, format_table(severity_dict, key_hdr='Plugin', val_hdr='Statistics'))


    def report(self, info, state, callee_logger, plugin_shortname, severity=logging.INFO, extra_info=None, only_once = False,
               extra_sections=None):
        """
        Reports an incident for the given state and the given plugin/severity.
        Only_once can be used for low-severity reports that should only be noted once to not bloat up the reports.

        :param info: A short description of the issue.
        :param state: The state to print.
        :param callee_logger: The logger to send some report info to
        :param plugin_shortname: The plugin to report this with
        :param severity: The report severity (one of logging severity levels)
        :param extra_info: A dict with extra info to be displayed as table on top
        :param only_once: Set to false to not repeat issues.
        :param extra_sections: A dict to print extra info in segments. Should have the format
        {groupname (string) : list(tuple(3, string)). Example: [(segment name, object to be placed in the section, environment type (verbatim|trace|table)]
        }.
        """
        if extra_info is None:
            extra_info = {}

        if extra_sections is None:
            extra_sections = {}

        # NOTE: Be careful to use get_reg here and disable actions and inspect!
        # Otherwise, the breakpoint will fire again and we get very weird results!
        # rip = get_reg_value(state, 'rip', disable_actions=True, inspect=False)
        # The above does not work for calls because rip is already set to call target!
        # Below seems more robust?
        rip = state.scratch.ins_addr if state.scratch.ins_addr is not None else state.solver.eval_one(state.regs.ip)

        # print short info on terminal
        rip_info = f'@{rip:#x}: ' + info

        if only_once or pandora_options.PandoraOptions().get_option(pandora_options.PANDORA_REPORT_ONLY_UNIQUE):
            # Abort early if we are in only once mode and already know this info at that rip
            if rip_info in self.unique_issues[plugin_shortname]:
                callee_logger.log(severity, f"Ignoring issue because it is already logged: {format_inline_header(rip_info)}")
                return
            else:
                self.unique_issues[plugin_shortname].add(rip_info)

        if severity > logging.INFO:
            callee_logger.log(severity, '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
            callee_logger.log(severity, f'!!!! {rip_info:^72} !!!!')
            callee_logger.log(severity, '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
        else:
            callee_logger.log(severity, rip_info)

        if severity < self.reporter_level:
            # Early out if the reported severity is to be ignored by the reporter.
            callee_logger.log(severity, 'Not writing this issue to report since it is below the report-level.')
        else:
            # We seem to be ready for report writing. Prepare the item and write it to file.
            sym = SymbolManager().get_symbol(rip)
            self.plugins[plugin_shortname]['rip'][logging.getLevelName(severity)].add((rip, info))

            if pandora_options.PandoraOptions().get_option(pandora_options.PANDORA_REPORT_OMIT_ATTACKER_CONSTRAINTS):
                attacker_constraints = ''
            else:
                attacker_constraints = format_attacker_constraints(state).split('\n')

            report_element = {
                "type": JsonEntryId.ENTRY_ID_DATA,
                "plugin": plugin_shortname,
                "rip": rip,
                "symbol": sym,
                "info": info,
                "severity": severity,
                "backtrace": get_state_backtrace_formatted(state),
                "asm": format_asm(state, highlight_rip=rip),
                "registers": format_regs(state),
                "constraints": attacker_constraints,
                "extra": {str(k): str(v) for k, v in extra_info.items()},
                "extra-sections": extra_sections,
            }

            self.file.write(json.dumps(report_element))
            self.file.write(',\n')
            self.file.flush()
