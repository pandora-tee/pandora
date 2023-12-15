#!/usr/bin/env python3

import asyncio
import configparser
import logging
import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import rich.pretty
import typer
import json
from rich.console import Console
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, BarColumn, TaskProgressColumn, \
    TimeRemainingColumn
from rich.style import Style
from rich.table import Table

console = Console(color_system=None, highlight=False, soft_wrap=True)
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s | %(message)s')
logger = logging.getLogger(__file__)

ci_state = {
}
ci_binaries = [
    'linux-sgx-selftest/linux_test_encl.elf',
    'pandora-sgx-selftest/pandora_selftest_enclave_sanitization0.elf',
    'pandora-sgx-selftest/pandora_selftest_enclave_sanitization1.elf',
    'pandora-sgx-selftest/pandora_selftest_enclave_sanitization2.elf',
    'pandora-sgx-selftest/pandora_selftest_enclave_sanitization3.elf',
    'pandora-sgx-selftest/pandora_selftest_enclave_sanitization4.elf',
    'pandora-sgx-selftest/pandora_selftest_enclave_eexit0.elf',
    'pandora-sgx-selftest/pandora_selftest_enclave_eexit1.elf',
    'pandora-sgx-selftest/pandora_selftest_enclave_eexit2.elf',
    'pandora-sgx-selftest/pandora_pointer-deref.elf',
    'pandora-sgx-selftest/pandora_indirect-jump.elf',
]


@dataclass
class CIContext:
    ctx: typer.Context
    filepath: Path
    no_rerun_ci: bool

def run_ci(ctx : CIContext, config):


    def shutdown():
        for task in asyncio.all_tasks():
            task.cancel()

    async def control_eventloop():
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGTERM, shutdown)
        loop.add_signal_handler(signal.SIGINT, shutdown)

        logger.info(f'Running Pandora {len(ci_binaries)} times.')

        base_path = Path(os.path.dirname(__file__)).resolve()
        examples_folder = (base_path.parent / 'runtime-dumps').resolve().as_posix()
        # Start creating tasks
        task_list = []
        task_counter = 0
        for binary_name in ci_binaries:
            command_name = f'{sys.executable} {base_path.resolve().as_posix()}/pandora.py explore ' \
                           f'-c {config} ' \
                           f'-n 0 ' \
                           f'{examples_folder}/{binary_name}'
            logger.info(f'Executing {command_name}')
            task_list.append(
                asyncio.create_subprocess_shell(
                    command_name,
                    stdout=subprocess.DEVNULL)
            )

        logger.info(f'Created {len(task_list)} tasks. Starting to run them...')

        process_list = []
        with Progress() as progress:
            progress_task = progress.add_task("[green]Starting tasks...", total=len(task_list))
            for f in asyncio.as_completed(task_list):
                process_list.append(await f)
                progress.update(progress_task, advance=1)

        with Progress() as progress:
            progress_task = progress.add_task("[green]Running tasks...", total=len(task_list))
            for pr in process_list:
                await pr.wait()
                progress.update(progress_task, advance=1)

    asyncio.run(control_eventloop())
    logger.info('Done with CI run.')


def check(ctx: CIContext, base_config_path='', ci_config_path=''):

    # Parse the two config files to get to the two folders that contain the json files
    # We disable interpolation to allow the format string.
    logger.info(f'Working with baseline config file {base_config_path} and CI config file {ci_config_path}')
    config_ci = configparser.ConfigParser(interpolation=None)
    config_ci.read(ci_config_path)
    config_base = configparser.ConfigParser(interpolation=None)
    config_base.read(base_config_path)

    # Sanity check that the files are correct
    if not 'Logging' in config_ci or not 'Logging' in config_base:
        raise RuntimeError('Config file error.')

    ci_folder = config_ci['Logging']['log_folder']
    base_folder = config_base['Logging']['log_folder']

    # Replace the PANDORA_DIR in the paths
    pandora_dir = Path(os.path.dirname(__file__)).resolve().as_posix()
    ci_folder = ci_folder.replace('$PANDORA_DIR$', pandora_dir)
    base_folder = base_folder.replace('$PANDORA_DIR$', pandora_dir)
    # For now only support the dir in the path, fail else
    if '$' in ci_folder or '$' in base_folder:
        raise RuntimeError(f'No support for other log dir configs than PANDORA_DIR right now. (No support for either {ci_folder} or {base_folder})')
    ci_folder = Path(ci_folder)
    base_folder = Path(base_folder)
    logger.info(f'Will compare ci directory {ci_folder} to baseline directory {base_folder}')

    # Check that both folders exist
    if not os.path.isdir(ci_folder):
        logger.error(f'{ci_folder} does not exist. Please run this with `check` but without the `--no-rerun` option on first start.')
        sys.exit(1)
    if not os.path.isdir(base_folder):
        logger.error(f'{base_folder} does not exist. On first run, please create a baseline with the `rebase` command.')
        sys.exit(1)

    ci_files = os.listdir(ci_folder)
    base_files = os.listdir(base_folder)
    num_issues = {
        logging.DEBUG : 0,
        logging.INFO : 0,
        logging.WARNING : 0,
        logging. CRITICAL: 0
    }

    def get_diff_prefix(a,b):
        prefix = '  '
        if a != b:
            prefix = ':heavy_multiplication_x: '

        return prefix

    def compare_and_report(entry_list, baseline_list, ci_list, check_index, criticality):
        """
        Compares and prints a diff if there is one.
        """
        baseline_item = baseline_list[check_index]
        ci_item = ci_list[check_index]


        diff_count = 0
        for entry in entry_list:
            if baseline_item[entry] != ci_item[entry]:
                diff_count+= 1
                logger.log(criticality, f'Index {check_index} has a mismatch! {entry} differs:')
                num_issues[criticality] = num_issues[criticality] + 1

                # Hack to fix table width for registers
                expand = True if entry == 'registers' else False
                table = Table(title=f"Index {check_index}: Entry diff for '{entry}' field", expand=expand)

                if type(baseline_item[entry]) is dict:
                    table.add_column("Key")
                    table.add_column("Baseline")
                    table.add_column("Generated")

                    for k,v in baseline_item[entry].items():
                        # could be digits
                        k_str = str(k)
                        v_str = str(v)
                        if k in ci_item[entry]:
                            ci_str = str(ci_item[entry][k])
                        else:
                            ci_str = '<missing>'
                        prefix = get_diff_prefix(v_str, ci_str)
                        table.add_row(prefix + k_str, prefix + v_str, prefix + ci_str)
                else:
                    table.add_column("Baseline")
                    table.add_column("Generated")
                    if type(baseline_item[entry]) is str:
                        for (base_line, ci_line) in zip(baseline_item[entry].split('\n'), ci_item[entry].split('\n')):
                            prefix = get_diff_prefix(base_line, ci_line)
                            table.add_row(prefix + base_line, prefix + ci_line)
                    else:
                        prefix = get_diff_prefix(baseline_item[entry], ci_item[entry])
                        table.add_row(prefix + str(baseline_item[entry]), prefix + str(ci_item[entry]))
                console.print(table)
        if diff_count > 0:
            console.print(f'Entry with index {check_index} had {diff_count} differences to the baseline.')

        return diff_count

    diff_list = []

    for file in ci_files:
        logger.info(f'Investigating file {file}.')
        # Loop through all files
        if file not in base_files:
            raise RuntimeError('Generated a CI file that is not in the baseline set. Please rebase CI with the rebase command.')

        # Open CI file and matching baseline file as json
        with open(Path(base_folder)/file, 'r') as f:
            baseline_json = json.load(f)

        with open(Path(ci_folder)/file, 'r') as f:
            ci_json = json.load(f)

        baseline_issues = []
        ci_issues = []
        for i in baseline_json:
            if i['type'] == 3:
                baseline_issues.append(i)

        for i in ci_json:
            if i['type'] == 3:
                ci_issues.append(i)

        # Are they of different length? Give a warning
        if len(baseline_issues) != len(ci_issues):
            logger.critical(
                f'Baseline and CI for {file} are different. Baseline log has {len(baseline_issues)} entries and newly generated CI has {len(ci_issues)} entries')

        # Loop through issues lists and find differences
        index = 0
        max_common_index = min(len(baseline_issues), len(ci_issues))
        to_check = ['plugin', 'rip', 'symbol', 'info', 'severity', 'registers', 'backtrace', 'asm', 'extra']
        while index < max_common_index:
            num_diffs = compare_and_report(to_check, baseline_issues, ci_issues, index, logging.INFO)
            if num_diffs > 0:
                diff_list.append((file, index, num_diffs))
            index += 1


        # Lastly, print the last entries that were missing in the other set
        if len(ci_issues) <= len(baseline_issues):
            smaller_set = 'CI'
            missing_entries = baseline_issues[index:]
        else:
            smaller_set = 'BASELINE'
            missing_entries = ci_issues[index:]

        num_issues[logging.CRITICAL] = num_issues[logging.CRITICAL] + abs(len(ci_issues) - len(baseline_issues))
        if len(missing_entries) > 0:
            diff_list.append((file, 'missing', len(missing_entries)))
            logger.critical(f'These (trimmed) issues were missing in {smaller_set}:')
            for e in missing_entries:
                for key in ('registers', 'asm', 'extra', 'constraints', 'backtrace'):
                    del e[key]
            rich.pretty.pprint(missing_entries)

        logger.info(f'Done with file {file}')

    logger.info('Done: Completed all files.\n')

    if len(diff_list) > 0:
        # Print a table of number of diffs per index
        table = Table(title=f"Difference overview for all files:")
        table.add_column("Filename")
        table.add_column("Index")
        table.add_column("Number of differences")
        for (filename, index, num) in diff_list:
            table.add_row(filename, str(index), str(num))
        console.print(table)

    logger.info(f'{num_issues[logging.DEBUG]:2d} DEBUG issues')
    logger.info(f'{num_issues[logging.INFO]:2d} INFO issues')
    logger.info(f'{num_issues[logging.WARNING]:2d} WARNING issues')
    logger.info(f'{num_issues[logging.CRITICAL]:2d} CRITICAL issues')
    logger.info(f'Overall had {sum(num_issues.values())} issues.')


# Fix map for broken pandora logs (Remove this char, Characters to append to end)
fix_map = {
    ',' : (True, '\n]'), # next item was prepared but is missing. Delete , and end with ]
    ']' : (False, ''), # Correct file (should not be reported)
    '}' : (False, '\n]') #just a closing } missing (most common Pandora problem on crash)
}
def fix(ctx: CIContext):

    if ctx.filepath is None:
        print('fix subcommand requires json file given via -f')
        exit(1)

    if not ctx.filepath.name.endswith('.json'):
        print('fix subcommand only works on .json files')

    logger.info(f'Checking json file {ctx.filepath}. Loading it..')
    with open(ctx.filepath, 'r') as file:
        file_string = file.read()

    logger.info(f'Loaded file. Attempting to parse it...')
    file_json = {}
    fixed = False
    try:
        file_json = json.loads(file_string)
        fixed = True
    except json.JSONDecodeError as e:
        logger.info('File seems to be broken. Attempting to fix it...')
        logger.debug(e)

    # Position of last character
    last_char = -1
    if file_string[-1] == '\n':
        last_char = -2

    if not fixed:
        fixable = False
        logger.info('Checking whether this is an error I can solve...')

        if file_string[last_char] in fix_map:
            replace, char = fix_map[file_string[last_char]]
            if replace:
                attempt_fix = file_string[:last_char] + char
            else:
                attempt_fix = file_string + char

            logger.info(f'Attempting with json end {repr(attempt_fix[-10:])}')
            try:
                file_json = json.loads(attempt_fix)
                fixable = True
            except json.JSONDecodeError:
                logger.info("This did not work...I don't seen to be able to fix this issue.")

        if not fixable:
            # Maybe try more later but for now we're out of luck here.
            logger.info("I can't fix this issue. sorry.")
            exit(1)
        else:
            logger.info('I can fix this file. Working...')

            # First, find the very first json object which contains the beginning time and metadata.
            start_index = file_string.find('{')
            stop_offset = file_string[start_index:].find('},') + 1  # Find on substring gives us the index before

            # Get the timestamp and metadata type entry from the file metadata
            metadata_substring = file_string[start_index: start_index + stop_offset]
            # logger.debug(f'Metadata string seems to be {metadata_substring}')
            file_metadata = json.loads(metadata_substring)
            logger.info(f'Found file metadata:')
            rich.pretty.pprint(file_metadata)
            stop_metadata = {"type": file_metadata['type'],
                             "stop_timestamp": file_metadata['start_timestamp']}

            # Now append that stop_metadata to the string
            stop_metadata_json = json.dumps(stop_metadata)
            logger.info(f'Appending stop metadata: {repr(stop_metadata_json)}')
            replace, char = fix_map[file_string[last_char]]
            if replace:
                attempt_fix = file_string + stop_metadata_json + char
            else:
                attempt_fix = file_string + ',' + stop_metadata_json + char

            logger.info(f'Attempting with file end: {repr(attempt_fix[-10-len(stop_metadata_json):])}')

            try:
                json.loads(attempt_fix)
            except json.JSONDecodeError as e:
                logger.info(f"Sorry, I can't fix this. Error is still:")
                rich.pretty.pprint(e)
                fixed = False
            else:
                with open(ctx.filepath, 'w') as file:
                    file.write(attempt_fix)
                logger.info('Found a fix for file and wrote it to disk.')
                fixed = True

    if fixed:
        logger.info('File seems to be fine (now).')



def main_callback(
        ctx: typer.Context,
        filepath: Path = typer.Option(
            None, "-f", "--file",
            help="Path to a file to be used by the subcommand.",
            exists=True, dir_okay=False, readable=True,
        ),
        no_rerun_ci: bool = typer.Option(
            False, "--no-rerun",
            help="Whether to rerun the CI. Set to false to use the cached version."
        ),
):
    '''
    Pandora: Principled vulnerability detection for SGX binaries.
    '''
    global ci_state
    # Store the state as a pandora context object
    ci_state['ctx'] = CIContext(**locals())

    BASE_CONFIG_PATH = 'config-generate-ci.ini'
    CI_CONFIG_PATH = 'config-ci.ini'

    if ctx.info_name == 'rebase':
        run_ci(ci_state['ctx'], BASE_CONFIG_PATH)
    elif ctx.info_name == 'check':
        logger.info('============ Step 1: Run CI to generate reports. ============')
        if not no_rerun_ci:
            run_ci(ci_state['ctx'], CI_CONFIG_PATH)
        else:
            logger.info('Skipped upon user request.')
        logger.info('============ Step 2: Compare generated reports to old ones on file. ============')
        check(ci_state['ctx'], base_config_path=BASE_CONFIG_PATH, ci_config_path=CI_CONFIG_PATH)
    elif ctx.info_name == 'fix':
        fix(ci_state['ctx'])


# Now we can define the main app as it uses the main_callback
# This is slightly ugly since we want to have the same callback set for all three commands
# The easiest way to do this with typer is to generate them as individual typer subapps that each have the same callback
# Since we invoke these callbacks even without a command, all the magic happens in the lines above this comment where
#  the commands are distinguished and the proper method is dispatched.
COMMAND_HELP_REBASE = 'Generates a new baseline set.'
COMMAND_HELP_CHECK = 'Checks the current Pandora against the baseline set.'
COMMAND_HELP_FIX = 'Checks and repairs a JSON log file if the exploration run was aborted by force.'
app = typer.Typer(add_completion=False, rich_markup_mode="rich", no_args_is_help=True)
app.command(name='rebase', help=COMMAND_HELP_REBASE)(main_callback)
app.command(name='check', help=COMMAND_HELP_CHECK)(main_callback)
app.command(name='fix', help=COMMAND_HELP_FIX)(main_callback)

if __name__ == "__main__":
    app()