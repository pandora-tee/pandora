# Global console to be reused for all logging. Allows to put a spinner below log messages.
import datetime
import os
from pathlib import Path

from rich.console import Console

console = Console(color_system=None, highlight=False, soft_wrap=True)

# Before importing angr, start a spinner to show progress.
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.live import Live

'''
At creation time of Pandora, we once import the whole of angr to get all its loggers and be able to disable them
as we need. This takes some seconds
'''
p = Progress(
    SpinnerColumn(finished_text=':white_check_mark:'),
    TextColumn("[progress.description]{task.description}"),
    TimeElapsedColumn(),
    transient=True,
)
with Live(p, console=console) as progress:
    task = p.add_task(description=f'Importing angr (this takes a second)', total=None)
    p.advance(task)

    import logging
    p.advance(task)

    # Angr import is important: at call time of the log setup, angr was not included yet, but we want to track its loggers.
    import angr

    p.update(task, total=1.0, completed=1.0)
    # p.remove_task(task)
p.stop()


# Before creating new loggers, get a list of all existing loggers (aka all angr loggers)
initial_loggers = list(logging.root.manager.loggerDict.keys())

# basedir is one up from ui
pandora_root_dir = Path(os.path.dirname(__file__)).parent.resolve().as_posix()

# store one timestamp to be used for all output paths
start_timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")