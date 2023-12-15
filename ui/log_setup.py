import configparser
import copy
from collections import defaultdict
import enum

import angr
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

from . import initial_loggers, console

import logging

logger = logging.getLogger(__name__)
# We disable interpolation to allow the format string.
config = configparser.ConfigParser(interpolation=None)


class LogLevel(str, enum.Enum):
    TRACE = "trace"
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

    @staticmethod
    def get_log_levels():
        return [v.value for v in LogLevel.__members__.values()]

    @staticmethod
    def get_max_logname_len():
        return len(max(LogLevel.get_log_levels(), key=len))


DEFAULT_LOG_FORMAT = '%(levelname)s | %(name)s | %(message)s'
DEFAULT_WIDTH = {
    'LoggingLevelnameStyle': LogLevel.get_max_logname_len(),
    'LoggingNameStyle': 20
}


def default_console(theme={}):
    # build a style dict with defaults for all known log levels before
    # passing the _populated_ dict to rich.theme
    style_dict = defaultdict(lambda: 'default', theme)
    for log_level in LogLevel.get_log_levels():
        style_dict[log_level] = style_dict[log_level]

    return Console(theme=Theme(style_dict, inherit=False))


class ColorFormatter(logging.Formatter):
    """
    Color formatter that sets the levelname and name to colors defined in the config file.
    For logging levels above CRITICAL, the formatter omits all fields but the message.
    This is useful for log messages at the end of the program that should always be printed.
    """

    def __init__(self, fmt, themes):
        super().__init__(fmt)
        # load the user-specified themes into custom consoles
        self.consoles = defaultdict(default_console)
        self.console_width = defaultdict(lambda: None, DEFAULT_WIDTH)
        for key, theme in themes.items():
            self.console_width[key] = int(theme.pop('width', self.console_width[key]))
            self.consoles[key] = default_console(theme)

    def fmt_rich(self, key, s, style):
        con = self.consoles[key]
        width = self.console_width[key]
        with con.capture() as capture:
            con.print(s, end='', style=style, justify='left', width=width, overflow='ignore')
        return capture.get().rstrip('\n')

    def format(self, record, *args, **kwargs):
        # if the corresponding logger has children, they may receive modified
        # record, so we want to keep it intact
        new_record = copy.copy(record)

        # Make a distinction for normal logging levels or above even critical
        if record.levelno <= logging.CRITICAL:
            # apply custom formatting as defined in the optional user config file
            style = record.levelname.lower()
            new_record.levelname = self.fmt_rich('LoggingLevelnameStyle', record.levelname, style)
            new_record.name = self.fmt_rich('LoggingNameStyle', record.name, style)

            # now we can let standard formatting take care of the rest
            return super(ColorFormatter, self).format(new_record, *args, **kwargs)
        # For above critical, just print the formatted message.
        else:
            # TODO: This seems to have issues logging dicts.
            return record.msg.format(*args, **kwargs)


class PandoraRichHandler(RichHandler):
    def emit(self, record: logging.LogRecord) -> None:
        """
        Overwrite the default way log messages are emitted by the handler.
        In Pandora, we prepare all logging via the log message. Thus, the handler does not need to perform any
            duties except push that message to the console.
        """
        message = self.format(record)

        message_renderable = self.render_message(record, message)

        try:
            self.console.print(message_renderable)
        except Exception:
            self.handleError(record)


def parse_config_file(config_file):
    if config_file:
        config.read(config_file)

    return config


def init_logger(config_file, pandora_level, angr_level):
    """
    Initializes the logger based on config information
    """
    parse_config_file(config_file)

    config_logging = config['Logging'] if 'Logging' in config else {}
    fmt = config_logging.get('format', DEFAULT_LOG_FORMAT)

    themes = {sect: dict(config.items(sect)) for sect in config if 'Style' in sect}

    # Register the all debug level with the logging module
    logging.TRACE = logging.DEBUG - 5
    logging.addLevelName(logging.DEBUG - 5, 'TRACE')

    # setup log handler
    formatter = ColorFormatter(fmt, themes)
    handler = PandoraRichHandler(console=console, markup=False, show_time=False, show_level=False, show_path=False)
    handler.setLevel(pandora_level.upper())
    handler.setFormatter(formatter)

    # Overwrite basic config to set handlers and general verbosity
    logging.basicConfig(
        force=True,
        handlers=[handler],
        level=pandora_level.upper()
    )

    # set all existing (i.e., angr, non-pandora) loggers to requested level
    angr_log_level = angr_level.upper()
    for l in initial_loggers:
        logging.getLogger(l).setLevel(angr_log_level)

    logger.info(f'Logger successfully set up. Pandora level is '
                f'{logging.getLevelName(logger.getEffectiveLevel())}; '
                f'Angr level is {angr_log_level}, {len(initial_loggers)} loggers)')
