import datetime
import logging
from collections import defaultdict
import re
from pathlib import Path

import dominate
from ansi2html import Ansi2HTMLConverter
from dominate.tags import *

from ui import pandora_root_dir
from ui.log_format import format_header, format_inline_header, format_table, format_log_level, format_path, log_always
from ui.log_setup import LogLevel
from ui.report import generate_basedir, generate_filename, JsonEntryId

logger = logging.getLogger(__name__)

########################################
#       Formatting logic               #
########################################

class BaseFormatter:
    def __init__(self, title, path, max_rips=0):
        self.max_rips = max_rips
        pass

    def save_report(self):
        pass

    def summary(self, severity_dict):
        pass

    def info(self, title, info):
        pass

    def alert(self, title, info):
        pass

    def section(self, rip, sym, info, severity):
        pass

    def subsection(self, name):
        pass

    def trace(self, name, trace_lst, ansi=False):
        pass

    def verbatim(self, name, text):
        pass

    def table(self, info_dict):
        pass

    def headless_table(self, info_dict):
        pass


def escape_ansi(line):
    """
    Removes all ANSI terminal escape codes from the given string.

    https://stackoverflow.com/a/38662876
    """
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


class LogFileFormatter(logging.Formatter):
    def format(self, record):
        return escape_ansi(record.msg)


class LogFormatter(BaseFormatter):
    def __init__(self, title, path):
        # create a logger that writes both to the console, including ANSI
        # coloring, as well as to a file, without ANSI escape codes.
        # Note: set this logger to DEBUG so everything is captured in the file
        # (but the stdout is still governed by the CLI loglevel option)
        self.logger = logging.getLogger('report.' + title)
        fh = logging.FileHandler(path, mode='w')
        fh.setFormatter(LogFileFormatter('%(message)s'))
        fh.setLevel(logging.DEBUG)
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(fh)

        self.logger.info(f'==== LogFormatter for {title} ====')

    def text(self, text):
        self.logger.info(text)

    def info(self, title, info):
        self.logger.info(f'[INFO] {info}')
        pass

    def alert(self, title, info):
        self.logger.warning(f'[ALERT] {info}')

    def section(self, rip, sym, info, severity):
        self.logger.log(severity, '--------------------------------------------------------------------------------')
        self.logger.log(severity, format_header(f'[{logging.getLevelName(severity)}] [RIP={rip:#x} ({sym})] {info}'))
        self.logger.log(severity, '--------------------------------------------------------------------------------')
        self.sect_sev = severity

    def subsection(self, name):
        self.logger.log(self.sect_sev, format_header('--- ' + name + ' ---'))

    def trace(self, name, trace_lst, ansi=False):
        self.logger.log(self.sect_sev, format_inline_header(name))
        for t in trace_lst:
            self.logger.log(self.sect_sev, t)

    def verbatim(self, name, text):
        self.logger.log(self.sect_sev, format_inline_header(name))
        self.logger.log(self.sect_sev, text)

    def table(self, info_dict):
        self.logger.log(self.sect_sev, format_table(info_dict))

    def headless_table(self, info_dict):
        self.logger.log(self.sect_sev, format_table(info_dict))



class HTMLFormatter(BaseFormatter):
    """
    Relevant documentation links:
        * Python dominate API: https://pypi.org/project/dominate/
        * Bootstrap 5: https://getbootstrap.com/docs/5.0/
    """
    # We use the following bootstrap versions as hard-coded assets from local disk.
    # This makes the html reports self-sustained
    # BOOTSTRAP_CSS = 'https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/css/bootstrap.min.css'
    # BOOTSTRAP_JS = 'https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/js/bootstrap.bundle.min.js'
    # BOOTSTRAP_ICONS = 'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.9.1/font/bootstrap-icons.css'

    badge_styles = {
        'DEBUG': 'bg-success',
        'INFO': 'bg-info text-dark',
        'WARNING': 'bg-warning text-dark',
        'ERROR': 'bg-danger',
        'CRITICAL': 'bg-danger'
    }

    def __init__(self, title, path, max_rips=0):
        self.path = path
        self.conv = Ansi2HTMLConverter()
        self.label_count = 0
        self.sec_map = defaultdict(lambda: [])
        self.max_rips = max_rips

        self.html = dominate.document(title='Report: ' + title)
        with self.html.head:
            for css_file in ['assets/bootstrap.min.css', 'assets/bootstrap-icons.css']:
                with open(f'{pandora_root_dir}/{css_file}', 'r') as file:
                    dominate.util.raw('<style type="text/css">\n')
                    dominate.util.raw(file.read())
                    dominate.util.raw('</style>\n')

            meta(name='viewport', content='width=device-width, initial-scale=1')
            dominate.util.raw('\n' + self.conv.produce_headers())
        self.content = self.html.body.add(div(cls='container d-grid gap-3', style='margin-bottom:200px'))

        with self.html.body:
            for js_file in ['assets/bootstrap.bundle.min.js']:
                with open(f'{pandora_root_dir}/{js_file}', 'r') as file:
                    dominate.util.raw('<script type="text/javascript">\n')
                    dominate.util.raw(file.read())
                    dominate.util.raw('</script>\n')

        with self.content:
            h1('Report ' + title, cls='display-3 text-center')
            hr()

    def save_report(self):
        self.create_rip_sections()

        with open(self.path, 'w') as f:
            print(self.html, file=f)

    def ansi2html(self, s):
        return dominate.util.raw(self.conv.convert(s, full=False))

    def make_unique_label(self, s):
        self.label_count += 1
        return f'{s}_{self.label_count}'

    def summary(self, severity_dict):
        table_dict = {}
        for sev, rips in severity_dict.items():
            table_dict[sev] = ul()
            for (rip, info) in rips:
                table_dict[sev] += li(em(info), f' at {rip:#x}')

        with self.content:
            h2('Report summary')
            self.create_table(table_dict, key='Severity', val='Reported issues')

    def create_box(self, content, desc='', icon=None, alert_type='primary', close=False):
        with self.content:
            d = div(cls=f'alert alert-{alert_type} d-flex align-items-center lead', role='alert')
            with d:
                if icon:
                    i(cls=f'bi bi-{icon}-fill flex-shrink-0 me-2', style='font-size: 1.7em')
                div(strong(f'{desc}: ') if desc else '', content)
                if close:
                    button(type='button', cls='btn-close', data_bs_dismiss='alert')
                    d['class'] += ' alert-dismissible fade show'

    def text(self, text):
        with self.content:
            p(text)

    def info(self, title, info):
        self.create_box(info, title, 'info-circle', 'primary')

    def alert(self, title, info):
        self.create_box(escape_ansi(info), title, 'exclamation-triangle', 'warning')

    def create_badge(self, lbl, style):
        return span(lbl, cls=f'badge rounded-pill {style}')

    def create_badges(self, badges_dict):
        """
        NOTE: we require a dict here to preserve order of the bagdges
        """
        badges = span(style='font-size:.7em')
        for lbl, style in badges_dict.items():
            badges += self.create_badge(lbl, style)
        return badges

    def create_rip_sections(self):
        if not self.sec_map:
            return
        rip_secs = ul(cls='list-group', id='rip_sections')

        # create a collapsible list of issue sections per instruction (RIP)
        for rip, sec_lst in self.sec_map.items():
            if self.max_rips > 0 and len(sec_lst) > self.max_rips:
                badges = {f'{len(sec_lst)} truncated to {self.max_rips}': 'bg-primary'}
                sec_lst = sec_lst[:self.max_rips]
            else:
                badges = {f'{len(sec_lst)}': 'bg-primary'}
            rip_sec = ul(cls='list-group list-group-flush collapse', id=self.make_unique_label('rip_section'))
            for (card, desc, severity, sym) in sec_lst:
                sev_collapse = f' collapse show {severity.lower()}'
                rip_sec += li(card, cls='list-group-item' + sev_collapse)
                badges[sym] = 'bg-light text-dark'
                badges[severity] = self.badge_styles[severity] + sev_collapse
                badges[desc] = self.badge_styles[severity] + sev_collapse

            badges = self.create_badges(badges)
            header = div(h3(a(i(cls='bi bi-chevron-down'), f' Issues reported at {rip:#x}',
                              badges, cls='text-muted text-decoration-none')), cls='w-100',
                         data_bs_toggle='collapse', data_bs_target=f'#{rip_sec["id"]}')
            rip_secs += li(header, rip_sec, cls='list-group-item')

        # create checkboxes to filter based on severity
        checks = div(cls=f'row p-1 lead')
        for lvl in self.badge_styles.keys():
            check = input_(checked='', cls='form-check-input', type='checkbox',
                           value='', id=self.make_unique_label('check'),
                           data_bs_toggle='collapse', data_bs_target=f'.{lvl.lower()}')
            lbl = label(lvl, cls='form-check-label', fr=check['id'])
            checks += div(check, lbl, cls='col col-md-auto form-check')

        self.content += h2('Report details ', small('(click to uncollapse)', cls='text-muted'))
        self.content += checks
        self.content += rip_secs

    def section(self, rip, sym, desc, severity):
        # create a "section" card to be filled with "subsection" information
        # about this vulnerability
        self.sec = div(cls='card-text collapse', id=self.make_unique_label('section'))

        # title the card with vulnerability description and badges
        sev = logging.getLevelName(severity)
        badges = self.create_badges({sev: self.badge_styles[sev], f'RIP={rip:#x}': 'bg-light text-dark'})
        title = div(h4(a(i(cls='bi bi-chevron-compact-down'), f' {desc}', badges,
                         cls='card-title p-2 text-muted text-decoration-none')), cls='w-100',
                    data_bs_toggle='collapse', data_bs_target=f'#{self.sec["id"]}')
        card = div(title, cls='card')
        card += self.sec

        # collect cards per RIP, to be aggregated upon writing out the report
        self.sec_map[rip].append((card, desc, sev, sym))

    def subsection(self, name):
        self.sec += h5(name, cls='p-2')
        self.subsec = div(cls='accordion p-2', id=self.make_unique_label('subsection'))
        self.sec += self.subsec

    def subsubsection(self, name, contents):
        # https://getbootstrap.com/docs/5.2/components/accordion/
        with self.subsec.add(div(cls='accordion-item')):
            target_id = self.make_unique_label('collapse')

            h = h6(cls='accordion-header')
            h += button(name, cls='accordion-button',
                        data_bs_toggle='collapse', data_bs_target=f'#{target_id}')

            d = div(id=target_id, cls='accordion-collapse collapse')
            # data_bs_parent=f'#{self.subsec["id"]}')
            d += div(pre(contents, style='white-space: pre-wrap;'), cls='accordion-body')

    def trace(self, name, trace_lst):
        t = '\n'.join(trace_lst)
        self.subsubsection(name, t)

    def verbatim(self, name, text):
        self.subsubsection(name, self.ansi2html(text))

    def create_table(self, info_dict, key='Key', val='Value'):
        # https://getbootstrap.com/docs/5.2/content/tables/
        t = table(cls='table table-bordered table-striped')
        if (key is not None and val is not None):
            t += thead(tr(th(key), th(val)))
        with t.add(tbody()):
            for k, v in info_dict.items():
                r = tr(cls=f'collapse show {k.lower()}')
                r += td(k)
                r += td(v)
        return t

    def table(self, info_dict):
        self.subsec += self.create_table(info_dict)

    def headless_table(self, info_dict):
        self.subsec += self.create_table(info_dict, key=None, val=None)


########################################
#       Implemented formats            #
########################################
report_formats = {
    'html': HTMLFormatter,
    'log': LogFormatter
}

class ReportFormatter:
    def __init__(self, report_data, report_fmt, reporter_level = LogLevel.INFO, max_rips=0):
        if len(report_data) < 3:
            raise Exception('Report data is missing the metadata fields')

        self.reporter_level = logging.getLevelName(reporter_level.upper())

        # First item in list stores metadata
        self.metadata = report_data[0]
        if self.metadata['type'] != JsonEntryId.ENTRY_ID_METADATA:
            raise Exception('Read Json file does not have the right format (metadata error)')

        self.plugin_entries = []
        self.data = []
        for item in report_data[1:-1]:
            if item['type'] == JsonEntryId.ENTRY_ID_PLUGIN:
                self.plugin_entries.append(item)
            elif item['type'] == JsonEntryId.ENTRY_ID_DATA:
                self.data.append(item)

        # Last item in list stores the completion metadata such as stop_timestamp
        if report_data[-1]['type'] != JsonEntryId.ENTRY_ID_METADATA:
            raise Exception('Read Json file does not end on proper metadata.')
        self.metadata.update(report_data[-1])

        # Initialize formatters for each plugin
        self.plugins = {}
        for plug in self.plugin_entries:

            # Generate path to repo]rt file
            binpath = Path(self.metadata['binary'])
            basedir = generate_basedir('report_folder', binpath)
            filename = f'{generate_filename("report_filename", binpath, logfile_timestamp= self.metadata["time"], force_use_logfile_timestamp=True)}' \
                       f'_{plug["name"]}.{report_fmt}'
            path = basedir / filename

            # Set formatter
            fmt = report_formats[report_fmt](plug['name'], path.as_posix(), max_rips)

            self.plugins[plug['shortname']] = {
                'fmt' : fmt,
                'name' : plug['name'],
                'desc' : plug['desc'],
                'rips' : defaultdict(set),
                'path' : path
            }

        for item in self.data:
            # To reduce generated report filesize, we only print items above report level.
            if item['severity'] >= self.reporter_level:
                self.add_report_item(item)


    def write_reports(self):
        elapsed = datetime.timedelta(seconds=self.metadata['stop_timestamp'] - self.metadata['start_timestamp'])

        for shortname, plug in self.plugins.items():
            fmt = plug['fmt']
            fmt.text('Plugin description: ' + plug['desc'])
            fmt.text(f"Analyzed '{self.metadata['binary']}', with '{self.metadata['sdk']}' enclave runtime. " +
                     f'Ran for {str(elapsed)} on {self.metadata["time"]}.')

            # Backwards compatibility
            if 'enclave_range' in self.metadata:
                fmt.info('Enclave info', f'Address range is {self.metadata["enclave_range"]}')

            # TODO: Slight code duplication to Reporter below
            lvl_summaries = []
            for sev, rips in plug['rips'].items():
                num = len(rips)
                lvl = f'{format_log_level(num, sev)} unique {format_log_level(sev, sev)} issue{"s" if num > 1 else ""}'
                lvl_summaries.append(lvl)

            if len(lvl_summaries) > 0:
                # Only if we have issues, print a summary and write to the file
                issues = f'{"; ".join(lvl_summaries)}.'
                fmt.alert('Summary', 'Found ' + issues)
                fmt.summary(plug['rips'])

                # Then write the rest of the report
                log_always(logger, f"Saving report of {plug['name']} to {format_path(plug['path'])}")
                fmt.save_report()
            else:
                # Report was empty. Ignore it and note that as a log info
                log_always(logger, f"Report of {plug['name']} is empty. Skipping it (not creating a file).")

        log_always(logger, 'Successfully saved all reports.')

    def add_report_item(self, item):
        if not 'extra-sections' in item:
            # Backwards compatibility
            item['extra-sections'] = {}

        fmt = self.plugins[item['plugin']]['fmt']
        rips = self.plugins[item['plugin']]['rips']

        rip = item['rip']
        sym = item['symbol']
        rips[logging.getLevelName(item['severity'])].add((rip, item['info']))

        # Store extended info in formatted report
        fmt.section(rip, sym, item['info'], item['severity'])

        if len(item['extra']) > 0:
            fmt.subsection('Plugin extra info')
            fmt.table(item['extra'])

        def _add_extra_section(group_name):
            if group_name in item['extra-sections']:
                group = item['extra-sections'][group_name]
                for name, content, env_type in group:
                    if env_type == "trace":
                        fmt.trace(name, content)
                    elif env_type == 'verbatim':
                        fmt.verbatim(name, content)
                    elif env_type == 'table':
                        fmt.table(content)

        fmt.subsection('Execution state info')
        fmt.verbatim('Disassembly', item['asm'])
        fmt.verbatim('CPU registers', item['registers'])
        _add_extra_section('Execution state info')

        fmt.subsection('Backtrace')
        fmt.trace(f'Basic block trace (most recent first) - Length: {len(item["backtrace"])}', item['backtrace'])
        _add_extra_section('Backtrace')

        fmt.subsection('Constraints')
        fmt.trace('Attacker constraints', item['constraints'])
        _add_extra_section('Backtrace')

        # Add more extra sections if requested in extra-sections
        for group in [g for g in list(item['extra-sections'].keys())
                      if g not in ["Execution state info", "Backtrace", "Constraints"]]:
            fmt.subsection(group)
            _add_extra_section(group)

