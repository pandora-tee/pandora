import logging
from functools import singledispatch

from rich.console import Console
from rich.pretty import Pretty
from rich.table import Table
from rich.theme import Theme

import re

from explorer import taint
from utilities.angr_helper import get_reg_value
from explorer.x86 import x86_arch_regs, x86_privileged_regs
from sdks.SymbolManager import SymbolManager

import logging
logger = logging.getLogger(__name__)

# workaround to make rich print hex numbers and strings without enclosing
# quotation marks
class RichHex():
    def __init__(self, num):
        self.num = num

    def __repr__(self):
        return hex(self.num)


class RichKey():
    def __init__(self, s):
        if type(s) == str:
            self.str = s
        else:
            self.str = str(s)

    def __repr__(self):
        return self.str


def format_fields(fields, normal_format=False):
    """
    Formats the given fields for Pandora. Will convert all numbers to hex.
    If the normal_format option is set to true, will try to format dict values with string() instead of as hex.
    """
    @singledispatch
    def _format(field: object) -> object:
        return field

    @_format.register
    def _(field: int) -> RichHex:
        return RichHex(field)

    @_format.register
    def _(field: str) -> RichKey:
        return RichKey(field)

    @_format.register
    def _(field: dict) -> dict:
        return {RichKey(k) : _format(v) for (k, v) in field.items()}

    @_format.register
    def _(field: list) -> list:
        return [_format(val) for val in field]

    @_format.register
    def _(field: tuple) -> tuple:
        return tuple([_format(val) for val in field])

    @singledispatch
    def _format_normal(field: dict) -> dict:
        return {RichKey(k) : RichKey(str(v)) for (k,v) in field.items()}

    if normal_format:
        my_format = _format_normal(fields)
    else:
        my_format = _format(fields)

    return format_rich(my_format, pretty=True, rich_content=True).rstrip('\n')

def format_ast(expression):
    """
    Allows to pretty print an AST that is either a symbolic expression or an int.
    Ints are printed as hex values, ASTs are simply cast to str and returned.
    """
    @singledispatch
    def _format(expression: object) -> object:
        return expression

    @_format.register
    def _(expression: int) -> RichHex:
        return RichHex(expression)

    return str(_format(expression))


empty_console = Console(theme=Theme({}, inherit=False), soft_wrap=True)
rich_console = Console(theme=Theme({'repr.str': 'default italic'}), soft_wrap=True)
def format_rich(msg, style='', rich_content=False, markdown=False, pretty=False):
    if not rich_content:
        con = empty_console
    else:
        con = rich_console

    if pretty:
        msg = Pretty(msg, expand_all=True, indent_guides=True)

    with con.capture() as capture:
        con.print(msg, end='', style=style, markup=markdown, overflow='ignore')
    return capture.get()  # .rstrip('\n')


"""
Usable format strings for logging messages to get some consistency.
"""


def format_error(msg):
    return format_rich(msg, 'bold red')


def format_warning(msg):
    return format_rich(msg, 'yellow')


def format_good(msg):
    return format_rich(msg, 'bold green')


def format_bad(msg):
    return format_rich(msg, 'bold red')


def format_header(msg):
    return format_rich(msg, 'bold')


def format_inline_header(msg):
    return format_rich(msg, 'cyan')


def format_log_level(msg, log_level):
    if log_level == 'DEBUG':
        return format_good(msg)
    elif log_level == 'INFO':
        return format_good(msg)
    elif log_level == 'WARNING':
        return format_warning(msg)
    elif log_level == 'ERROR':
        return format_error(msg)
    elif log_level == 'CRITICAL':
        return format_bad(msg)
    else:
        raise Exception(f"unknown log level '{log_level}'")


def format_table(kv_dict, key_hdr='key', val_hdr='value'):
    table = Table(title='', safe_box=True)
    table.add_column(key_hdr)
    table.add_column(val_hdr)

    for k, v in kv_dict.items():
        table.add_row(str(k), str(v))

    return format_rich(table, rich_content=True)


def format_link(url, linkname):
    md = f'[link={url}]{linkname}[/link]'
    return format_rich(md, markdown=True)


def format_path(path):
    return format_link(path.absolute().as_uri(), path.as_posix())


def log_always(logger, msg):
    logger.log(logging.CRITICAL + 10, msg)


def format_regs(state, only_gen_purpose=False, exit=False):
    regs = ''

    for reg_name in state.project.arch.register_names.values():
        # skip internal angr pseudo registers
        artificial_registers = getattr(state.project.arch, 'artificial_registers', [])
        if reg_name in artificial_registers or \
                reg_name in x86_arch_regs or \
                reg_name in x86_privileged_regs:
            continue
        # optionally skip non-general purpose registers
        if only_gen_purpose and reg_name not in state.arch.default_symbolic_registers:
            continue

        reg = get_reg_value(state, reg_name)

        # mark tainted registers
        if not exit:
            match = taint.is_tainted(reg)
            do_pr = True
        else:
            match = not taint.is_tainted(reg) and reg != 0
            do_pr = match

        if match:
            s = format_bad(f'*\t{reg_name:8s}')
        else:
            s = f' \t{reg_name:8s}'

        if state.solver.symbolic(reg):
            r = str(reg)
        else:
            r = hex(reg)

        if do_pr:
            regs += f'\t{s} : {r}\n'

    return regs


def dump_regs(state, logger, log_level=logging.DEBUG, only_gen_purpose=False, exit=False, header_msg=""):
    log_msg = format_header(header_msg) \
              + format_inline_header('\n\t---- BEGIN REGISTERS {} ----'.format('(exit leakage)' if exit else '')) + '\n'

    log_msg += format_regs(state, only_gen_purpose, exit)

    log_msg = log_msg + '\t' + format_bad("*") + ' -> Attacker tainted\n'
    log_msg = log_msg + format_inline_header('\t---- END REGISTERS ----')

    logger.log(log_level, log_msg)


def format_attacker_constraints(state):
    log_msg = ''
    ca = [c for c in state.solver.constraints if taint.is_tainted(c)]
    if len(ca) > 0:
        for c in ca:
            log_msg = log_msg + f'* {c}\n'

    return log_msg

def dump_attacker_constraints(state, logger, log_level=logging.DEBUG, header_msg=""):
    ca = format_attacker_constraints(state)
    if len(ca) > 0:
        log_msg = format_header(header_msg) + '\n' + format_inline_header(
            '\t--- Begin solver attacker constraints ---\n')
        log_msg += ca
        log_msg += format_inline_header('\t--- End solver attacker constraints ---')
        logger.log(log_level, log_msg)

def get_state_backtrace_formatted(state):
    """
    Returns the block backtrace for a given state, formatted as a list of strings that can be printed immediately.
    """
    bbt = []
    for a in state.history.bbl_addrs:
        sym_name = SymbolManager().get_symbol_with_offset(a)
        rel = SymbolManager().get_rebased_addr(a)
        bbt.append(f'{sym_name:<35} ({rel:#x} relative to obj base)')
    return list(reversed(bbt))

def get_state_backtrace_compact(state):
    bbt = []
    sym_name_prev = ''
    for a in state.history.bbl_addrs:
        sym_name = SymbolManager().get_symbol(a)
        rel = SymbolManager().get_rebased_addr(a)
        if sym_name != sym_name_prev:
            bbt.append(f'{a:#x} {"<" + sym_name + ">":<35} ({rel:#x} relative to obj base)')
        sym_name_prev = sym_name
    return bbt

def format_asm(state, formatting=None, angr_project=None, use_ip=None, highlight_ip=None):
    """
    :param use_ip: Allows to overwrite the ip that is dumped. Useful for when the state is actually a
    history state with no registers anymore.
    :param angr_project: Overwrite the angr project. Useful for when the state is actually a
    history state with no registers anymore.
    :param highlight_ip: None or a hex string
    """
    if angr_project is None:
        angr_project = state.project

    if use_ip is None:
        if state.scratch.bbl_addr is not None:
            ip = state.scratch.bbl_addr
        else:
            ip = get_reg_value(state, 'ip')
    else:
        ip = use_ip
    
    current_block = angr_project.factory.block(ip)
    try:
        disasm = angr_project.analyses.Disassembly(ranges=[(current_block.addr, current_block.addr +current_block.size)])
        pp = disasm.render(formatting=formatting)
        pp = re.sub(r'0x[0-9a-f]+', lambda h: SymbolManager().get_hex_symbol(int(h.group(),base=16)), pp)
        ins_list = [f'\t{line.lstrip()}\n' for line in pp.split('\n')]
        if highlight_ip:
            usable_ip = f'{highlight_ip:x}'
            for idx, ins_str in enumerate(ins_list):
                if usable_ip in ins_str:
                    ins_list[idx] = 'x' + ins_str
                    break
        pretty_print_str = "".join(ins_list)
    except Exception as e:
        # VEX does not support disassembly for MSP430 so we work around that
        # here by calling objdump externally
        arch = angr_project.arch.name.lower()
        logger.debug(f"Exception '{e.__class__.__name__}' when disassembling; falling back to {arch}-objdump..")
        pretty_print_str = SymbolManager().get_objdump(ip, ip+current_block.size, arch=arch)
    
    # print('---- BEGIN VEX ----')
    # proj.factory.block(ip).vex.pp()
    # print('---- END VEX ----')

    return pretty_print_str

def dump_asm(state, logger, log_level=logging.DEBUG, header_msg="", angr_project=None, use_ip=None):
    """
    :param use_ip: Allows to overwrite the ip that is dumped. Useful for when the state is actually a
    history state with no registers anymore.
    :param angr_project: Overwrite the angr project. Useful for when the state is actually a
    history state with no registers anymore.
    """
    if angr_project is None:
        angr_project = state.project

    asm = format_asm(state, angr_project=angr_project, use_ip=use_ip)
    if use_ip is not None:
        ip = use_ip
    else:
        if state.scratch.bbl_addr is not None:
            ip = state.scratch.bbl_addr
        else:
            ip = get_reg_value(state, 'ip')

    sym = SymbolManager().get_symbol(ip)

    log_msg = format_header(header_msg) \
              + format_inline_header(f'\n\t---- BEGIN ASM ({sym}) ----') \
              + '\n' + asm \
              + format_inline_header('\t---- END ASM ----')
    logger.log(log_level, log_msg)
    return sym

def format_solver(state, expr):
    if not state.solver.satisfiable():
        res = 'unsat'
    else:
        se = state.solver.eval(expr)
        if type(se) != bool:
            se = '{:#x}'.format(se)
        res = f'{se} (unique={state.solver.unique(expr)})'
    return res


def dump_solver(state, expr, logger, log_level=logging.DEBUG):
    res = format_solver(state, expr)
    logger.log(log_level, f'solver says {expr} := {res}')
