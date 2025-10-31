import logging

import angr
import claripy

from explorer import taint
from pithos.BasePlugin import BasePlugin
from ui.action import UserAction
from ui.log_format import (
    format_ast,
)
from ui.report import Reporter
from utilities.angr_helper import get_reg_value

logger = logging.getLogger(__name__)

# Global variables used by the hooks.
taint_action = UserAction.NONE
shortname = "ptr"


class PointerSanitizationPlugin(BasePlugin):
    """
    Plugin for checking pointer sanitization.

    # Summary Pointer Sanitization
    At every memory read and write, we check the following criteria:
    1. address may lie inside or outside enclave => Return CRITICAL
    2. address is tainted AND address lies entirely inside enclave => Return WARNING
    3. address is not-tainted AND address may lie outside enclave => Return CRITICAL

    Criterion 1 checks that we do not have unconstrained pointers: when address may lie inside or outside enclave it
    generally means that the address is not constrained and there is no sane use case that would allow such behavior.

    Criterion 2 check that attacker controlled pointers are properly sanitized.
    Instead of raising a critical issue for attacker controlled pointers inside enclave, we raise a WARNING.
    The rationale behind that is that when address lies entirely inside enclave, it means that the address is
    'constrained'. This might be, for instance, a memory access resulting from an attacker provided index, which has
    been checked properly to lie inside a table.
    Note that this downgrade is only a heuristics to reduce false alarms: if there is an out-of-bound memory access that
    lies completely inside the enclave, the plugin will report it as a WARNING instead of a CRITICAL error. However,
    this heuristics seems like the best we can get in the absence of a policy for defining out-of-bound memory accesses.

    Criterion 3 checks that a pointer crafted by the enclave does not access untrusted memory (this should never happen
    in a sane enclave).

    # Relevant links
    See https://dl.acm.org/doi/abs/10.1145/3319535.3363206 for examples of vulnerabilities exploiting incorrect pointer
    sanitizations.
    """

    @staticmethod
    def get_help_text():
        return "Validates attacker-tainted pointer dereferences."

    def init_globals(self):
        global taint_action, shortname
        taint_action = self.action
        shortname = self.shortname

    def init_angr_breakpoints(self, init_state):
        """
        Note that because read hooks are triggered as angr.BP_BEFORE, we don't have the data yet
        """
        # Criterion 1: address may lie inside or outside enclave => Return CRITICAL
        init_state.inspect.b("inside_or_outside_mem_read", when=angr.BP_BEFORE, action=unconstrained_read_hook)
        init_state.inspect.b("inside_or_outside_mem_write", when=angr.BP_BEFORE, action=unconstrained_write_hook)

        # Criterion 2: address is tainted AND address lies entirely inside enclave => Return WARNING
        init_state.inspect.b("trusted_mem_read", when=angr.BP_BEFORE, action=trusted_mem_read_hook)
        init_state.inspect.b("trusted_mem_write", when=angr.BP_BEFORE, action=trusted_mem_write_hook)

        # Criterion 3: address is not-tainted AND address lies outside enclave => Return CRITICAL
        init_state.inspect.b("untrusted_mem_read", when=angr.BP_BEFORE, action=untrusted_read_hook)
        init_state.inspect.b("untrusted_mem_write", when=angr.BP_BEFORE, action=untrusted_write_hook)


def unconstrained_read_hook(state):
    """
    Criteria 1: address may lie inside or outside enclave => Return CRITICAL
    """
    addr = state.inspect.mem_read_address
    tainted = taint.is_tainted(addr)
    length = state.inspect.mem_read_length
    info = "Unconstrained read"
    extra_info = "Read address may lie inside or outside enclave"

    _report_error(state, addr, tainted, length, info, ptr_in_enclave=True, severity=logging.CRITICAL, extra_info=extra_info)


def unconstrained_write_hook(state):
    """
    Criteria 1: address may lie inside or outside enclave => Return CRITICAL
    """
    addr = state.inspect.mem_write_address
    tainted = taint.is_tainted(addr)
    length = state.inspect.mem_write_length
    data = state.inspect.mem_write_expr
    info = "Unconstrained write"
    extra_info = "Write address may lie inside or outside enclave"

    # Length may be None. In that case, take the size from data
    if length is None:
        length = len(data)

    _report_error(state, addr, tainted, length, info, ptr_in_enclave=True, severity=logging.CRITICAL, data=data, extra_info=extra_info)


def trusted_mem_read_hook(state):
    """
    Criteria 2: address is tainted AND address lies entirely inside enclave => Return WARNING
    """
    addr = state.inspect.mem_read_address
    tainted = taint.is_tainted(addr)
    length = state.inspect.mem_read_length
    info = "Attacker tainted read inside enclave"
    extra_info = "Issue downgraded to a warning since read is strictly constrained to memory region inside enclave. Disclaimer: This is a heuristic only, please double check manually!"

    if tainted:
        _report_error(state, addr, tainted, length, info, ptr_in_enclave=True, severity=logging.WARNING, extra_info=extra_info)


def trusted_mem_write_hook(state):
    """
    Criteria 2: address is tainted AND address lies entirely inside enclave => Return WARNING
    """
    addr = state.inspect.mem_write_address
    tainted = taint.is_tainted(addr)
    length = state.inspect.mem_write_length
    data = state.inspect.mem_write_expr
    info = "Attacker tainted write inside enclave"
    extra_info = "Issue downgraded to a warning since write is strictly constrained to memory region inside enclave. Disclaimer: This is a heuristic only, please double check manually!"

    # Length may be None. In that case, take the size from data
    if length is None:
        length = len(data)

    if tainted:
        _report_error(state, addr, tainted, length, info, ptr_in_enclave=True, severity=logging.WARNING, data=data, extra_info=extra_info)


def untrusted_read_hook(state):
    """
    Criterion 3: address is not-tainted AND address lies outside enclave => Return CRITICAL
    """
    addr = state.inspect.mem_read_address
    tainted = taint.is_tainted(addr)
    length = state.inspect.mem_read_length
    info = "Non-tainted read outside enclave"

    if not tainted:
        _report_error(state, addr, tainted, length, info, ptr_in_enclave=False, severity=logging.CRITICAL)


def untrusted_write_hook(state):
    """
    Criterion 3: address is not-tainted AND address lies outside enclave => Return CRITICAL
    """
    addr = state.inspect.mem_write_address
    tainted = taint.is_tainted(addr)
    length = state.inspect.mem_write_length
    data = state.inspect.mem_write_expr
    info = "Non-tainted write outside enclave"
    # Length may be None. In that case, take the size from data
    if length is None:
        length = len(data)

    if not tainted:
        _report_error(state, addr, tainted, length, info, ptr_in_enclave=False, severity=logging.CRITICAL, data=data)


def _report_error(
    state,
    addr,  # Address of memory access
    tainted,  # True if address is tainted
    length,  # Length of memory access
    info,  # Message to report to the reporter
    ptr_in_enclave,  # True if pointer can lie in enclave
    severity=logging.CRITICAL,
    data=None,
    extra_info=None,
):
    """
    Reports error to the reporter. Appends useful information such as address range and data if available.
    """
    if type(addr) is int:
        addr = claripy.BVV(addr, 64)

    reporter = Reporter()
    ip = get_reg_value(state, "ip")
    symbol = state.project.loader.find_symbol(ip, fuzzy=True)
    unique = symbol not in reporter.plugins[shortname]["ip"]

    # Send this event to reporter
    addr_max = state.solver.max(addr)
    addr_min = state.solver.min(addr)
    addr_range = f"[{format_ast(addr_min)}, {format_ast(addr_max)}]"

    can_wrap = state.solver.satisfiable(extra_constraints=[addr.UGT(addr + length - 1)])

    extra = {"Address": addr, "Attacker tainted": tainted, "Length": length, "Pointer range": addr_range, "Pointer can wrap address space": can_wrap, "Pointer can lie in enclave": ptr_in_enclave}
    if data is not None:
        extra["Data"] = state.solver.simplify(data)
    if extra_info is not None:
        extra["Extra info"] = extra_info

    # Lastly, send off that issue to the reporter
    reporter.report(info, state, logger, shortname, severity, extra)

    # Run taint action if requested
    taint_action(state=state, info=info, unique=unique)
