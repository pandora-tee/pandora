import angr

from explorer import taint
from explorer.enclave import buffer_entirely_inside_enclave, buffer_touches_enclave
from sdks.SDKManager import SDKManager
from ui.report import Reporter
from pithos.BasePlugin import BasePlugin
from ui.action import UserAction
from utilities.angr_helper import get_reg_value, memory_is_tainted
import logging

from ui.log_format import format_ast, format_asm

logger = logging.getLogger(__name__)

# Global variables used by the hooks.
taint_action = UserAction.NONE
shortname = 'cf'


class ControlFlowSanitizationPlugin(BasePlugin):
    """
    Plugin for detecting attacker-controlled jump targets in an enclave setting.

    # Summary
    At every control-flow jump, we check the following criteria:
    1. target to unmeasured AND uninitialized memory => report CRITICAL
    2. target that is tainted AND target may lie inside or outside enclave => report CRITICAL
    3. target that is tainted AND restricted to fully inside enclave => report WARNING

    Criterion 1 checks that we don't jump to attacker-controlled memory inside
    the enclave. This should never happen in a sane enclave.

    Criterion 2 checks that we don't jump to attacker-controlled _arbitrary_
    locations. This should never happen in a sane enclave.

    Criterion 3 checks that attacker-controlled jump targets always fall
    entirely inside the enclave. Downgrading here to the WARNING level is a
    heuristic here (similar to `ptrsan.py`).

    NOTE: We do not consider _invalid_ jump targets (i.e., concrete jump
    targets falling in non-executable pages or pages outside the enclave) as
    vulnerabilities here, since these would result in a runtime hardware page
    fault. Such invalid jump targets detected in `explorer/techniques/ControlFlow.py`,
    where execution for such paths is aborted.
    """

    @staticmethod
    def get_help_text():
        return 'Detects attacker-controlled jump targets.'

    def init_globals(self):
        global taint_action, shortname
        taint_action = self.action
        shortname = self.shortname

    def init_angr_breakpoints(self, init_state):
        init_state.inspect.b('exit', when=angr.BP_BEFORE, action=check_tainted_jump)

def check_tainted_jump(state):
    """
    At every jump, we check the following criteria:
    1. target to unmeasured AND uninitialized memory => report CRITICAL
    2. target that is tainted AND target may lie inside or outside enclave => report CRITICAL
    3. target that is tainted AND restricted to fully inside enclave => report WARNING
    """
    target = state.inspect.exit_target
    # NOTE: as we don't want to bother decoding the length of the target
    # instruction, we safely over-approximate this here to the maximum length
    # of an x64 instruction (15 bytes)
    target_len = 15
    tainted = taint.is_tainted(target)
    symbolic = state.solver.symbolic(target)
    sdk = SDKManager()
    jumptypes = {
        'Ijk_Call' : 'call',
        'Ijk_Exit' : 'conditional jmp',
        'Ijk_Boring' : 'jmp',
        'Ijk_Ret' : 'ret'
    }
    if state.inspect.exit_jumpkind in jumptypes:
        kind = jumptypes[state.inspect.exit_jumpkind]  
    else:
        kind = state.inspect.exit_jumpkind

    logger.log(logging.TRACE, f'{"Symbolic" if symbolic else "Concrete"} {kind} to {target}')

    # Fast path: do not invoke the constraint solver for concrete jump targets
    # (most prevalent)
    if not symbolic:
        if type(target) is not int:
            target = state.solver.eval_one(target)

        # Jumps to non-executable memory are aborted in
        # `explorer/techniques/ControlFlow.py` and would result in a runtime
        # page fault by SGX hardware. We still report a warning, as this should
        # normally not happen in sane, well-programmed enclaves.
        if not sdk.addr_in_executable_pages(target):
            info = f'Concrete {kind} target in non-executable memory'
            severity = logging.WARNING
            _report_error(state, target, target_len, symbolic, tainted, info, severity)

        else:
            # Case 1: concrete target unmeasured AND uninitialized
            if sdk.addr_in_unmeasured_uninitialized_page(target, target_len):
                if memory_is_tainted(state, target, target_len):
                    info = f'Concrete {kind} target in unmeasured uninitialized memory'
                    severity = logging.CRITICAL
                    _report_error(state, target, target_len, symbolic, tainted, info, severity)

            # Case 2/3: concrete and executable tainted target always lies
            # inside the enclave
            elif tainted:
                info = f'Concrete {kind} tainted target in enclave memory'
                severity = logging.WARNING
                _report_error(state, target, target_len, symbolic, tainted, info, severity)

            # Case 0: always okay if target is concrete AND in the allowlist of
            # executable pages AND not tainted AND measured or initialized

    # Slow path: call the constraint solver to check symbolic jump targets
    else:
        # Case 1: symbolic target touches in unmeasured uninitialized memory
        # TODO: this can probably be optimized by first building a list of
        # constraints and calling the solver only once(?)
        # TODO: we may also consider overapproximating here and only checking
        # for the concrete min and max values of the symbolic target?
        for unmeasured_addr, unmeasured_size in sdk.get_unmeasured_uninitialized_pages():
            if buffer_touches_enclave(state, target, target_len, use_enclave_range=(unmeasured_addr, unmeasured_size)):
                info = f'Symbolic {kind} target in unmeasured uninitialized memory'
                #TODO this may throw false positives when the symbolic memory
                # has been initialized without memset/memcpy.
                # --> ideally we should check this with memory.load as above,
                # but this won't work for symbolic addresses.
                severity = logging.CRITICAL
                _report_error(state, target, target_len, symbolic, tainted, info, severity)
                return

        if tainted:
            # Case 3: symbolic tainted target restricted to fully inside enclave
            if buffer_entirely_inside_enclave(state, target, target_len):
                info = f'Symbolic {kind} tainted target in enclave memory'
                severity = logging.WARNING
                _report_error(state, target, target_len, symbolic, tainted, info, severity)

            # Case 2: symbolic tainted target unrestricted inside/outside enclave
            else:
                info = f'Symbolic unconstrainted tainted {kind} target'
                severity = logging.CRITICAL
                _report_error(state, target, target_len, symbolic, tainted, info, severity)


def _report_error(
        state,
        target,         # Address of memory access
        target_len,
        symbolic,
        tainted,        # True if target is tainted
        info,           # Message to report to the reporter
        severity=logging.CRITICAL,
        extra_info=None,
):
    """
     Reports error to the reporter. Appends useful information such as address range and data if available.
     """
    reporter = Reporter()
    rip = state.scratch.ins_addr  # get_reg_value(state, 'rip') <- this one returns the pc after the call!
    symbol = state.project.loader.find_symbol(rip, fuzzy=True)
    unique = symbol not in reporter.plugins[shortname]['rip']

    # NOTE: we explicitly call the constraint solver here; this is okay as the
    # fast path should normally only save reports in rare and relevant cases
    target_max = state.solver.max(target)
    target_min = state.solver.min(target)
    target_range = f'[{format_ast(target_min)}, {format_ast(target_max)}]'
    target_in_enclave = buffer_entirely_inside_enclave(state, target, target_len)

    extra = {
            'Target': target,
            'Attacker tainted': tainted,
            'Symbolic': symbolic,
            'Target range': target_range,
            'Target entirely inside enclave': target_in_enclave
    }

    if extra_info is not None:
        extra['Extra info'] = extra_info

    # Add disassembly of jump target
    extra_sec = None
    if not symbolic:
        extra_sec = {'Execution state info': [(
                 'Disassembly of jump target (not executed)',
                 format_asm(state, formatting=None, angr_project=state.project, use_rip=target),
                 'verbatim'
        )]}

    # Send this event to reporter
    reporter.report(info, state, logger, shortname, severity, extra, extra_sections=extra_sec)

    if severity >= logging.INFO:
        # Run taint action if requested
        taint_action(state=state, info=info, unique=unique)
