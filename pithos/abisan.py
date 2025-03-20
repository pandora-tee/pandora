import angr

from sdks.SDKManager import SDKManager
from sdks.SymbolManager import SymbolManager
from ui.report import Reporter
from utilities.angr_helper import get_sym_reg_value, get_reg_value, set_reg_value, get_reg_name, concretize_value_or_fail, \
    concretize_value_or_none, get_current_opcode
from explorer.x86 import x86_data_regs, x86_arch_regs, x86_privileged_regs
from pithos.BasePlugin import BasePlugin
from ui.action import UserAction

from explorer import taint
from ui.log_format import dump_regs, format_fields, format_header

abi_action = UserAction.NONE
abi_shortname = 'abi'
ignored_regs = {}

import logging
logger = logging.getLogger(__name__)

class ABISanitizationPlugin(BasePlugin):
    """
    Plugin for detecting improperly sanitized registers and flags.

    # Summary
    The plugin checks that:
    1. No attacker controlled register is read => report CRITICAL if done anyway
       Registers in `x86_data_regs` or `ignored_regs` (i.e., x86_privileged_regs and agnr artificial registers) are
       ignored.
    2. At the end of ABI sanitization phase (i.e., heuristically first call), all registers are sanitized
       => report WARNING for unsanitized registers
       Registers in "ignored_regs" and `eenter_untrusted_regs` (i.e., 'rsi', 'rdi') are ignored.
    3. On EEXIT, stack registers are attacker tainted (i.e., 'rsp', 'rbx') => report WARNING if they are untainted

    A possible extension to do at a later point is to check that:
    4. On EEXIT, x86_data_regs do not contain enclave secrets (i.e., non-attacker tainted symbolic values)
       => report WARNING if registers are tainted secret

    """

    def __init__(self, init_state, reporter, usr_act=UserAction.NONE, shortname=abi_shortname):
        self.angr_arch = SDKManager().get_angr_arch()
        super().__init__(init_state, reporter, usr_act, shortname)

        if self.angr_arch == 'x86_64':
            # Initialize ignored regs from architectural artificial registers and privileged registers
            global ignored_regs
            ignored_regs = x86_arch_regs.union(set(init_state.project.arch.artificial_registers), x86_privileged_regs)
            logger.debug(f'Will ignore the following architectural registers in the ABI plugin: {ignored_regs}')
        else:
            logger.debug(f"Note: abisan support for MSP430 is currently limited to EEXIT register cleansing checking..")

    @staticmethod
    def get_help_text():
        return 'Validates CPU register sanitizations.'

    @staticmethod
    def supports_arch(angr_arch):
        return True

    def init_globals(self):
        global abi_action, reporter, abi_shortname
        abi_action = self.action
        reporter = self.reporter
        abi_shortname = self.shortname

    def init_angr_breakpoints(self, init_state):
        if self.angr_arch == 'x86_64':
            # Prepare init_state global for API entry
            init_state.globals['abi_hit_api_entry'] = False

            # Criterion 1: do not read attacker-controlled registers
            init_state.inspect.b('reg_read', when=angr.BP_AFTER, action=reg_read_hook)

            # Criterion 2: check that register are sanitized at the end of ABI sanitization phase
            init_state.inspect.b('call', when=angr.BP_AFTER, action=break_abi_to_api)

            # Criterion 3 (and 4): check that stack regs are tainted (and that x86_data_regs do not contain enclave secrets)
            init_state.inspect.b('eexit', when=angr.BP_AFTER, action=break_abi_eexit)
        elif self.angr_arch == 'msp430':
            init_state.inspect.b('eexit', when=angr.BP_AFTER, action=break_abi_eexit_msp430)

def reg_read_hook(state):
    """
    On *every* register read, we hook this function. This makes it very expensive and we make sure that it exits early
     if we are not exploring.
    """
    # First: Check if the state is even active and abort if the state is currently not being active yet:
    if not state.globals['pandora_active']:
        return

    # Then, check whether the register read is tainted
    reg_expr = state.inspect.reg_read_expr
    if taint.is_tainted(reg_expr):
        # Expression is tainted!
        # Get the reg offset and name. Offset should be a concrete value. If it is symbolic, something probably went wrong.
        reg_offset = concretize_value_or_fail(state, state.inspect.reg_read_offset)
        reg_name = get_reg_name(state, reg_offset)

        if reg_name in x86_data_regs or reg_name in ignored_regs:
            return

        # allowlist certain opcodes that _store_ possibly tainted flag bits
        opcode = get_current_opcode(state)
        if 'pushf' in opcode or 'stmxcsr' in opcode or 'fnstcw' in opcode:
            logger.warning(f'ignoring attacker-tainted read from {reg_name.upper()} in {format_header(opcode)}')
            return

        """
        We can now be certain that this is an issue, a tainted data register has been read!
        
        Potential Todo:
        Ideally we should skip some known false positives here (e.g., popfq and pushfq are harmless but read/write the flags..)
        However doing so arbitrarily would mean that we disassembly the current instruction address on each register 
            read which is quite expensive. So for now we leave it as-is.
        """

        extra = {'reg_name': reg_name, 'reg': str(reg_expr)}
        logger.info(f'Detected an attacker-tainted read from {reg_name.upper()} register')
        dump_regs(state, logger, logging.INFO, only_gen_purpose=True)
        Reporter().report(f'Attacker-tainted read from {reg_name.upper()} register', state, logger, abi_shortname,
                        logging.CRITICAL, extra)
        logger.info('')
        abi_action(state=state, info='[abi-read]')


api_addr = None
api_false_alarms = {'restore_xregs'}
eenter_untrusted_regs = {'rsi', 'rdi'}
eexit_untrusted_regs = {'rsp', 'rbx'}

def break_abi_to_api(state):
    """
    When breaking from the ABI to the API entry point, we want to check that all control registers are cleared from
     attacker-tainted influences.

    Since this breakpoint executes on *each* call, we need to early out very quickly.
    We keep two global variables:
     1. A Pandora-global variable api_addr that keeps the address of the API entry point once it is found.
     2. A state (globals) variable that remembers whether this state already entered the API entry point. It is not too
     important to restore this on EENTER since if the ABI/API break is broken, it should already be found on first entry (probably) (normally).
    """
    global api_addr   # Address of the api when found
    global eenter_untrusted_regs # Registers that are fine to be untrusted on EENTER

    # 1) Is global api_addr already found?
    if api_addr is None:
        ip = concretize_value_or_none(state, state.inspect.function_address)

        if not ip:
            # Something is horribly wrong. There seems to be more than one concrete solution to the IP address
            #  we want to jump to. This should never happen and will also probably crash soon.
            logger.critical(f'--- ABI2API breakpoint @{ip} seems to be symbolic. Aborting ---')
            return

        sym_name = SymbolManager().get_symbol(ip)
        """
        Our heuristic assumes that the first call instruction is the actual api entry point. 
        While surprisingly effective, this is not true for all SDKs.
        For example the Intel SDK has as a first call a restore_xregs function.
        Until we find a smarter way of doing so, we can go a long way by double-checking that the
        API break does not happen onto a blocklisted symbol.
        However, for OpenEnclave, Scone, and the Linux Selftest enclave, the first call is indeed the API breakpoint.
        """
        if sym_name in api_false_alarms:
            return

        # If we are still here, assume this is indeed the API breakpoint.
        logger.info(f'--- Found global ABI2API breakpoint @{sym_name} ---')
        dump_regs(state, logger, header_msg='Registers at ABI2API break:')
        api_addr = ip

        Reporter().report('API entry point', state, logger, abi_shortname, logging.INFO)

    # Either if we just set it or if it was already set, check if api has already been found and we have not hit it yet
    if api_addr is not None and not state.globals['abi_hit_api_entry']:

        if concretize_value_or_none(state, state.inspect.function_address) == api_addr:
            """
            We seem to be doing the api break. Do our thing:
            Loop over all registers and warn about them if they are tainted data registers
            Some regs are allowed to be tainted on eenter
            """
            logger.debug('--- Investigating ABI2API state breakpoint ---')
            state.globals['abi_hit_api_entry'] = True

            extra = {}
            extra_info = ''
            extra_sec = None
            lvl = logging.WARNING

            # first go over "shadow" x86 registers unknown to angr and kept manually by Pandora
            mxcsr = state.globals['pandora_mxcsr']
            if taint.is_tainted(mxcsr):
                do_report = True
            else:
                # NOTE to protect against Intel's recent MXCSR Configuration
                # Dependent Timing (MCDT) security advisory, MXCSR always needs
                # to be _exactly_ the value 0x1FBF
                try: 
                    mxcsr_val = state.solver.eval_one(mxcsr)
                    do_report = mxcsr_val != 0x1FBF
                    mxcsr = hex(mxcsr_val)
                except:
                    do_report = True

            # If MXCSR already wants to do a report, this is a critical issue
            if do_report:
                lvl = logging.CRITICAL
                extra_info = '; MCDT'
                extra['MXCSR'] = mxcsr
                extra_sec = {'MXCSR Configuration Dependent Timing (MCDT)': [
                    ('', {
                        'Actual MXCSR value': str(mxcsr),
                        'Expected MXCSR value': '0x1FBF',
                        'Additional information': 'After setting the mxcsr to 0x1FBF, an lfence instruction is advised by Intel.',
                        'Intel security advisory': 'https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/mxcsr-configuration-dependent-timing.html'
                    }, 'table'),
                    ]}
    
            # now go over all angr-known registers
            for reg_name in state.project.arch.register_names.values():
                if reg_name in ignored_regs or reg_name in eenter_untrusted_regs:
                    continue

                reg = get_reg_value(state, reg_name)
                if taint.is_tainted(reg):
                    extra[reg_name.upper()] = reg
                
                """
                NOTE: angr appears to compute RFLAGS lazily. This means that it
                will keep a lengthy `<BV64 if ... >` symbolic expression when
                some of the RFLAGS bits were tainted by the attacker on entry
                and afterwards sanitized by the enclave. If the sanitization
                was correct, the above call to `get_reg_value` will yield only
                one unique concrete solution (as provided by `solver.eval_one`).
                
                Thus, we can simply replace the symbolic value with its only 
                possible concrete result. This effectively forces an "eager"
                replacement of these flag bits, so that when they are used later
                they will not appear to be tainted by the attacker and will
                not trigger any false positives. That is, because there is only
                one concrete result for this symbolic expression, we are sure
                that any attacker-controlled symbolic values in the above if 
                expression were properly masked away by the enclave 
                sanitization logic.

                See also <https://docs.angr.io/advanced-topics/ir#condition-flags-computation-for-x86-and-arm>
                """
                if (reg_name == 'd' or reg_name == 'ac' or reg_name == 'id') \
                   and not state.solver.symbolic(reg):
                    logger.debug(f'Eagerly concretizing RFLAGS.{reg_name.upper()} symbolic expression {format_fields(get_sym_reg_value(state, reg_name))} with unique concrete value={reg}.')
                    set_reg_value(state, reg_name, reg)

            if len(extra.keys()) > 0:
                Reporter().report(f'{len(extra.keys())} attacker-tainted entry registers' + extra_info,
                                state, logger, abi_shortname, lvl, extra,
                                extra_sections=extra_sec)
                abi_action(state=state, info=f'[abi2api] And have {len(extra.keys())} issues to report.')

            logger.debug('--- ABI2API investigation complete ---')


def break_abi_eexit(state):
    """
    When the enclave performs an EEXIT, we want to make sure that no enclave secrets leak to the attacker.
    As of now, 'secret' tainting is not implemented.
    However, we can still perform some minimal checks on EEXIT that:
     - eexit_untrusted_regs *should* be tainted
     - data registers that are *not* tainted, should not contain symbolic values

    This misses on important case: it could well be that a concrete secret is still in a register or flag
    A similar, alternative check could be that registers are *zeroed out* on EEXIT to avoid missing vulnerabilities
      when a value has been concretized for some reason.
    However, a register could as well be *tainted and still* contain secret data!

    Thus, we do not try to be better but still bad here and instead note that a better implementation would
     be to have a *secret taint* for the enclave secrets/data.
    If we want to focus on runtimes we could have a hook for a dummy enclave application that sets everything to secret.
    """
    global eexit_untrusted_regs

    # Check if we successfully hooked EEXIT in explorer/x86.py
    if state.globals['eexit']:
        # First, dump some info on cli
        # Get ip just for printing, so it's fine if it stays symbolic (however it logically should never be symbolic)
        ip = get_reg_value(state, 'ip')
        logger.debug(f'--- Investigating EEXIT state breakpoint @ {ip:#x} ---')
        dump_regs(state, logger, log_level=logging.DEBUG)

        # Check all data registers for their value
        for reg_name in x86_data_regs:
            # Some registers should be attacker tainted (stack registers should refer to the untrusted stack)
            reg = get_reg_value(state, reg_name)

            extra = {'reg_name': reg_name, 'reg': reg}
            if reg_name in eexit_untrusted_regs:
                # Above registers _should_ be tainted and point to untrusted memory.
                if not taint.is_tainted(reg):
                    logger.debug(f'{reg_name} ({reg}) is symbolic {state.solver.symbolic(reg)} and NOT tainted!')
                    Reporter().report(f'On EExit: {reg_name.upper()} register still points to trusted memory.',
                                    state, logger, abi_shortname, logging.WARNING, extra)
                    #TODO: error message is misleading: we check that the register is tainted, not that it points to untrusted memory.
                    # We could probably check that the value of rsp and rbx has been restored to the initial (attacker controlled) value?

            else:
                if taint.is_tainted(reg):
                    # An attacker tainted data register on exit is fine. This usually means that its original
                    # state was restored before exiting. One might still want to give an info here but by default we omit it.
                    # Reporter().report(f'On EEXIT: Attacker tainted {reg_name.upper()} register.',
                    #                 state, logger, abi_shortname, logging.DEBUG, extra, only_once=True)
                    pass
                elif state.solver.symbolic(reg):
                    logger.debug(f'{reg_name} ({reg}) is symbolic {state.solver.symbolic(reg)} and not attacker-tainted!')
                    Reporter().report(f'On EExit: Potentially secret-tainted {reg_name.upper()} register',
                                    state, logger, abi_shortname, logging.WARNING, extra)

        logger.debug('--- EEXIT investigation complete ---')
        abi_action(info='[abi-eexit]')

def break_abi_eexit_msp430(state):
    ip = get_reg_value(state, 'ip')
    logger.debug(f'--- Investigating EEXIT state breakpoint @ {ip:#x} ---')
    dump_regs(state, logger, log_level=logging.DEBUG)

    # r1 (sp) is cleansed auto by HW so no need to check
    for reg_name in ['sr', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
        reg = get_reg_value(state, reg_name)
        extra = {'reg_name': reg_name, 'reg': reg}
        if reg_name in ['r12', 'r13', 'r14', 'r15']:
            extra['extra info'] = f'Issue downgraded to a warning since {reg_name} register is in return value ABI registers. Disclaimer: This is a heuristic only, please double check manually!'
            lvl = logging.WARNING
        else:
            lvl = logging.CRITICAL

        if state.solver.symbolic(reg) or reg != 0:
            logger.debug(f"Symbolic or non-zero register on EEXIT: '{reg_name}'={reg}")
            Reporter().report(f'On EEXIT: Unscrubbed {reg_name.upper()} register',
                                state, logger, abi_shortname, lvl, extra)

    logger.debug('--- EEXIT investigation complete ---')
    abi_action(info='[abi-eexit]')
    