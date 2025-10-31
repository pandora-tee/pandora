import logging

from angr import BP_AFTER, BP_BEFORE, ExplorationTechnique, SimState

import ui
from explorer.enclave import buffer_entirely_inside_enclave
from explorer.taint import is_tainted
from sdks.SDKManager import SDKManager
from ui.action_manager import ActionManager
from ui.report import SYSTEM_EVENTS_REPORT_NAME, Reporter
from utilities.angr_helper import (
    get_reg_value,
    get_sym_memory_value,
    memory_is_tainted,
)

logger = logging.getLogger(__name__)


class ControlFlowTracker(ExplorationTechnique):
    """
    Tracks all active states before stepping them and makes sure we properly emulate SGX hardware behavior:
        1. terminate execution when jumping to non-exectable enclave regions; and
        2. terminate execution when jumping to memory outside the enclave (without EEXIT).

    NOTE: For Intel SGX, we can decide condition (2) here without an explicit call to the
        constraint solver, as regions outside the enclave are not supposed to be
        in the allowlist of executable regions for (1), so the check for (1) here
        implies the check for (2).
    """

    def __init__(self, init_state: SimState):
        super().__init__()

        self.init_state = init_state

    def step(self, simgr, **kwargs):
        """
        Before stepping, check all active states and compare their IP against the list of allowed IPs
        """

        wrong_jumps = []
        for s in simgr.active:
            # NOTE IP should always be concrete at this point, as per angr internals
            ip = get_reg_value(s, "ip")
            assert type(ip) is int
            # logger.debug(f'jmp to {ip:#x}')

            executable = SDKManager().addr_in_executable_range(ip)
            unmeasured_tainted = SDKManager().addr_in_unmeasured_uninitialized_page(ip, 1) and memory_is_tainted(s, ip, 1)
            do_eexit = SDKManager().is_eexit_target(ip)

            if do_eexit:
                logger.debug(f"EEXIT for jump target {ip:#x}")

                # Call EEXIT BEFORE breakpoint
                s._inspect("eexit", BP_BEFORE)

                # Mark state as eexited
                s.globals["eexit"] = True
                simgr.move(from_stash="active", to_stash="eexited", filter_func=lambda s: s.globals["eexit"] is True)

                # Lastly, call eexit breakpoint again (AFTER)
                s._inspect("eexit", BP_AFTER)
            elif not executable or unmeasured_tainted:
                wrong_jumps.append(s)
                logger.error(f"State {s.history.parent} incorrectly jumped to {ip:#x} which is not an allowed code region. Exiting this state.")
                bbl_addrs = list(s.history.bbl_addrs)
                if len(bbl_addrs) > 0:
                    ui.log_format.dump_asm(s.history.parent, logger, logging.ERROR, header_msg="Assembly code of the removed state before the jump:", use_ip=bbl_addrs[-1], angr_project=s.project)  # Pass the project of the state since history doesn't have it

                # Send this as a system event to the reporter to log it properly
                bvv_at_target = get_sym_memory_value(s, ip, SDKManager().get_max_inst_size(), with_enclave_boundaries=True)
                extra_sec = None
                if buffer_entirely_inside_enclave(s, ip, SDKManager().get_max_inst_size()):
                    extra_sec = {"Execution state info": [("Disassembly of jump target (not executed)", ui.log_format.format_asm(s, formatting=None, angr_project=s.project, use_ip=ip), "verbatim")]}
                ty = "unmeasured and uninitialized" if unmeasured_tainted else "non-executable"
                Reporter().report(
                    f"Aborted branch due to illegal jump to {ty} region",
                    s,
                    logger,
                    SYSTEM_EVENTS_REPORT_NAME,
                    severity=logging.ERROR,
                    extra_info={
                        "Jump target": hex(ip),
                        "Jump target is tainted": is_tainted(bvv_at_target),
                        f"Jump target ({SDKManager().get_max_inst_size()} bytes)": str(bvv_at_target),
                        "Executable": executable,
                        "Unmeasured and tainted": unmeasured_tainted,
                    },
                    extra_sections=extra_sec,
                )
                # Trigger a user action if requested
                ActionManager().actions["system"](info="Aborted branch due to illegal jump", state=s)

        if len(wrong_jumps) > 0:
            simgr.move(from_stash="active", to_stash="incorrect", filter_func=lambda x: x in wrong_jumps)
            logger.debug(f"Removed states {wrong_jumps}")

        simgr = simgr.step(**kwargs)
        return simgr
