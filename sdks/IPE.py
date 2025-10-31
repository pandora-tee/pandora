import logging

from sdks.AbstractSDK import AbstractSDK
from utilities.angr_helper import get_sym_reg_value, set_reg_value

logger = logging.getLogger(__name__)

IPE_SECTION = ".ipe_seg"
BOOTCODE_SECTION = ".bootcode"


class openIPESDK(AbstractSDK):
    project = None

    def __init__(self, elffile, init_state, version_str, **kwargs):
        super().__init__(elffile, init_state, version_str, **kwargs)
        self.project = init_state.project
        if version_str == "code":
            self.ipe_start = self.get_symbol_addr("__ipe_seg_start")
            self.ipe_end = self.get_symbol_addr("__ipe_seg_end")
            self.ipe_rx_start = self.get_symbol_addr("__ipe_rx_start")
            self.ipe_rx_end = self.get_symbol_addr("__ipe_rx_end")
            self.ipe_rw_start = self.get_symbol_addr("__ipe_rw_start")
            self.ipe_rw_end = self.get_symbol_addr("__ipe_rw_end")
            self.untrusted_entries = [self.get_symbol_addr("ipe_ocall_cont"), self.get_symbol_addr("untrusted_ret")]
        elif version_str == "firmware":
            self.ipe_start = self.get_symbol_addr("start_bootcode")
            self.ipe_end = self.get_symbol_addr("_bootcode_ivt_end")
            self.ipe_rx_start = self.ipe_start
            self.ipe_rx_end = self.ipe_end
            self.ipe_rw_start = self.ipe_start
            self.ipe_rw_end = self.ipe_end
            self.untrusted_entries = [0xFFFE]

        logger.info(f"Found IPE: [{self.ipe_start:#x},{self.ipe_end:#x}]")
        logger.info(f"\tr-- range: [{self.ipe_start:#x},{self.ipe_rx_start:#x}]")
        logger.info(f"\tr-x range: [{self.ipe_rx_start:#x},{self.ipe_rx_end:#x}]")
        logger.info(f"\trw- range: [{self.ipe_rw_start:#x},{self.ipe_rw_end:#x}]")

    def get_symbol_addr(self, name):
        s = self.project.loader.find_symbol(name)
        assert s
        return s.linked_addr

    @staticmethod
    def detect(elffile, binpath):
        if elffile.get_section_by_name(IPE_SECTION) is not None:
            return "code"
        elif elffile.get_section_by_name(BOOTCODE_SECTION) is not None:
            return "firmware"
        return ""

    @staticmethod
    def get_sdk_name():
        return "openIPE"

    @staticmethod
    def get_angr_arch():
        return "msp430"

    def get_base_addr(self):
        return self.ipe_start

    def get_entry_addr(self):
        return self.ipe_rx_start

    def get_encl_size(self):
        return self.ipe_end - self.ipe_start

    def get_enclave_range(self):
        return [(self.ipe_start, self.ipe_end - 1)]

    def is_eexit_target(self, addr):
        # Any jumps outside of the IPE section result in (implicit) enclave exit
        return addr < self.ipe_start or addr >= self.ipe_end

    def get_max_inst_size(self):
        # 2-byte opcode + 2*2byte extension words
        return 6

    def get_exec_ranges(self):
        # IPE enclaves can legally jump out, but compiler-generated enclaves should
        # normally only jump to the unprotected_entry symbol
        ue = [(e, e + 1) for e in self.untrusted_entries]
        return [(self.ipe_rx_start, self.ipe_rx_end - 1)] + ue

    def init_eenter_state(self, eenter_state):
        set_reg_value(eenter_state, "ip", self.ipe_rx_start)
        # openIPE has hardware-managed stack switching, initialized to zero
        set_reg_value(eenter_state, "sp", 0x0)
        # constrain r7 as we currently do not validate interrupt-service routines
        eenter_state.add_constraints(get_sym_reg_value(eenter_state, "r7") != -1)
