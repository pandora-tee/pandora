from sdks.AbstractSDK import AbstractSDK
import logging
from utilities.angr_helper import set_reg_value

logger = logging.getLogger(__name__)

EXPECTED_SECTION = '.ipe_seg'

class openIPESDK(AbstractSDK):
    project = None

    def __init__(self, elffile, init_state, version_str, **kwargs):
        super().__init__(elffile, init_state, version_str, **kwargs)
        self.project = init_state.project
        self.ipe_start = self.get_symbol_addr('__ipe_seg_start')
        self.ipe_end = self.get_symbol_addr('__ipe_seg_end')
        self.ipe_rx_start = self.get_symbol_addr('__ipe_rx_start')
        self.ipe_rx_end = self.get_symbol_addr('__ipe_rx_end')
        self.ipe_rw_start = self.get_symbol_addr('__ipe_rw_start')
        self.ipe_rw_end = self.get_symbol_addr('__ipe_rw_end')
        logger.info(f'Found IPE: [{self.ipe_start:#x},{self.ipe_end:#x}]')
        logger.info(f'\tr-- range: [{self.ipe_start:#x},{self.ipe_rx_start:#x}]')
        logger.info(f'\tr-x range: [{self.ipe_rx_start:#x},{self.ipe_rx_end:#x}]')
        logger.info(f'\trw- range: [{self.ipe_rw_start:#x},{self.ipe_rw_end:#x}]')

    def get_symbol_addr(self, name):
        s = self.project.loader.find_symbol(name)
        assert(s)
        return s.linked_addr

    @staticmethod
    def detect(elffile, binpath):
        if elffile.get_section_by_name(EXPECTED_SECTION) != None:
            return 'v1'
        return ''

    @staticmethod
    def get_sdk_name():
        return "openIPE"

    @staticmethod
    def get_angr_arch():
        return 'msp430'
    
    def get_base_addr(self):
        return self.ipe_start

    def get_encl_size(self):
        return self.ipe_end - self.ipe_start
    
    def init_eenter_state(self, eenter_state):
        set_reg_value(eenter_state, 'ip', self.ipe_rx_start)
        # openIPE has hardware-managed stack switching, initialized to zero
        set_reg_value(eenter_state, 'sp', 0x0)