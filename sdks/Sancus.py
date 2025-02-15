from sdks.AbstractSDK import AbstractSDK
from utilities.angr_helper import set_reg_value
import re
import logging

logger = logging.getLogger(__name__)

EXPECTED_SECTION = r'.text.sm.*'

class SancusSDK(AbstractSDK):
    project = None

    def __init__(self, elffile, init_state, version_str, **kwargs):
        super().__init__(elffile, init_state, version_str, **kwargs)
        self.project = init_state.project
        self.enclave = SancusSDK.get_sancus_enclave(elffile)

        self.textStart = self.get_symbol_addr(f'__sm_{self.enclave}_public_start')
        self.textEnd = self.get_symbol_addr(f'__sm_{self.enclave}_public_end')
        self.dataStart = self.get_symbol_addr(f'__sm_{self.enclave}_secret_start')
        self.dataEnd = self.get_symbol_addr(f'__sm_{self.enclave}_secret_end')
        logger.info(f'Found Sancus enclave "{self.enclave}":')
        logger.info(f'\ttext range: [{self.textStart:#x},{self.textEnd:#x}[')
        logger.info(f'\tdata range: [{self.dataStart:#x},{self.dataEnd:#x}[')
    
    def get_symbol_addr(self, name):
        s = self.project.loader.find_symbol(name)
        assert(s)
        return s.linked_addr

    """
        TODO: for now just return the first enclave in case of multiple enclaves
    """
    @staticmethod
    def get_sancus_enclave(elf_file):
        pattern = re.compile(EXPECTED_SECTION)
        for section in elf_file.iter_sections():
            if pattern.search(section.name):
                logger.debug(f"Found enclave section {section.name}")
                return section.name.removeprefix('.text.sm.')
        return None

    @staticmethod
    def detect(elffile, binpath):
        if SancusSDK.get_sancus_enclave(elffile) != None:
            return 'v1'
        return ''

    @staticmethod
    def get_sdk_name():
        return "Sancus"
    
    @staticmethod
    def get_angr_arch():
        return 'msp430'
    
    def get_base_addr(self):
        #TODO make it return a pair!
        return self.textStart

    def get_encl_size(self):
        #TODO
        #return {'text': self.textSize, 'data': self.dataSize}
        return self.textEnd - self.textStart
    
    def get_enclave_range(self):
        return [(self.textStart, self.textEnd - 1), (self.dataStart, self.dataEnd - 1)]

    def get_exec_ranges(self):
        return [(self.textStart, self.textEnd - self.textStart)]

    def init_eenter_state(self, eenter_state):
        set_reg_value(eenter_state, 'ip', self.textStart)