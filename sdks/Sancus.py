import explorer
from sdks.AbstractSDK import AbstractSDK
from angr import BP_AFTER
from utilities.angr_helper import set_reg_value, get_reg_value
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
        return self.textStart
    
    def get_entry_addr(self):
        return self.textStart

    def get_encl_size(self):
        return self.textEnd - self.textStart
    
    def get_enclave_range(self):
        return [(self.textStart, self.textEnd - 1), (self.dataStart, self.dataEnd - 1)]

    def is_eexit_target(self, addr):
        # Any jumps outside of the Sancus text section result in (implicit) enclave exit
        return addr < self.textStart or addr > self.textEnd

    def get_exec_ranges(self):
        # Sancus enclaves can legally jump out, so mark only the
        # data section as strictly non-executable
        return [(0, max(0, self.dataStart - 1)), (min(self.dataEnd + 1, 2**16 - 1), 2**16)]

    def init_eenter_state(self, eenter_state):
        set_reg_value(eenter_state, 'ip', self.get_entry_addr())

        #Indicate states where the code writes to its own text section (such that these can be removed to errored stash)
        eenter_state.globals['sancus_text_range'] = (self.textStart, self.textEnd-1)
        eenter_state.inspect.b('trusted_mem_write', when=BP_AFTER, action=check_write_to_text_section)
    
"""
Function that changes the 'written_to_text_section' variable if there will be written to the 
text section of the enclave
"""
def check_write_to_text_section(state):
    addr = state.inspect.mem_write_address
    length = state.inspect.mem_write_length
    encl_range = state.globals['sancus_text_range']
    write_addr_inside_encl = explorer.enclave.buffer_touches_enclave(state, addr, length, use_enclave_range=[encl_range])
    if write_addr_inside_encl:
        logger.warning(f"Aborting due to write in Sancus text section @{get_reg_value(state, 'ip'):#x} -> {addr}")
        state.globals['enclave_fault'] = True
