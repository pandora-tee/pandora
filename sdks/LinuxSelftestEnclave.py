import logging

from sdks.AbstractSGXSDK import AbstractSGXSDK

EXPECTED_SECTION = '.tcs'
EXPECTED_POSITION = 0x0

logger = logging.getLogger(__name__)


class LinuxSelftestEnclave(AbstractSGXSDK):
    """
    The selftest enclave has its tcs at location zero.
    """

    def __init__(self, elffile, init_state, version_str, **kwargs):
        super().__init__(elffile, init_state, version_str, **kwargs)
        self.tcs = self.get_base_addr()
        self.size = init_state.project.loader.main_object.max_addr + 1 - init_state.project.loader.main_object.min_addr

        self.unmeasured_regions = []
        sec = elffile.get_section_by_name('.unmeasured')
        if sec:
            self.unmeasured_sec_addr = sec_addr = sec["sh_addr"]
            self.unmeasured_sec_size = sec_size = sec["sh_size"]
            self.unmeasured_regions.append((sec_addr, sec_size))
            # Note the `.unmeasured` section is appended as a non-allocatable
            # section at the end of the enclave image, so we have to account
            # for it by manually growing the enclave address space here.
            assert(sec_addr == self.size)
            self.size += sec_size


    def override_executable(self, addr):
        if len(self.unmeasured_regions) > 0:
            return self.unmeasured_sec_addr <= addr < self.unmeasured_sec_addr + self.unmeasured_sec_size
        else:
            return False

    @staticmethod
    def get_sdk_name():
        return 'Linux selftest enclave'

    def get_encl_size(self):
        return self.size

    def get_base_addr(self):
        return LinuxSelftestEnclave.get_load_addr()

    @staticmethod
    def get_load_addr():
        return 0x0 #0x5000

    @staticmethod
    def detect(elffile, binpath):
        sec = elffile.get_section_by_name(EXPECTED_SECTION)

        if sec and sec['sh_addr'] == EXPECTED_POSITION:
            return 'v1'

        return ''

