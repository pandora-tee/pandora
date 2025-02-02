import subprocess

class AbstractSDK:
    def __init__(self, elffile, init_state, version_str, **kwargs):
        self.init_state = init_state

    @staticmethod
    def detect(elffile, binpath):
        """
        @return Empty string if not detected, else version string.
        """
        pass

    @staticmethod
    def match_strings(binpath, sub):
        strings = subprocess.run(['strings', binpath], check=True, capture_output=True, text=True).stdout.split('\n')
        sdk_version = [ s for s in strings if sub in s ]
        assert len(sdk_version) == 1, f'More than one {sub} string detected.'
        return sdk_version[0][len(sub):]

    @staticmethod
    def get_sdk_name():
        raise 'Not implemented'

    def init_eenter_state(self, eenter_state):
        raise 'Not implemented'
    
    def get_unmeasured_pages(self):
        return []
    
    def get_encl_size(self):
        raise 'Not implemented'
    
    def get_base_addr(self):
        AbstractSDK.get_load_addr()

    @staticmethod
    def get_load_addr():
        """
        @return the base address that this SDK requests to be loaded at.
        Values < 0 are ignored and defaulted to angr
        """
        return -1 # Default: Let angr decide (i.e., skip this setting)

    @staticmethod
    def get_angr_backend():
        """
        Default backend is elf as most executables will be an elf file.
        However, enclave dumps may want to utilize the blob backend of angr.
        """
        return 'elf'

    @staticmethod
    def get_angr_arch():
        raise 'Not implemented'

    def modify_init_state(self, init_state):
        """
        Receives the init state and gets a last pass of modifying it before execution starts.
        Useful if the SDK requires to set specific registers on the init state for functionality or
          to speed up exploration.
        """
        pass

    def override_executable(self, addr):
        return False

class HasJSONLayout:
    """
    Additional base class that REQUIRES a JSON layout
    """
    def get_code_pages(self):
        """
        Returns a table of [(addr, size)] with all pages that are executable.
        """
        pass

    @staticmethod
    def prepare_enclave_offset(json_file):
        """
        Prepares the enclave offset based on the json file.
        """
        pass