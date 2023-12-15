import subprocess
import ctypes
from sdks.common import Secs

class AbstractSDK:
    def __init__(self, elffile, init_state, version_str, **kwargs):
        self.tcs = None  # to be set by subclass
        self.init_state = init_state
        self.unmeasured_regions = []

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

    def get_tcs(self):
        """
        Returns TCS as the address in memory where the TCS is stored.
        """
        return self.tcs
    
    def get_secs(self):
        """
        Returns the SGX Enclave Control Structure (SECS) for this enclave.

        TODO: This is now only implemented for EnclaveDump SDK. Later we can refactor this to be properly used for all SDKs and give sane defaults and replace get_base_address etc.
        """
        # Create an empty, zero-initialized SECS structure
        secs = Secs()
        secs.size = self.get_encl_size()
        secs.base = self.get_base_addr()
        
        # Set INIT on; DEBUG off; 64bit on; rest off
        secs.attributes.flags = 0b101
        # Set XFRM according to a sane default (according to test system)
        secs.attributes.xfrm = 231

        # Unless SDK subclasses override this, we assume a default SSA framesize of 1 page
        secs.ssa_frame_size = 1
        
        return secs

    def get_unmeasured_pages(self):
        return self.unmeasured_regions

    @staticmethod
    def get_sdk_name():
        raise 'Not implemented'

    def get_encl_size(self):
        raise 'Not implemented'

    @staticmethod
    def get_base_addr():
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
