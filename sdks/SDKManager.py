import logging
import os

from elftools.elf.elffile import ELFFile

import ui.log_format
import ui.log_format as fmt
from sdks import (
    IPE,
    EnclaveDump,
    IntelSDK,
    LinuxSelftestEnclave,
    OpenEnclaveSDK,
    Sancus,
    Scone,
)
from sdks.AbstractSDK import HasJSONLayout
from sdks.AbstractSGXSDK import AbstractSGXSDK
from sdks.SymbolManager import SymbolManager
from utilities.helper import file_stream_is_elf_file
from utilities.Singleton import Singleton

logger = logging.getLogger(__name__)

SDKS = {
    "x86_64": {
        "intel": IntelSDK.IntelSDK,
        "linux-selftest": LinuxSelftestEnclave.LinuxSelftestEnclave,
        "open-enclave": OpenEnclaveSDK.OpenEnclaveSDK,
        "scone": Scone.Scone,
    },
    "msp430": {
        "ipe": IPE.openIPESDK,
        "sancus": Sancus.SancusSDK,
    },
}
ADDITIONAL_LOADING_OPTIONS = {
    "dump": EnclaveDump.EnclaveDump,
}


class SDKManager(metaclass=Singleton):
    def __init__(self, executable_path="", requested_sdk="auto", elf_file=None, **kwargs):
        """
        SDKManager takes an elf_path and a requested_sdk to load the given binary as the SDK into angr.
        Default options exist to make the SDKManager callable as a Singleton.
        """
        # Define sdk and init_state, initialized as None
        self.sdk = None
        self.init_state = None
        self.additional_args = kwargs
        self.elf_symb_file = elf_file
        self.executable_path = executable_path
        self.target_arch = "x86_64"

        # Open the path as a stream to check for the elf magic number
        executable_stream = open(executable_path, "rb")
        if file_stream_is_elf_file(executable_stream):
            # File is elf file. open stream as ELFfile to pass to SDK detectors
            self.executable_object = ELFFile(executable_stream)

            # reduce SDK candidates based on machine architecture in ELF file
            self.target_arch = self.executable_object.header.e_machine.replace("EM_", "").lower()
            if self.target_arch not in SDKS.keys():
                logger.error(ui.log_format.format_error(f"Detected {self.target_arch}: Unsupported architecture!"))
                exit(1)

            if self.target_arch == "msp430":
                logger.debug("Detecting MSP430 binary; dynamically importing angr-platforms..")
                try:
                    from angr_platforms.msp430 import (  # noqa: F401,I001
                        arch_msp430,
                        lift_msp430,
                        simos_msp430,
                    )
                except ModuleNotFoundError:
                    logger.error(ui.log_format.format_error("Failed to dynamically import MSP430 angr platform support: did you install <https://github.com/angr/angr-platforms>?"))
                    exit(1)

                if self.additional_args["angr_log_level"]:
                    logging.getLogger("angr_platforms.msp430.instrs_msp430").setLevel(self.additional_args["angr_log_level"].upper())
        else:
            # This cannot be an ELF file: magic is missing.
            if requested_sdk in SDKManager.get_sdk_arch_names():
                logger.error(ui.log_format.format_error(f"Cannot proceed with SDK {requested_sdk}: {executable_path} is not an ELF file!"))
                exit(1)

            # If auto was requested and we are not an elf file, set it to the enclave dump to skip the detection part
            if requested_sdk == "auto":
                requested_sdk = "dump"
                self.executable_object = executable_path
            else:
                self.executable_object = executable_stream

        # Interject if the name ends on .dump and we are auto detect, then we just assume that it is an enclave dump
        if requested_sdk == "auto" and os.path.splitext(executable_path)[1] == ".dump":
            requested_sdk = "dump"
            self.executable_object = executable_path

        # Detect the utilized SDK from the binary.
        if requested_sdk == "auto":
            logger.debug(f"Starting {self.target_arch.upper()} SDK detection..")
            found = False
            self.possible_sdk = None
            self.possible_sdk_version = ""

            for name, sdk in SDKS[self.target_arch].items():
                version = sdk.detect(self.executable_object, executable_path)
                if version != "":
                    logger.info(f"Binary seems to be compiled with the {fmt.format_header(sdk.get_sdk_name())} version {fmt.format_header(version)}")
                    if found:
                        logger.critical("Multiple matches for SDKs detected!")
                    self.possible_sdk = sdk
                    self.possible_sdk_version = version
                    found = True
                else:
                    logger.debug(f"Not a {sdk.get_sdk_name()} ELF file.")

            if self.possible_sdk is None:
                logger.critical(f"I could not detect which SDK this is! Is it maybe an enclave memory dump? Then rerun with the {ui.log_format.format_inline_header('-s dump')} option.")
                exit(1)
            else:
                logger.debug("I have found my SDK.")

        # Or if specific SDK is requested, default to that
        else:
            if requested_sdk in SDKS[self.target_arch].keys():
                logger.warning(f"Forcing requested SDK {requested_sdk}. Proceed at your own risk!")
                self.possible_sdk_version = SDKS[self.target_arch][requested_sdk].detect(self.executable_object, executable_path)
                self.possible_sdk = SDKS[self.target_arch][requested_sdk]
            elif requested_sdk in ADDITIONAL_LOADING_OPTIONS.keys():
                logger.warning(f"Proceeding with SDK {requested_sdk}")
                self.possible_sdk_version = ADDITIONAL_LOADING_OPTIONS[requested_sdk].detect(self.executable_object, executable_path)
                self.possible_sdk = ADDITIONAL_LOADING_OPTIONS[requested_sdk]
            else:
                logger.error(ui.log_format.format_error(f"Unsupported SDK '{requested_sdk}' for arch '{self.target_arch}'.") + " Aborting...")
                exit(1)

        if requested_sdk == "dump" and self.additional_args["json_file"] is None:
            # Try to recover by checking if we can find a .json file of the same name as the .dump file
            file_stem = os.path.splitext(self.executable_path)[0]
            possible_json_file = file_stem + ".json"
            if os.path.isfile(possible_json_file):
                # Apparently there is a json file with that same name at that same location. Attempt to use that.
                self.additional_args["json_file"] = possible_json_file
                logger.warning(f"I did not receive an explicit --sdk-json-file with my dump, but I found {possible_json_file} that I will attempt to use now.")
            else:
                logger.error(f"{ui.log_format.format_error('EnclaveDump SDK requires an additional json file.')} Give this through {ui.log_format.format_inline_header('--sdk-json-file')}. Aborting..")
                exit(1)

        # Laslty, keep a list of unmeasured but initialized pages so that they can be combined for the filler mixin
        self.unmeasured_uninitialized_pages = None

        # and store the requested sdk / final decided sdk
        self.requested_sdk = requested_sdk

    def initialize_sdk(self, init_state):
        """
        Initialize a new instance of the previously detected SDK, give elffile and init state
        """
        self.init_state = init_state
        logger.debug(f"Initializing SDK as {self.possible_sdk.get_sdk_name()} in version {self.possible_sdk_version}")
        self.sdk = self.possible_sdk(self.executable_object, self.init_state, self.possible_sdk_version, **self.additional_args)

        if issubclass(self.sdk.__class__, AbstractSGXSDK):
            # for debugging, print tcs
            tcs_struct = self.sdk.get_tcs_struct(init_state)
            logger.debug(f"TCS at {self.sdk.get_tcs():#x} is:\n{str(tcs_struct)}")

            # for debugging, print any unmeasured areas
            for region_addr, region_size in self.get_measured_page_information():
                # SGX unmeasured areas have to be a multiple of the page size
                assert (region_size % 4096) == 0
                logger.debug(f"Detected unmeasured area: {region_addr:#x} ({int(region_size / 4096)} pages)." + " Initial reads from that region will be symbolized.")

        # Initialize the SymbolManager that will rely either on the elf file or on the SDK-specific symbol dict

        # If we decided on the dump SDK and elf_file is none, do a double check if maybe
        if self.requested_sdk == "dump" and self.elf_symb_file is None:
            file_stem = os.path.splitext(self.executable_path)[0]
            possible_elf_file = file_stem + ".so"
            if os.path.isfile(possible_elf_file):
                # Apparently there is a json file with that same name at that same location. Attempt to use that.
                self.elf_symb_file = possible_elf_file
                logger.warning(f"I did not receive an explicit --sdk-elf-file with my dump, but I found {self.elf_symb_file} that I will attempt to use now.")

        SymbolManager(init_state=init_state, elf_file=self.elf_symb_file, exec_path=self.executable_path, base_addr=self.get_base_addr(), sdk_name=self.get_sdk_name())

    def prepare_init_state(self, init_state):
        """
        Called after explorer prepared the eenter but before exploration starts.
        Useful for SDKs that need to modify the initial state.
        """
        self.sdk.modify_init_state(init_state)

    def __get_sdk_class(self):
        """
        Returns either the initialized SDK or the possible sdk base class if one was detected.
        """
        if self.sdk is not None:
            return self.sdk
        else:
            return self.possible_sdk

    def get_secs(self):
        if self.sdk is not None:
            return self.sdk.get_secs()
        else:
            raise "SDK not initialized yet."

    def get_entry_addr(self):
        if self.sdk is not None:
            return self.sdk.get_entry_addr()
        else:
            raise "SDK not initialized yet."

    def get_sdk_name(self):
        target_sdk = self.__get_sdk_class()
        if target_sdk is not None:
            return self.sdk.get_sdk_name()
        else:
            raise RuntimeError("SDK not initialized yet.")

    def get_encl_size(self):
        if self.sdk is not None:
            return self.sdk.get_encl_size()
        else:
            raise RuntimeError("SDK not initialized yet.")

    def get_max_inst_size(self):
        if self.sdk is not None:
            return self.sdk.get_max_inst_size()
        else:
            raise RuntimeError("SDK not initialized yet.")

    def get_base_addr(self):
        if self.sdk is not None:
            base_addr = self.sdk.get_base_addr()
            if base_addr == -1:
                if self.init_state is None:
                    # We do not have an init state yet. There may be the option that we have an SDK that
                    #  has a JSON Layout and may want to set the base addr before it exists.
                    if issubclass(self.sdk, HasJSONLayout) and self.additional_args["json_file"] is not None:
                        self.sdk.prepare_enclave_offset(self.additional_args["json_file"])
                        # After this, call get_base_addr again
                        base_addr = self.sdk.get_base_addr()
                else:
                    # We actually have an init state already. Use that:
                    return self.init_state.project.loader.main_object.min_addr
            return base_addr

        raise RuntimeError("SDK not initialized yet.")

    def get_enclave_range(self):
        if self.sdk is not None:
            return self.sdk.get_enclave_range()
        else:
            raise RuntimeError("SDK not initialized yet.")

    def get_load_addr(self):
        # MSP430 enclaves span a subpart of a larger static binary of the whole program memory
        # that does _not_ need to be relocated
        # SGX enclaves are shipped as relocatable shared libraries
        target_sdk = self.__get_sdk_class()
        if target_sdk is not None:
            return target_sdk.get_load_addr()
        else:
            raise RuntimeError("SDK not initialized yet.")

    def init_eenter_state(self, eenter_state):
        if self.sdk is not None:
            return self.sdk.init_eenter_state(eenter_state)
        else:
            raise RuntimeError("SDK not initialized yet.")

    def get_angr_backend(self):
        target_sdk = self.__get_sdk_class()
        if target_sdk is None:
            raise RuntimeError("SDK not initialized yet.")
        else:
            return target_sdk.get_angr_backend()

    def get_angr_arch(self):
        target_sdk = self.__get_sdk_class()
        if target_sdk is None:
            raise RuntimeError("SDK not initialized yet.")
        else:
            return target_sdk.get_angr_arch()

    @staticmethod
    def get_sdk_arch_names():
        return [sdk for arch, sdks in SDKS.items() for sdk in sdks.keys()]

    @staticmethod
    def get_sdk_names():
        """
        Returns a list of all SDK short names
        """
        return SDKManager.get_sdk_arch_names() + list(ADDITIONAL_LOADING_OPTIONS.keys())

    def get_exec_ranges(self):
        return self.sdk.get_exec_ranges()

    def get_measured_page_information(self):
        return self.sdk.get_unmeasured_pages()

    def get_unmeasured_uninitialized_pages(self):
        """
        If the SDK supports this information, return that. Otherwise, return an empty list.
        """
        if not self.unmeasured_uninitialized_pages:
            self.unmeasured_uninitialized_pages = self.get_measured_page_information()
        return self.unmeasured_uninitialized_pages

    def initialize_unmeasured_page(self, page_addr, page_size):
        if not self.unmeasured_uninitialized_pages:
            self.unmeasured_uninitialized_pages = self.get_measured_page_information()

        for idx, (unmeasured_addr, unmeasured_size) in enumerate(self.unmeasured_uninitialized_pages):
            if page_addr == unmeasured_addr:
                if page_size == unmeasured_size:
                    # Remove this page from the list
                    self.unmeasured_uninitialized_pages.pop(idx)
                else:
                    # size differs: split it up
                    self.unmeasured_uninitialized_pages[idx] = (page_addr + page_size, unmeasured_size - page_size)
            else:
                if page_addr < unmeasured_addr < page_addr + page_size:
                    # we have to split up the section
                    # 1) current region now stops at the initialized part
                    self.unmeasured_uninitialized_pages[idx] = (page_addr, unmeasured_addr - page_addr)
                    # 2) new uninitialized region starts after page_addr + size
                    new_size = (page_addr + page_size) - (unmeasured_addr + unmeasured_size)
                    if new_size:
                        self.unmeasured_uninitialized_pages.append((unmeasured_addr + unmeasured_size, new_size))

    def addr_in_unmeasured_uninitialized_page(self, addr, size):
        for unmeasured_addr, unmeasured_size in self.get_unmeasured_uninitialized_pages():
            if unmeasured_addr <= addr < unmeasured_addr + unmeasured_size:
                # addr lies in an unmeasured page. Do a sanity check whether it reaches out of an unmeasured area
                if addr + size > unmeasured_addr + unmeasured_size:
                    logger.warning("Read from unmeasured area but reaching into next area. I probably handle this incorrectly.")
                return True

        return False

    def is_eexit_target(self, addr):
        return self.sdk.is_eexit_target(addr)

    def addr_in_executable_range(self, addr):
        """
        Returns a bool whether the given concrete IP is within an allowed executable section.
        If exec_ranges is set, relies on that information. Otherwise asks the angr project to resolve this.
        """
        exec_ranges = self.get_exec_ranges()

        if exec_ranges is not None:
            return any(exec_addr <= addr < exec_addr + exec_size for (exec_addr, exec_size) in exec_ranges)

        else:
            section = self.init_state.project.loader.main_object.sections.find_region_containing(addr)
            if section is not None and section.is_executable:
                return True
            else:
                # allow the SDK to have the last word (to support unmeasured
                # executable page that are added to the ELF file after loading)
                return self.sdk.override_executable(addr)
