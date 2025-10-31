import logging

import ui
from sdks.AbstractSDK import HasJSONLayout
from sdks.AbstractSGXSDK import AbstractSGXSDK
from sdks.common import Secs, SgxAttributes, Tcs, load_struct_from_memory
from utilities.helper import decode_as_json

logger = logging.getLogger(__name__)

# Keep a global var for the base address since we actually know it before initialization but it depends on the loaded json
MEMORY_DUMP_BASE_ADDRESS = -1
class EnclaveDump(AbstractSGXSDK, HasJSONLayout):

    def __init__(self, file_name, init_state, version_str, json_file=None, **kwargs):
        """
        Loading an enclave dump is slightly different from the other SDKs.
        First, our first argument is not actually an elf file. Instead, it is a file stream to the memory dump.
        Second, we require a json_file to understand the layout of the enclave dump
        """
        super().__init__(file_name, init_state, version_str, **kwargs)

        if json_file is None:
            logger.error(f'{ui.log_format.format_error("EnclaveDump SDK requires an additional json file.")} '
                         f'Give this through '
                         f'{ui.log_format.format_inline_header("--sdk-json-file")}. Aborting..')
            exit(1)

        self.enclave_layout = decode_as_json(json_file)

        """
        Parse the json and split it into the following parts:
         - SECS and SECS_PAGES
           We do not really need SECS PAGES because we only care about the value of the SECS structure, not its location.
        - TCS and TCS_PAGES
           Make this into a list of tuples [dict(tcs struct), dict(tcs page)]
        - PAGES
           All remaining pages that are not any of the above
        """
        secs = []
        secs_pages = []
        tcs = []
        tcs_pages = []
        pages = []
        for l in self.enclave_layout:
            entry_type = l['entry_type']
            if entry_type == 0:
                secs.append(l)
            elif entry_type == 1:
                tcs.append(l)
            elif entry_type == 2:
                # For pages, we check what page it is. Type PT_TCS or PT_SECS get appended to their page list respectively
                page_type = l['type']
                if page_type == 'PT_SECS':
                    secs_pages.append(l)
                elif page_type == 'PT_TCS':
                    tcs_pages.append(l)
                else:
                    # All other pages we just put into the page list
                    pages.append(l)

        assert len(secs) == 1
        secs = secs[0]

        # Create a zero-initialized SECS and fill it with the JSON captured SECS
        # from the ECREATE system call
        self.secs = Secs()
        self.secs.size = secs['size']
        self.secs.base = secs['base']
        self.secs.ssa_frame_size = secs['ssa_frame_size']
        self.secs.misc_select = secs['miscselect']
        self.secs.attributes = SgxAttributes(flags=secs['attributes'],xfrm=secs['xfrm'])
        # TODO we can also capture the other fields and write them here for completeness (eg if we convert to the SGXS format..)
        logger.debug(f'Created SECS structure:\n{str(self.secs)}')

        # Now decide on a TCS to use
        tcs = list(zip(tcs, tcs_pages))
        logger.debug(f'Found {len(tcs)} TCS structures:\n{ui.log_format.format_fields(tcs)}')

        # For now, we simply pick the first TCS. This may be changed in the future.
        tcs_index = 0

        """
        Now, we utilize the parsed data from above:
        1. Read enclave size and base addr from SECS struct
        2. Choose a TCS and get TCS address from the according Page
           Perform a double check by reading its content and comparing with the one in the dumpfile
        """

        # First, get enclave size and base addr from SECS
        self.enclave_size = secs['size']
        global MEMORY_DUMP_BASE_ADDRESS
        self.enclave_base = secs['base']
        MEMORY_DUMP_BASE_ADDRESS = self.enclave_base

        # Second, the TCS addres from base addr plus page offset
        self.tcs = tcs[tcs_index][1]['offset'] + MEMORY_DUMP_BASE_ADDRESS

        # Perform sanity check that we also have this TCS at that memory location
        tcs_mem_struct = load_struct_from_memory(self.init_state, self.tcs, Tcs)
        logger.debug(f'Decided on TCS with index {tcs_index} @{self.tcs:#x}. Loaded it from memory and will verify it now.')
        logger.debug(str(tcs_mem_struct))
        assert tcs_mem_struct.flags == tcs[tcs_index][0]['flags']
        assert tcs_mem_struct.ossa == tcs[tcs_index][0]['ssa_offset']
        assert tcs_mem_struct.cssa == tcs[tcs_index][0]['ssa_index']
        assert tcs_mem_struct.nssa == tcs[tcs_index][0]['ssa_num']
        assert tcs_mem_struct.oentry == tcs[tcs_index][0]['entry_offset']
        assert tcs_mem_struct.ofs_base == tcs[tcs_index][0]['fs_base']
        assert tcs_mem_struct.ogs_base == tcs[tcs_index][0]['gs_base']
        logger.debug('All good. TCS loaded and verified. Can proceed with enclave dump!')


        # 3. Create a list of all code pages that we have (used by the hooker)
        self.code_pages = [(p['offset'] + MEMORY_DUMP_BASE_ADDRESS, max(p['length'], p['count'])) for p in pages if 'X' in p['permissions'] and p['measured'] == 1]

        self.unmeasured_regions = []
        for p in pages:
            if p['measured'] == 0:
                my_addr = p['src'] + p['offset']
                my_size = max(p['length'], p['count'])

                # Check whether we can append this page to the regions we have on file
                found = False
                for idx, (region_addr, region_size) in enumerate(self.unmeasured_regions):
                    if region_addr + region_size == my_addr:
                        # Simply extend the region
                        self.unmeasured_regions[idx] = (region_addr, region_size + my_size)
                        found = True
                        break

                if not found:
                    self.unmeasured_regions.append((my_addr, my_size))

        """
        Note, that here we assume silently, that unmeasured memory is zero-initialized.
        The angr blob loader has an optimization that ignores zero pages during load.
        This results in our EnclaveMemoryFillerMixin to be called for unmeasured memory access, which is also
        tested in the selftest.
        """

        logger.info('EnclaveDump SDK initialized. Ready to execute!')

    @staticmethod
    def detect(elffile, binpath):
        return "MemoryDumpV1"

    @staticmethod
    def get_sdk_name():
        return 'Enclave memory dump'

    def get_encl_size(self):
        return self.enclave_size

    def get_secs(self):
        return self.secs

    @staticmethod
    def get_load_addr():
        return MEMORY_DUMP_BASE_ADDRESS

    def get_base_addr(self):
        EnclaveDump.get_load_addr()

    @staticmethod
    def get_angr_backend():
        return 'blob'

    def get_exec_ranges(self):
        return self.code_pages

    @staticmethod
    def prepare_enclave_offset(json_file):
        """
        We need to prepare the enclave offset based on the json file to read it from the SECS structure.
        """
        global MEMORY_DUMP_BASE_ADDRESS

        json_list = decode_as_json(json_file)
        for entry in json_list:
            if entry['entry_type'] == 0:
                MEMORY_DUMP_BASE_ADDRESS = entry['base']
                logger.info(f'Prepared base address for enclave based on JSON Layout. Base addr is now {MEMORY_DUMP_BASE_ADDRESS}')
                break

        if MEMORY_DUMP_BASE_ADDRESS == -1:
            logger.critical('Failed to find SECS structure and could not set base address correctly. Expect things to fail!')
