import binascii
import ctypes
import logging

import archinfo
import elftools.elf.sections

import ui
from sdks.AbstractSDK import AbstractSDK
from sdks.common import write_struct_to_memory, load_struct_from_memory, Tcs, create_versioned_struct
from sdks.intel_linux_sgx_structs import Metadata, PatchEntry, Layout, DataDirectory, ElrangeConfigEntry, \
    LayoutGroup, LayoutId, GlobalData

logger = logging.getLogger(__name__)

EXPECTED_SECTION = '.note.sgxmeta'
EXPECTED_MAGIC = '4c0e5d639402a886'
EXPECTED_NAME = 'sgx_metadata'

# Intel forgot to Pad the sgx_metadata name to a 4 byte alignment.
# This results in all normal tools to ignore the first 3 bytes of the magic
# We hack around this by blindly appending this to the data read out by pyelftools.
UNPADDED_MAGIC = '4c0e5d'
UNPADDED_MAGIC_LEN = 3


class IntelSDK(AbstractSDK):
    def __init__(self, elffile, init_state, version_str, **kwargs):
        super().__init__(elffile, init_state, version_str, **kwargs)
        self.init_state = init_state

        versions = version_str.split('.')
        self.version_major = int(versions[0])
        self.version_minor = int(versions[1])

        notes_sec_list = list(elffile.get_section_by_name(EXPECTED_SECTION).iter_notes())
        assert len(notes_sec_list) == 1
        notes_sec = notes_sec_list[0]
        assert notes_sec['n_name'] == EXPECTED_NAME

        # NOTE: Intel forgot to 4-byte align the sgx_metadata\0 name in the section header field.
        # This is unpatched since 2019 https://github.com/intel/linux-sgx/issues/360
        # This results in tools like Pyelftools that adhere to standards, to ignore the first 3 byte of the magic.
        # Here, we first check whether the descdata section starts with the expected first 3 bytes and if
        #   it does not, we blindly append that to the start of the byte blob.
        if notes_sec['n_descdata'][0:UNPADDED_MAGIC_LEN] != bytes.fromhex(UNPADDED_MAGIC):
            notes_sec['n_descdata'] = bytes.fromhex(UNPADDED_MAGIC) + notes_sec['n_descdata']
            # To complete this hack, we delete as many bytes as we added from the end of the buffer.
            # Since the buffer is way larger than needed, it should already be padded with
            #   lots of zeros at the end, so should be no danger in deleting them
            assert notes_sec['n_descdata'][-3:] == b'\00\00\00'
            notes_sec['n_descdata'] = notes_sec['n_descdata'][:-3]

        assert ctypes.sizeof(Metadata) == len(
            notes_sec["n_descdata"]), ".note.sgxmeta section does not have expected size."

        self.metadata = Metadata.from_buffer_copy(notes_sec['n_descdata'])
        assert self.metadata.magic_num == int.from_bytes(bytes.fromhex(EXPECTED_MAGIC), "little", signed=False)

        logger.debug(f'Intel SGX Metadata: \n{str(self.metadata)}')

        # Now, we parse the patches and layouts.
        # We can use the python class to just parse all objects
        def _parse_dir_data(data, struct_class, size):
            """
            Inner method to parse the expected class from data up until size is reached
                    (size should be a multiple of the expected class size).
            """
            struct_size = ctypes.sizeof(struct_class)
            assert size % struct_size == 0, \
                f'{str(struct_class)}: Wanted size {size} is not a multiple of struct size {struct_size}'
            struct_instances_list = []
            for i in range(0, size, struct_size):
                struct_instances_list.append(struct_class.from_buffer_copy(data[i: i + struct_size]))
            return struct_instances_list

        # Start by parsing the patch table (index 0)
        # TODO: Shorten and put more in inner function
        patch_size = self.metadata.dirs[0].size
        # The patch offset is given as offset from section header start
        # Thus, we need to subtract the offset of the data section itself as we use it directly here
        patch_offset = Metadata.metadata_offset_to_data_offset(self.metadata.dirs[0].offset)
        self.patches = _parse_dir_data(
            bytearray(self.metadata.data[patch_offset: patch_offset + patch_size]),
            PatchEntry,
            patch_size
        )
        logger.debug(f'Metadata patches:\n{ui.log_format.format_fields(self.patches)}')

        # Patch 0 is always the global_data_t. We print it here to help debugging.
        p0 = self.patches[0]
        src_offset = Metadata.metadata_offset_to_data_offset(p0.src)
        gd = create_versioned_struct(GlobalData, self.version_major, self.version_minor)
        gd = gd.from_buffer_copy(bytearray(self.metadata.data[src_offset: src_offset + p0.size]))
        logger.debug(f'Patch 0: Global data (sizeof={ctypes.sizeof(gd)}):\n{str(gd)}')
        assert ctypes.sizeof(gd) == p0.size, 'global_data_t size does not match patch0 size'

        # Do the same with layouts
        layout_size = self.metadata.dirs[1].size
        # Layout offset same as patch offset above
        layout_offset = Metadata.metadata_offset_to_data_offset(self.metadata.dirs[1].offset)
        self.layouts = _parse_dir_data(
            bytearray(self.metadata.data[layout_offset:layout_offset + layout_size]),
            Layout,
            layout_size
        )
        logger.debug(f'Metadata layouts:\n{ui.log_format.format_fields([k.to_dict() for k in self.layouts])}')

        # Next, we want to read the elrange config. This is hardcoded to be the first data contained in the data buffer
        # https://github.com/intel/linux-sgx/blob/321a6580fb133a4f9d80245f18556e5bd51521d3/sdk/sign_tool/SignTool/manage_metadata.cpp#L695
        # Thus, we first parse a data dir struct from the beginning of data and use that to get the elrange config
        dir = DataDirectory.from_buffer_copy(bytearray(self.metadata.data[0:ctypes.sizeof(DataDirectory)]))
        config_offset = Metadata.metadata_offset_to_data_offset(dir.offset)
        # TODO: We always seem to have a zero size and a negative offset for our binary. so when is this used? Figure it out...
        if dir.size > 0 and config_offset > 0:
            # TODO: Always skipped for our code so far
            print(f'offset is {config_offset}, wanted is {dir.offset}, size {dir.size}')
            self.elrange_config = ElrangeConfigEntry.from_buffer_copy(
                bytearray(self.metadata.data[config_offset: config_offset + dir.size])
            )
            logger.debug(f'Metadata elrange config: {str(self.elrange_config)}')
        else:
            self.elrange_config = None
            logger.debug('ElrangeConfigEntry does not exist.')

        # For now, we do not support multiple SSAs or threads. This makes it easier to implement the layout as
        #   can ignore the gorups for now. Thus, assert here that we have no groups in the layout
        layout_groups = [l for l in self.layouts if type(l) is LayoutGroup]
        assert len(layout_groups) == 0, 'Intel SDK plugin only supports a single thread per enclave as of now.'

        # For now, we do not support multiple SSAs or threads. This makes it easier to implement the layout as
        #   can ignore the gorups for now. Thus, assert here that we have no groups in the layout
        dynamic_layouts = [l for l in self.layouts if l.entry.id > LayoutId.LAYOUT_ID_GUARD.value]
        assert len(dynamic_layouts) == 0, 'Intel SDK plugin only supports static layouts as of now, no dynamic layouts.'

        # Prepare address of tcs, will be filled by setup.
        self.tcs = 0

        # Now do state specific setup. This is split off since it works on the initialized state and everything
        # we did so far has been independent of angr.
        self.setup(init_state)

    def setup(self, init_state):
        # With the initialization behind us, we can start on applying the patches and layouts.

        # Get enclave base via mapped base of the main object (the angr way)
        # Also possible: project.loader.find_symbol("__ImageBase").rebased_addr
        enclave_file_base = init_state.project.loader.main_object.mapped_base

        # Loop through patches and apply them all
        for p in self.patches:
            mem_dst = enclave_file_base + p.dst
            data_offset = Metadata.metadata_offset_to_data_offset(p.src)
            src_slice = bytes(bytearray(self.metadata.data[data_offset: data_offset + p.size]))
            logger.debug(f'Patching memory location {hex(mem_dst)} '
                         f'of size {hex(p.size)} '
                         # f'to be {binascii.hexlify(src_slice)}'
                         )
            init_state.memory.store(mem_dst, init_state.solver.BVV(src_slice), with_enclave_boundaries=False)

        # Now do the same with all layouts
        PAGE_SIZE = 0x1000
        # Init an empty page and a guard page.
        # For now a guard page is just treated as an empty page but we might want to treat them different later
        empty_page = init_state.solver.BVV(b'\00' * PAGE_SIZE)
        # Loop over layouts and apply those that are relevant
        # NOTE: As asserted above, all layouts are assumed to be entries and no groups are supported.
        for l in self.layouts:
            # We ignore guard pages for now.
            if l.entry.id == LayoutId.LAYOUT_ID_GUARD.value:
                logger.debug('Skipping guard page.')
                continue

            # Layout is based on content_offset. If it is 0, the whole page is set to the value defined by content_size
            # I.e., everything except for tcs is not copied from memory but set to a fixed value
            # (usually 0 and 0xcc for stack)
            if l.entry.content_offset == 0:
                # Just overwrite this memory based on static content_size value
                content_page = empty_page
                if l.entry.content_size != 0:
                    # We have content to write into the page and can't use the empty page.
                    # Create a new BVV page for this
                    content_amount = int(PAGE_SIZE / 4)  # content_size is uint32 = 4 byte
                    content_size_bytes = l.entry.content_size.to_bytes(4, "little")
                    content_page = init_state.solver.BVV(content_size_bytes * content_amount)

                # We just want to add the page. Do this as often as page_count demands
                logger.debug(f'Fixing layout {l.entry.get_name()}: Adding {l.entry.page_count} pages '
                             f'at {hex(l.entry.rva)} (rebased={hex(l.entry.rva + enclave_file_base)}) '
                             f'with content {hex(l.entry.content_size)}')
                for i in range(0, l.entry.page_count):
                    init_state.memory.store(
                        enclave_file_base + l.entry.rva + (i * PAGE_SIZE),
                        content_page,
                        endness=archinfo.Endness.LE,
                        with_enclave_boundaries=False
                    )
            # Alternatively, content_offset could have a value. Then we copy from metadata to the destination.
            else:
                assert l.entry.page_count == 1, \
                    "Copying memory for layout but more than one page requested? Unknown feature. Aborting."
                metadata_offset = self.metadata.metadata_offset_to_data_offset(l.entry.content_offset)
                mem_slice = init_state.solver.BVV(bytes(bytearray(
                    self.metadata.data[metadata_offset: metadata_offset + l.entry.content_size]
                )))
                init_state.memory.store(enclave_file_base + l.entry.rva, mem_slice, with_enclave_boundaries=False)
                logger.debug(f'Fixing layout {l.entry.get_name()}: Copying {hex(l.entry.content_size)} bytes '
                             f'to {hex(l.entry.rva)} (rebased={hex(l.entry.rva + enclave_file_base)}).')

                # logger.debug(f'Copied bytes source: {mem_slice}')
                # logger.debug(f'Copied bytes dest @{hex(enclave_file_base + l.entry.rva)} after: '
                #                   f'{init_state.memory.load(enclave_file_base + l.entry.rva, ctypes.sizeof(Tcs))}')

            # If this layout is the TCS, remember its address
            if l.entry.id == LayoutId.LAYOUT_ID_TCS.value:
                tcs = l.entry.rva + enclave_file_base
                logger.debug(f'Found TCS @{hex(tcs)}')

                # Intel SDK sgx_sign tool produces a patch for TCS
                # initialization with addresses that are relative to the TCS
                # base address. But the SGX EENTER hardware expects addresses
                # that are relative to the enclave base address. The untrusted
                # enclave load process, hence, still adds the (relative) TCS
                # base address. We still need to do this explicitly here.
                # See https://github.com/intel/linux-sgx/blob/26c458905b72e66db7ac1feae04b43461ce1b76f/psw/urts/loader.cpp#L403
                tcs_struct = load_struct_from_memory(init_state, tcs, Tcs)
                logger.debug('Relocating TCS ossa/ofs_base/ogs_base fields relative to enclave base.')
                tcs_struct.ossa += l.entry.rva
                tcs_struct.ofs_base += l.entry.rva
                tcs_struct.ogs_base += l.entry.rva
                write_struct_to_memory(init_state, tcs, tcs_struct)

        assert tcs != 0, 'TCS could not be read from layouts. Aborting!'
        self.tcs = tcs

        gd_struct = create_versioned_struct(GlobalData, self.version_major, self.version_minor)
        my_gd = load_struct_from_memory(init_state, enclave_file_base + 0xf0c0, gd_struct)
        logger.debug(f'Global data before eenter is (sizeof={hex(ctypes.sizeof(my_gd))}):\n{str(my_gd)}')

    @staticmethod
    def get_sdk_name():
        return 'Intel SGX SDK'

    def get_sdk_version(self):
        return f'{self.version_major}.{self.version_minor}'

    def get_encl_size(self):
        return self.metadata.enclave_size

    @staticmethod
    def detect(elffile, binpath):
        sec = elffile.get_section_by_name(EXPECTED_SECTION)

        if not sec or not type(sec) == elftools.elf.sections.NoteSection:
            return ''

        logger.debug(f'Found section {EXPECTED_SECTION}. This could be an Intel SDK.')

        # We have an elftools NoteSection. Get its contents (sgx should only have a single contained notes data)
        notes_sec_list = list(sec.iter_notes())
        if len(notes_sec_list) != 1:
            logger.debug("More than one notes element in expected section. Can't be Intel sdk.")
            logger.debug(f'Instead, notes section has length {len(notes_sec_list)} and is this: {notes_sec_list}')
            return ''
        notes_sec = notes_sec_list[0]

        # Check for the notes name
        if notes_sec['n_name'] != EXPECTED_NAME:
            logger.debug("Note section name is not as expected. Can't be Intel SDK!")
            return ''

        # Lastly, check for the magic at the start of the data.
        # NOTE: Intel forgot to 4-byte align the sgx_metadata\0 name in the section header field.
        # This is unpatched since 2019 https://github.com/intel/linux-sgx/issues/360
        # This results in tools like Pyelftools that adhere to standards, to ignore the first 3 byte of the magic.
        # Here, we first check whether the descdata section starts with the expected first 3 bytes and if
        #   it does not, we blindly append that to the start of the byte blob.
        if notes_sec['n_descdata'][0:UNPADDED_MAGIC_LEN] != bytes.fromhex(UNPADDED_MAGIC):
            notes_sec['n_descdata'] = bytes.fromhex(UNPADDED_MAGIC) + notes_sec['n_descdata']

        possible_magic = notes_sec['n_descdata'][0:ctypes.sizeof(ctypes.c_uint64)]
        if possible_magic != bytes.fromhex(EXPECTED_MAGIC):
            logger.debug('We have a section with the right name but it does not contain the magic! Not Intel SDK.')
            logger.debug(f'Instead, the start of the section is {binascii.hexlify(possible_magic)} '
                         f'but I expected {binascii.hexlify(bytes.fromhex(EXPECTED_MAGIC))}.')
            logger.debug('Start of data section in note section is: '
                         f"{binascii.hexlify(notes_sec['n_descdata'][0:20])}")
            logger.debug('The note section headers are: '
                         f'{str({n: v for n, v in notes_sec.items() if n not in ["n_descdata", "n_desc"]})}')
            logger.debug('At the same time, byte buffer of the section starts with'
                         f'{binascii.hexlify(sec.data()[0:100])}')
            return ''

        # All tests passed, seems to be a proper Intel SDK!
        return AbstractSDK.match_strings(binpath, 'SGX_TRTS_VERSION_')

# https://github.com/intel/linux-sgx/blob/edfe42a517b3e4b1d81204c3cdef6da6cb35fefc/common/inc/internal/metadata.h
# https://github.com/intel/linux-sgx/blob/321a6580fb133a4f9d80245f18556e5bd51521d3/sdk/sign_tool/SignTool/manage_metadata.cpp

# https://github.com/openenclave/openenclave/blob/cd72fd7069488ba6f453c8f5f47bd9fd9a6e6c0d/docs/GettingStartedDocs/IntelSDKPortingGuideLinux.md#configuration-file-formats

# https://github.com/fortanix/rust-sgx/blob/3fea4337f774fe9563a62352ce62d3cad7af746d/intel-sgx/sgxs-tools/src/bin/isgx-pe2sgx.rs#L446
# https://github.com/fortanix/rust-sgx/blob/dbe1430367b3fde78ccb6209cfd49ed0fdc2d707/doc/WINTEL-SGX-ABI.md

# https://docs.angr.io/core-concepts/loading
# https://api.angr.io/cle.html

# TODO we probably want to subclass the CLE loader with SGX-SDK specific ones to build the enclave address space?
# https://github.com/angr/cle


# https://github.com/intel/linux-sgx/blob/1a98debccc9c8a365ddedc1c9b352cdbc216f598/psw/urts/parser/elfparser.cpp
# https://github.com/intel/linux-sgx/blob/1a98debccc9c8a365ddedc1c9b352cdbc216f598/psw/urts/enclave_creator_hw_com.cpp


# https://github.com/intel/linux-sgx/blob/1a98debccc9c8a365ddedc1c9b352cdbc216f598/psw/urts/loader.cpp


# g_global_data is initialized/patched as part of sgxmeta here:
# https://github.com/intel/linux-sgx/blob/321a6580fb133a4f9d80245f18556e5bd51521d3/sdk/sign_tool/SignTool/manage_metadata.cpp#L1052
# and actually patched upon load here:
# https://github.com/intel/linux-sgx/blob/1a98debccc9c8a365ddedc1c9b352cdbc216f598/psw/urts/loader.cpp#L654
# global data template build here:
# https://github.com/intel/linux-sgx/blob/321a6580fb133a4f9d80245f18556e5bd51521d3/sdk/sign_tool/SignTool/manage_metadata.cpp#L1200
# https://github.com/intel/linux-sgx/blob/1a98debccc9c8a365ddedc1c9b352cdbc216f598/psw/urts/parser/update_global_data.hxx


# relocations
# https://en.wikipedia.org/wiki/Position-independent_code
# https://github.com/fortanix/rust-sgx/issues/202
# https://github.com/rust-lang/rust/blob/master/library/std/src/sys/sgx/abi/reloc.rs
# https://refspecs.linuxbase.org/elf/gabi4+/ch4.reloc.html
# https://stackoverflow.com/questions/19593883/understanding-the-relocation-table-output-from-readelf

# gs local thread_data
#https://github.com/intel/linux-sgx/blob/26c458905b72e66db7ac1feae04b43461ce1b76f/common/inc/internal/thread_data.h#L88
# https://github.com/intel/linux-sgx/blob/1a98debccc9c8a365ddedc1c9b352cdbc216f598/psw/urts/parser/update_global_data.hxx#L63
# https://github.com/intel/linux-sgx/blob/321a6580fb133a4f9d80245f18556e5bd51521d3/sdk/sign_tool/SignTool/manage_metadata.cpp#L1235V

# Global data is written by the sign tool here:
# https://github.com/intel/linux-sgx/blob/1a98debccc9c8a365ddedc1c9b352cdbc216f598/psw/urts/parser/update_global_data.hxx#L119
# To get debug output from the sign tool, compile it with `make all DEBUG=1` and simply sign an enclave
# For example one of the test binaries in this repo and a random test.pem key could run
# ./sgx_sign sign -enclave encl-nop-sdk2.16.so -out enclave.out -key test.pem -resign
