import logging

from sdks.AbstractSGXSDK import AbstractSGXSDK
from sdks.open_enclave_structs import OESgxEnclaveProperties

logger = logging.getLogger(__name__)

EXPECTED_SECTION = '.oeinfo'


class OpenEnclaveSDK(AbstractSGXSDK):
    def __init__(self, elffile, init_state, version_str, **kwargs):
        super().__init__(elffile, init_state, version_str, **kwargs)

        sec = elffile.get_section_by_name(EXPECTED_SECTION)

        props = OESgxEnclaveProperties.from_buffer_copy(sec.data())

        logger.debug(str(props))
        logger.critical("I don't know what to do with OE enclaves yet. Spawning a shell... figure it out yourself.")
        import IPython
        IPython.embed()


        """
        Notes on how to set up heap,stack, and tcs pages
        
        TCS is filled with:
        
        Open questions
        
        Arguments to add_data_pages:
        what is oeimage.elf.entry_rva ?
        what is vaddr? 
        
        """

    @staticmethod
    def detect(elffile, binpath):
        """
        OpenEnclave puts a .oeinfo section into the elf file. We simply check for that.
        https://github.com/openenclave/openenclave/blob/cd72fd7069488ba6f453c8f5f47bd9fd9a6e6c0d/docs/GettingStartedDocs/IntelSDKPortingGuideLinux.md#configuration-file-formats
        """
        sec = elffile.get_section_by_name(EXPECTED_SECTION)

        if sec:  # OE .oeinfo is not a notes section so we can't do an additional check on it
            logger.debug(f'Found section {EXPECTED_SECTION}. This could be an Open Enclave SDK.')
            return 'unknown'

        return ''

    @staticmethod
    def get_sdk_name():
        return 'Open Enclave SDK'

    """
    Notes on OpenEnclave

    Layout is described here:
    https://github.com/openenclave/openenclave/blob/3fac91909f8291926182381394ec0ac2de4645e6/host/sgx/loadelf.c#L543

    TCS and other "control pages" are created here:
    https://github.com/openenclave/openenclave/blob/4cc08d3fcc32d17586b34c390905b11a4f547729/host/sgx/create.c#L223 

    oe_sgx_build_enclave
        -> oe_load_enclave_image        -- this is what angr already does for us
        -> oeimage.sgx_patch            -- we can prob skip this (relocations already done by angr)
            -> https://github.com/openenclave/openenclave/blob/3fac91909f8291926182381394ec0ac2de4645e6/host/sgx/loadelf.c
            -> TODO: understand if OE also patches global data like in Intel SDK?
                --> it seems so(!) see doc on global data + relocs etc here:
                https://github.com/openenclave/openenclave/blob/21ed5686f87814c8ec4c6ecb2e60653523a54492/enclave/core/sgx/globals.c#L93
        -> _add_data_pages              -- we need to do this
            -> _add_heap_pages
            -> _add_stack_pages
            -> _add_control_pages
    
    ---
    A lot of things also happen when creating the enclave
    https://github.com/openenclave/openenclave/blob/4cc08d3fcc32d17586b34c390905b11a4f547729/host/sgx/create.c#L888
    
    This file is the loader that loads an elf file into memory:
    https://github.com/openenclave/openenclave/blob/3fac91909f8291926182381394ec0ac2de4645e6/host/sgx/loadelf.c#L458
    
    At its core, the following struct is filled. Values are added as comments
    
    struct _oe_enclave_elf_image
{
    elf64_t elf; 
    ---> The elf file struct. Basically contains magic, data, and size
    data is just the byte blob if the file read from path below
    magic is expected to be ELF_MAGIC 0x7d7ad33b. This is NOT equal to the Elf magic .. (which would be 7f 45 4c 46 02 01 01)
    data is typed into a elf64_ehdr_t struct 

    const char* path; /* Path of the ELF binary */

    char* image_base;   /* Base of the loaded segment contents */
    --> allocated in _initialize_image_segments, page aligned
    --> zero initialized
    
    uint64_t image_rva; /* RVA of the loaded segment contents */
    size_t image_size;  /* Size of all loaded segment contents */
    --> calculated in _initialize_image_segments

    /* Cached properties of loadable segments for enclave page add */
    oe_elf_segment_t* segments;
    size_t num_segments;

    /* Relocation info for enclave initialization */
    void* reloc_data;
    size_t reloc_size;

    /* Thread-local storage .tdata section */
    uint64_t tdata_rva;
    --> sh->sh_addr; of .tdata
    uint64_t tdata_size;
    --> sh->sh_size; of .tdata
    uint64_t tdata_align;
    --> sh->sh_addralign; of .tdata

    /* Thread-local storage .tbss section */
    uint64_t tbss_size;
    --> sh->sh_size; of .tbss
    uint64_t tbss_align;
    --> sh->sh_addralign; of .tbss

    /*
     * Additional properties used for SGX enclave handling
     */

    /* RVA of the enclave entry point to set in TCS.OENTRY */
    uint64_t entry_rva;
    ---> This field is set to the e_entry field of the elf file. readelf calls this field the Entry point address 
    and it is part of the elf header

    /* RVA of the .oeinfo section to read oe_sgx_enclave_properties_t
     * during enclave load */
    uint64_t oeinfo_rva;
    ---> set to sh->sh_addr; of .oeinfo

    /* Offset to write back to the file oe_sgx_enclave_properties_t
     * during signing */
    uint64_t oeinfo_file_pos;
    ---> set to sh->sh_offset; of .oeinfo

    /* Offset of the dynamic section. Needed by submodule allocation */
    uint64_t dynamic_rva;
    ---> set to sh->sh_addr; of .dynamic
};
    
struct _oe_enclave_image
{
    oe_image_type type;

    /* Note: this can be part of a union distinguished by type if
     * other enclave binary formats are supported later */
    oe_enclave_elf_image_t elf;

    /* Pointer to the dependent image for the enclave
     * Only up to one such .so dependecy is currently allowed */
    oe_enclave_elf_image_t* submodule;

    /* Image type specific callbacks to handle enclave loading */
    oe_result_t (
        *calculate_size)(const oe_enclave_image_t* image, size_t* image_size);

    oe_result_t (*get_tls_page_count)(
        const oe_enclave_image_t* image,
        size_t* tls_page_count);

    oe_result_t (*add_pages)(
        const oe_enclave_image_t* image,
        oe_sgx_load_context_t* context,
        oe_enclave_t* enclave,
        uint64_t* vaddr);

    oe_result_t (*sgx_patch)(
        oe_enclave_image_t* image,
        size_t enclave_size,
        size_t extra_data_size);

    oe_result_t (*sgx_get_debug_modules)(
        oe_enclave_image_t* image,
        oe_enclave_t* enclave,
        oe_debug_module_t** modules);

    oe_result_t (*sgx_load_enclave_properties)(
        const oe_enclave_image_t* image,
        oe_sgx_enclave_properties_t* properties);

    oe_result_t (*sgx_update_enclave_properties)(
        const oe_enclave_image_t* image,
        const oe_sgx_enclave_properties_t* properties);

    oe_result_t (*unload)(oe_enclave_image_t* image);
};
    
    
    """
