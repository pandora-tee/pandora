import binascii
import ctypes
import enum
import logging

import ui.log_format

from .common import SgxAttributes

logger = logging.getLogger(__name__)

################################################################################
# SGX SDK .note.sgxmeta structure definitions.
# --> appears mostly stable across SGX-SDK versions.
################################################################################

ENCLAVE_CSS_SIZE = 1808
ENCLAVE_DATA_SIZE = 18592

LAYOUT_GROUP_FLAG = 1 << 12


class LayoutId(enum.Enum):
    LAYOUT_ID_HEAP_MIN = 1
    LAYOUT_ID_HEAP_INIT = 2
    LAYOUT_ID_HEAP_MAX = 3
    LAYOUT_ID_TCS = 4
    LAYOUT_ID_TD = 5
    LAYOUT_ID_SSA = 6
    LAYOUT_ID_STACK_MAX = 7
    LAYOUT_ID_STACK_MIN = 8
    LAYOUT_ID_THREAD_GROUP = LAYOUT_GROUP_FLAG | 9
    LAYOUT_ID_GUARD = 10
    LAYOUT_ID_HEAP_DYN_MIN = 11
    LAYOUT_ID_HEAP_DYN_INIT = 12
    LAYOUT_ID_HEAP_DYN_MAX = 13
    LAYOUT_ID_TCS_DYN = 14
    LAYOUT_ID_TD_DYN = 15
    LAYOUT_ID_SSA_DYN = 16
    LAYOUT_ID_STACK_DYN_MAX = 17
    LAYOUT_ID_STACK_DYN_MIN = 18
    LAYOUT_ID_THREAD_GROUP_DYN = LAYOUT_GROUP_FLAG | 19
    LAYOUT_ID_RSRV_MIN = 20
    LAYOUT_ID_RSRV_INIT = 21
    LAYOUT_ID_RSRV_MAX = 22
    INCORRECT_OR_NON_STD_ID = 23


class EnclaveCss(ctypes.LittleEndianStructure):
    """
    EnclaveCSS has a flat size of 1808 bytes (static from initial SDK to at least 2.19, July 2022):
        https://github.com/intel/linux-sgx/blob/321a6580fb133a4f9d80245f18556e5bd51521d3/common/inc/internal/arch.h#L252
    typedef struct _enclave_css_t {      /* 1808 bytes */
        css_header_t    header;             /* (0) */
        css_key_t       key;                /* (128) */
        css_body_t      body;               /* (900) */
        css_buffer_t    buffer;             /* (1028) */
    } enclave_css_t;
    NOTE: Since we do not really need anything in this struct, we just keep it as a byte array.
    """

    _fields_ = [
        ("data", ctypes.c_uint8 * ENCLAVE_CSS_SIZE),
    ]


class DataDirectory(ctypes.LittleEndianStructure):
    """
    DataDirectory defines which data is contained in the large data buffer at the end of the metadata.
        https://github.com/intel/linux-sgx/blob/edfe42a517b3e4b1d81204c3cdef6da6cb35fefc/common/inc/internal/metadata.h#L97
    typedef struct _data_directory_t
    {
        uint32_t    offset;
        uint32_t    size;
    } data_directory_t;
    """

    _fields_ = [("offset", ctypes.c_uint32), ("size", ctypes.c_uint32)]

    def __repr__(self):
        return f"Data dir entry:<offset: {self.offset:#x}, size: {self.size:#x}>"


class Metadata(ctypes.LittleEndianStructure):
    """
    Python class for metadata struct, based on this struct in metadata.h:
    https://github.com/intel/linux-sgx/blob/edfe42a517b3e4b1d81204c3cdef6da6cb35fefc/common/inc/internal/metadata.h
    typedef struct _metadata_t
    {
        uint64_t            magic_num;             /* The magic number identifying the file as a signed enclave image */
        uint64_t            version;               /* The metadata version */
        uint32_t            size;                  /* The size of this structure */
        uint32_t            tcs_policy;            /* TCS management policy */
        uint32_t            ssa_frame_size;        /* The size of SSA frame in page */
        uint32_t            max_save_buffer_size;  /* Max buffer size is 2632 */
        uint32_t            desired_misc_select;
        uint32_t            tcs_min_pool;          /* TCS min pool*/
        uint64_t            enclave_size;          /* enclave virtual size */
        sgx_attributes_t    attributes;            /* XFeatureMask to be set in SECS. */
        enclave_css_t       enclave_css;           /* The enclave signature */
        data_directory_t    dirs[DIR_NUM];
        uint8_t             data[18592];
    }metadata_t;
    """

    _fields_ = [
        ("magic_num", ctypes.c_uint64),
        ("version", ctypes.c_uint64),
        ("size", ctypes.c_uint32),
        ("tcs_policy", ctypes.c_uint32),
        ("ssa_frame_size", ctypes.c_uint32),
        ("max_save_buffer_size", ctypes.c_uint32),
        ("desired_misc_select", ctypes.c_uint32),
        ("tcs_min_pool", ctypes.c_uint32),
        ("enclave_size", ctypes.c_uint64),
        ("attributes", SgxAttributes),
        ("enclave_css", EnclaveCss),
        ("dirs", DataDirectory * 2),
        ("data", ctypes.c_uint8 * ENCLAVE_DATA_SIZE),
    ]

    def __repr__(self):
        return f"Intel SGX SDK Metadata Object <Magic: {self.magic_num:#x}, Version: {self.version:#x}, Size: {self.size:#x}>"

    def __str__(self):
        partial_dict = {n: getattr(self, n) for n, _ in self._fields_ if n not in ["enclave_css", "data", "attributes", "dirs"]}
        partial_dict["dirs"] = list(self.dirs)
        return ui.log_format.format_fields(partial_dict)

    @staticmethod
    def metadata_offset_to_data_offset(full_offset):
        """
        Intel structs always assume an offset beginning from the metadata start.
        This function bridges this to our representation by calculating the number of bytes that
         prepend the data, i.e., the offset of the data array and subtracting it from the given offset.
        Since this is a static offset depending on the struct, it is implemented as
            a staticmethod (which is nicer than directly hardcoding the value)
        """
        offset = 0
        for f, t in Metadata._fields_:
            if f == "data":
                break

            offset += ctypes.sizeof(t)

        return full_offset - offset


class PatchEntry(ctypes.LittleEndianStructure):
    """
    Python class for PatchEntry that is used for patching up memory locations
    https://github.com/intel/linux-sgx/blob/edfe42a517b3e4b1d81204c3cdef6da6cb35fefc/common/inc/internal/metadata.h#L175
    typedef struct _patch_entry_t
    {
        uint64_t dst;               /* relative to enclave file base */
        uint32_t src;               /* relative to metadata base */
        uint32_t size;              /* patched size */
        uint32_t reserved[4];
    } patch_entry_t;
    """

    _fields_ = [
        ("dst", ctypes.c_uint64),
        ("src", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32 * 4),
    ]

    def __repr__(self):
        return f"PatchEntry<dst: 0x{self.dst:04x}, src: 0x{self.src:04x}, size: 0x{self.size:04x}, reserved: {hex(int(binascii.hexlify(bytearray(self.reserved))))}>"


class LayoutEntry(ctypes.LittleEndianStructure):
    """
    Python class for the layout entry struct that is used to define memory layout for a specific region
    typedef struct _layout_entry_t
    {
        uint16_t    id;             /* unique ID to identify the purpose for this entry */
        uint16_t    attributes;     /* EADD/EEXTEND/EREMOVE... */
        uint32_t    page_count;     /* map size in page. Biggest chunk = 2^32 pages = 2^44 bytes. */
        uint64_t    rva;            /* map offset, relative to enclave base */
        uint32_t    content_size;   /* if content_offset = 0, content_size is the initial data to fill the whole page. */
        uint32_t    content_offset; /* offset to the initial content, relative to metadata */
        // si_flags is uint64
        // https://github.com/intel/linux-sgx/blob/321a6580fb133a4f9d80245f18556e5bd51521d3/common/inc/internal/arch.h#L159
        si_flags_t  si_flags;       /* security info, R/W/X, SECS/TCS/REG/VA */
    } layout_entry_t;
    """

    _fields_ = [
        ("id", ctypes.c_uint16),
        ("attributes", ctypes.c_uint16),
        ("page_count", ctypes.c_uint32),
        ("rva", ctypes.c_uint64),
        ("content_size", ctypes.c_uint32),
        ("content_offset", ctypes.c_uint32),
        ("si_flags", ctypes.c_uint64),
    ]

    def get_name(self):
        id_name = "unknown"
        if self.id < LayoutId.INCORRECT_OR_NON_STD_ID.value and self.id > 0:
            lid = LayoutId(self.id)
            id_name = lid.name
        else:
            logger.critical(f"Intel SDK LayoutID does not conform to format! {self.id:#x}")

        return id_name

    def __repr__(self):
        id_name = self.get_name()
        maxname = len(max(LayoutId.__members__.keys(), key=len))
        return f"LayoutEntry<id: {id_name.ljust(maxname)}({self.id:#3x}); pages: {self.page_count:3}; rva=[{self.rva:#x}--{self.rva + 4096 * self.page_count:#x}]>"

    def __str__(self):
        return ui.log_format.format_fields(self.to_dict())

    def to_dict(self):
        fields = {n: getattr(self, n) for n, _ in self._fields_}
        fields["id"] = LayoutId(self.id).name
        return fields


class LayoutGroup(ctypes.LittleEndianStructure):
    """
    Python class for the layout group struct that is used to bundle multiple layout entries together
    https://github.com/intel/linux-sgx/blob/edfe42a517b3e4b1d81204c3cdef6da6cb35fefc/common/inc/internal/metadata.h#L167
    typedef struct _layout_group_t
    {
        uint16_t    id;             /* unique ID to identify the purpose for this entry */
        uint16_t    entry_count;    /* reversely count entry_count entries for the group loading. */
        uint32_t    load_times;     /* the repeated times of loading */
        uint64_t    load_step;      /* the group size. the entry load rva should be adjusted with the load_step */
                                    /* rva = entry.rva + group.load_step * load_times */
        uint32_t    reserved[4];
    } layout_group_t;
    """

    _fields_ = [
        ("id", ctypes.c_uint16),
        ("entry_count", ctypes.c_uint16),
        ("load_times", ctypes.c_uint32),
        ("load_step", ctypes.c_uint64),
    ]

    def __repr__(self):
        return "LayoutGroup with ID {0}".format(self.id)

    def __str__(self):
        return ui.log_format.format_fields({n: getattr(self, n) for n, _ in self._fields_})

    def to_dict(self):
        return {n: getattr(self, n) for n, _ in self._fields_}


class Layout(ctypes.Union):
    """
    layout_type is defined here:
     https://github.com/intel/linux-sgx/blob/edfe42a517b3e4b1d81204c3cdef6da6cb35fefc/common/inc/internal/metadata.h#L167
    That file also gives an example:
        layout table example
        entry0 - entry1 - entry2 - group3 (entry_count=2, load_times=3) ...
        the load sequence should be:
        entry0 - entry1 - entry2 - entry1 - entry2 - entry1 - entry2 - entry1 - entry2 ...
                                   --------------    --------------    --------------
                                   group3 1st time   group3 2nd time   group3 3rd time

    typedef union _layout_t
    {
        layout_entry_t entry;
        layout_group_t group;
    } layout_t;
    """

    _fields_ = [
        ("entry", LayoutEntry),
        ("group", LayoutGroup),
    ]

    def is_group(self):
        if self.entry.id & LAYOUT_GROUP_FLAG:
            return True
        else:
            return False

    def __repr__(self):
        if self.is_group():
            return repr(self.group)
        else:
            return repr(self.entry)

    def __str__(self):
        if self.is_group():
            return str(self.group)
        else:
            return str(self.entry)

    def to_dict(self):
        if self.is_group():
            return self.group.to_dict()
        else:
            return self.entry.to_dict()


class ElrangeConfigEntry(ctypes.LittleEndianStructure):
    """
    Struct for elrange config. Contained in data buffer
    https://github.com/intel/linux-sgx/blob/edfe42a517b3e4b1d81204c3cdef6da6cb35fefc/common/inc/internal/metadata.h#L182
    typedef struct _elrange_config_entry_t
    {
    uint64_t enclave_image_address;
    uint64_t elrange_start_address;
    uint64_t elrange_size;
    }elrange_config_entry_t;
    """

    _fields_ = [
        ("enclave_image_address", ctypes.c_uint64),
        ("elrange_start_address", ctypes.c_uint64),
        ("elrange_size", ctypes.c_uint64),
    ]

    def __str__(self):
        return ui.log_format.format_fields({n: getattr(self, n) for n, _ in self._fields_})


################################################################################
# SGX SDK global_data_t structure definitions (init by URTS and used by TRTS).
# --> appears quite _unstable_ across SGX-SDK versions!
################################################################################


class ThreadData(ctypes.LittleEndianStructure):
    """
    Struct definitions of the thread local data patch (1st patch). Not used in
    sgxmetadata and auto patched, but we add it here for pretty printing.

    https://github.com/intel/linux-sgx/blob/26c458905b72e66db7ac1feae04b43461ce1b76f/common/inc/internal/thread_data.h#L88

    typedef struct _thread_data_t
    {
        sys_word_t  self_addr;
        sys_word_t  last_sp;            /* set by urts, relative to TCS */
        sys_word_t  stack_base_addr;    /* set by urts, relative to TCS */
        sys_word_t  stack_limit_addr;   /* set by urts, relative to TCS */
        sys_word_t  first_ssa_gpr;      /* set by urts, relative to TCS */
        sys_word_t  stack_guard;        /* GCC expects start_guard at 0x14 on x86 and 0x28 on x64 */

        sys_word_t  flags;
        sys_word_t  xsave_size;         /* in bytes (se_ptrace.c needs to know its offset).*/
        sys_word_t  last_error;         /* init to be 0. Used by trts. */

    #ifdef TD_SUPPORT_MULTI_PLATFORM
        sys_word_t  m_next;             /* next TD used by trusted thread library (of type "struct _thread_data *") */
    #else
        struct _thread_data_t *m_next;
    #endif
        sys_word_t  tls_addr;           /* points to TLS pages */
        sys_word_t  tls_array;          /* points to TD.tls_addr relative to TCS */
    #ifdef TD_SUPPORT_MULTI_PLATFORM
        sys_word_t  exception_flag;     /* mark how many exceptions are being handled */
    #else
        intptr_t    exception_flag;
    #endif
        sys_word_t  cxx_thread_info[6];
        sys_word_t  stack_commit_addr;
    } thread_data_t;
    """

    _fields_versioned_ = [
        (2, 0, "self_addr", ctypes.c_uint64),
        (2, 0, "last_sp", ctypes.c_uint64),
        (2, 0, "stack_base_addr", ctypes.c_uint64),
        (2, 0, "stack_limit_addr", ctypes.c_uint64),
        (2, 0, "first_ssa_gpr", ctypes.c_uint64),
        (2, 0, "stack_guard", ctypes.c_uint64),
        (2, 1, "flags", ctypes.c_uint64),
        (2, 0, "xsave_size", ctypes.c_uint64),
        (2, 0, "last_error", ctypes.c_uint64),
        (2, 0, "m_next", ctypes.c_uint64),
        (2, 0, "tls_addr", ctypes.c_uint64),
        (2, 0, "tls_array", ctypes.c_uint64),
        (2, 0, "exception_flag", ctypes.c_uint64),
        (2, 0, "cxx_thread_info", ctypes.c_uint64 * 6),
        (2, 0, "stack_commit_addr", ctypes.c_uint64),
    ]

    def __str__(self):
        return ui.log_format.format_fields({n: getattr(self, n) for n, _ in self._fields_})

    def to_dict(self):
        dict = {n: getattr(self, n) for n, _ in self._fields_}
        dict["cxx_thread_info"] = list(self.cxx_thread_info)
        return dict


class GlobalData(ctypes.LittleEndianStructure):
    """
    https://github.com/intel/linux-sgx/blob/edfe42a517b3e4b1d81204c3cdef6da6cb35fefc/common/inc/internal/metadata.h#L69
    #define TCS_TEMPLATE_SIZE   72

    https://github.com/intel/linux-sgx/blob/1a98debccc9c8a365ddedc1c9b352cdbc216f598/common/inc/internal/global_data.h#L48
    #define LAYOUT_ENTRY_NUM 42
    typedef struct _global_data_t
    {
        sys_word_t     sdk_version;
        sys_word_t     enclave_size;            /* the size of the virtual address range that the enclave will use*/
        sys_word_t     heap_offset;
        sys_word_t     heap_size;
        sys_word_t     rsrv_offset;
        sys_word_t     rsrv_size;
        sys_word_t     rsrv_executable;
        sys_word_t     thread_policy;
        sys_word_t     tcs_max_num;
        sys_word_t     tcs_num;
        thread_data_t  td_template;
        uint8_t        tcs_template[TCS_TEMPLATE_SIZE];
        uint32_t       layout_entry_num;
        uint32_t       reserved;
        layout_t       layout_table[LAYOUT_ENTRY_NUM];
        uint64_t       enclave_image_address;   /* the base address of the enclave image */
        uint64_t       elrange_start_address;   /* the base address provided in the enclave's SECS (SECS.BASEADDR) */
        uint64_t       elrange_size;            /* the size of the enclave address range provided in the enclave's SECS (SECS.SIZE) */
    } global_data_t;
    """

    # Class should be dynamically created via method in common.py
    _fields_versioned_ = [
        (2, 9, "sdk_version", ctypes.c_uint64),
        (2, 0, "enclave_size", ctypes.c_uint64),
        (2, 0, "heap_offset", ctypes.c_uint64),
        (2, 0, "heap_size", ctypes.c_uint64),
        (2, 6, "rsrv_offset", ctypes.c_uint64),
        (2, 6, "rsrv_size", ctypes.c_uint64),
        (2, 8, "rsrv_executable", ctypes.c_uint64),
        (2, 0, "thread_policy", ctypes.c_uint64),
        (2, 8, "tcs_max_num", ctypes.c_uint64),
        (2, 17, "tcs_num", ctypes.c_uint64),
        (2, 0, "td_template", ThreadData),
        (2, 0, "tcs_template", ctypes.c_uint8 * 72),
        (2, 0, "layout_entry_num", ctypes.c_uint32),
        (2, 0, "reserved", ctypes.c_uint32),
        (2, 6, "layout_table", Layout * 42),
        (2, 0, "layout_table", Layout * 38),
        (2, 14, "enclave_image_address", ctypes.c_uint64),
        (2, 14, "elrange_start_address", ctypes.c_uint64),
        (2, 14, "elrange_size", ctypes.c_uint64),
    ]

    def __str__(self):
        fields = {n: getattr(self, n) for n, _ in self._fields_ if n not in ["reserved"] and "rsrv" not in n}
        fields["layout_table"] = list(self.layout_table)[0 : self.layout_entry_num]
        fields["td_template"] = self.td_template.to_dict()
        s = ui.log_format.format_fields(fields)

        return s

    def to_dict(self):
        dict = {n: getattr(self, n) for n, _ in self._fields_}
        return dict
