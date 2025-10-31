import ctypes
import enum

import ui.log_format

# https://github.com/openenclave/openenclave/blob/613f6a4a7f82a37bbe5c95b1d978a090e0898335/include/openenclave/bits/defs.h#L241
OE_PAGE_SIZE = 0x1000

"""
https://github.com/openenclave/openenclave/blob/613f6a4a7f82a37bbe5c95b1d978a090e0898335/include/openenclave/bits/defs.h#L157
/* The maxiumum value for a four-byte enum tag */
#define OE_ENUM_MAX 0xffffffff
"""
OE_ENUM_MAX = 0xFFFFFFFF


class OEEnclaveType(enum.Enum):
    """
    https://github.com/openenclave/openenclave/blob/ebd3727cfd711aa157ae215caafae7f5f3051ecb/include/openenclave/bits/types.h#L115
    /**
     * This enumeration defines values for the type parameter
     * passed to **oe_create_enclave()**.
     */
    typedef enum _oe_enclave_type
    {
        /**
         * OE_ENCLAVE_TYPE_AUTO will pick the type
         * based on the target platform that is being built, such that x64 binaries
         * will use SGX.
         */
        OE_ENCLAVE_TYPE_AUTO = 1,
        /**
         * OE_ENCLAVE_TYPE_SGX will force the platform to use SGX, but any platform
         * other than x64 will not support this and will generate errors.
         */
        OE_ENCLAVE_TYPE_SGX = 2,
        /**
         * OE_ENCLAVE_TYPE_OPTEE will force the platform to use OP-TEE, but any
         * platform other than one that implements ARM TrustZone with OP-TEE as its
         * secure kernel will not support this and will generate errors.
         */
        OE_ENCLAVE_TYPE_OPTEE = 3,
        /**
         * Unused
         */
        __OE_ENCLAVE_TYPE_MAX = OE_ENUM_MAX,
    } oe_enclave_type_t;
    """

    OE_ENCLAVE_TYPE_AUTO = (1,)
    OE_ENCLAVE_TYPE_SGX = (2,)
    OE_ENCLAVE_TYPE_OPTEE = (3,)
    __OE_ENCLAVE_TYPE_MAX = (OE_ENUM_MAX,)


class OEEnclaveSizeSettings(ctypes.LittleEndianStructure):
    """
    https://github.com/openenclave/openenclave/blob/8f28b2520165be167b4f9d2dba0eab705272b083/include/openenclave/bits/properties.h#L29
    typedef struct _oe_enclave_size_settings
    {
        uint64_t num_heap_pages;
        uint64_t num_stack_pages;
        uint64_t num_tcs;
    } oe_enclave_size_settings_t;
    """

    _fields_ = [
        ("num_heap_pages", ctypes.c_uint64),
        ("num_stack_pages", ctypes.c_uint64),
        ("num_tcs", ctypes.c_uint64),
    ]

    def __repr__(self):
        return "<" + str({n: getattr(self, n) for (n, _) in self._fields_}) + ">"


class OEEnclavePropertiesHeader(ctypes.LittleEndianStructure):
    """
    OE properties base type
        https://github.com/openenclave/openenclave/blob/8f28b2520165be167b4f9d2dba0eab705272b083/include/openenclave/bits/properties.h#L37
    /* Base type for enclave properties */
    typedef struct _oe_enclave_properties_header
    {
        uint32_t size; /**< (0) Size of the extended structure */

        oe_enclave_type_t enclave_type; /**< (4) Enclave type */

        oe_enclave_size_settings_t size_settings; /**< (8) Enclave settings */
    } oe_enclave_properties_header_t;
    """

    _fields_ = [
        ("size", ctypes.c_uint32),
        ("enclave_type", ctypes.c_uint32),  # Enums are 4byte integers, we use unsigned for 0xffffffff
        ("size_settings", OEEnclaveSizeSettings),
    ]

    def __str__(self):
        partial_dict = {
            n: getattr(self, n)
            for (n, _) in self._fields_
            if n not in ["size_settings"]  # 'family_id', 'extended_product_id',
        }
        partial_dict["size_settings"] = str(self.size_settings)
        return ui.log_format.format_fields(partial_dict)


class OESgxEnclaveFlags(ctypes.LittleEndianStructure):
    """
    https://github.com/openenclave/openenclave/blob/3b21d5a2589b64bcf253691b4ada0a6f60eb76e3/include/openenclave/bits/sgx/sgxproperties.h#L37
    typedef struct _oe_sgx_enclave_flags_t
    {
        uint32_t capture_pf_gp_exceptions : 1;
        uint32_t create_zero_base_enclave : 1;
        uint32_t reserved : 30;
    } oe_sgx_enclave_flags_t;
    """

    _fields_ = [
        ("capture_pf_gp_exceptions", ctypes.c_uint32),
        ("create_zero_base_enclave", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
    ]

    def __repr__(self):
        return "<" + str({n: getattr(self, n) for (n, _) in self._fields_}) + ">"


class OESgxEnclaveConfig(ctypes.LittleEndianStructure):
    """
    https://github.com/openenclave/openenclave/blob/3b21d5a2589b64bcf253691b4ada0a6f60eb76e3/include/openenclave/bits/sgx/sgxproperties.h#L44
    typedef struct oe_sgx_enclave_config_t
    {
        uint16_t product_id;
        uint16_t security_version;

        oe_sgx_enclave_flags_t flags;

        uint8_t family_id[16];
        uint8_t extended_product_id[16];
        /* (OE_SGX_FLAGS_DEBUG | OE_SGX_FLAGS_MODE64BIT | OE_SGX_FLAGS_KSS) */
        uint64_t attributes;

        /* XSave Feature Request Mask */
        uint64_t xfrm;

        /* Enclave start address. Currently valid only for 0-base enclave */
        uint64_t start_address;
    } oe_sgx_enclave_config_t;
    """

    _fields_ = [
        ("product_id", ctypes.c_uint16),
        ("security_version", ctypes.c_uint16),
        ("flags", OESgxEnclaveFlags),
        ("family_id", ctypes.c_uint8 * 16),
        ("extended_product_id", ctypes.c_uint8 * 16),
        ("attributes", ctypes.c_uint64),
        ("xfrm", ctypes.c_uint64),
        ("start_address", ctypes.c_uint64),
    ]

    def __str__(self):
        partial_dict = {n: getattr(self, n) for (n, _) in self._fields_ if n not in ["family_id", "extended_product_id", "flags"]}
        partial_dict["family_id"] = str(self.family_id)
        partial_dict["extended_product_id"] = str(self.extended_product_id)
        partial_dict["flags"] = str(self.flags)
        return ui.log_format.format_fields(partial_dict)


class OESgxEnclaveImageInfo(ctypes.LittleEndianStructure):
    """
    https://github.com/openenclave/openenclave/blob/3b21d5a2589b64bcf253691b4ada0a6f60eb76e3/include/openenclave/bits/sgx/sgxproperties.h#L17
    /* Image information */
    typedef struct _oe_sgx_enclave_image_info_t
    {
        uint64_t oeinfo_rva;
        uint64_t oeinfo_size;
        uint64_t reloc_rva;
        uint64_t reloc_size;
        uint64_t heap_rva; /* heap size is in header.sizesettings */
        uint64_t enclave_size;
    } oe_sgx_enclave_image_info_t;
    """

    _fields_ = [
        ("oeinfo_rva", ctypes.c_uint64),
        ("oeinfo_size", ctypes.c_uint64),
        ("reloc_rva", ctypes.c_uint64),
        ("reloc_size", ctypes.c_uint64),
        ("heap_rva", ctypes.c_uint64),
        ("enclave_size", ctypes.c_uint64),
    ]

    def __str__(self):
        partial_dict = {n: getattr(self, n) for (n, _) in self._fields_}
        return ui.log_format.format_fields(partial_dict)


"""
https://github.com/openenclave/openenclave/blob/3b21d5a2589b64bcf253691b4ada0a6f60eb76e3/include/openenclave/bits/sgx/sgxproperties.h#L35
define OE_SGX_SIGSTRUCT_SIZE 1808
"""
# OE_SGX_SIGSTRUCT_SIZE = 1808
# TODO: We are missing 8 bytes somewhere...?!?! Somehow sigstruct is only 1800 bytes in our elf file
OE_SGX_SIGSTRUCT_SIZE = 1800


class OESgxEnclaveProperties(ctypes.LittleEndianStructure):
    """
    https://github.com/openenclave/openenclave/blob/3b21d5a2589b64bcf253691b4ada0a6f60eb76e3/include/openenclave/bits/sgx/sgxproperties.h#L64
    /* Extends oe_enclave_properties_header_t base type */
    typedef struct _oe_sgx_enclave_properties
    {
        /* (0) */
        oe_enclave_properties_header_t header;

        /* (32) */
        oe_sgx_enclave_config_t config;

        /* (96) */
        oe_sgx_enclave_image_info_t image_info;

        /* (144)  */
        uint8_t sigstruct[OE_SGX_SIGSTRUCT_SIZE];

        /* (1960) end-marker to make sure 0-filled signstruct doesn't get omitted */
        uint64_t end_marker;
    } oe_sgx_enclave_properties_t;

    These properties are written to the elf file and filled by the sign tool
    The default values are defined here:
    https://github.com/openenclave/openenclave/blob/3b21d5a2589b64bcf253691b4ada0a6f60eb76e3/include/openenclave/bits/sgx/sgxproperties.h#L108

    #define _OE_SET_ENCLAVE_SGX_IMPL(                                         \
    PRODUCT_ID,                                                           \
    SECURITY_VERSION,                                                     \
    EXTENDED_PRODUCT_ID,                                                  \
    FAMILY_ID,                                                            \
    ALLOW_DEBUG,                                                          \
    REQUIRE_KSS,                                                          \
    CAPTURE_PF_GP_EXCEPTIONS,                                             \
    CREATE_ZERO_BASE_ENCLAVE,                                             \
    ENCLAVE_START_ADDRESS,                                                \
    HEAP_PAGE_COUNT,                                                      \
    STACK_PAGE_COUNT,                                                     \
    TCS_COUNT)                                                            \
    OE_INFO_SECTION_BEGIN                                                 \
    volatile const oe_sgx_enclave_properties_t oe_enclave_properties_sgx = \
    {                                                                     \
        .header =                                                         \
        {                                                                 \
            .size = sizeof(oe_sgx_enclave_properties_t),                  \
            .enclave_type = OE_ENCLAVE_TYPE_SGX,                          \
            .size_settings =                                              \
            {                                                             \
                .num_heap_pages = HEAP_PAGE_COUNT,                        \
                .num_stack_pages = STACK_PAGE_COUNT,                      \
                .num_tcs = TCS_COUNT                                      \
            }                                                             \
        },                                                                \
        .config =                                                         \
        {                                                                 \
            .product_id = PRODUCT_ID,                                     \
            .security_version = SECURITY_VERSION,                         \
            .flags =                                                      \
            {                                                             \
                .capture_pf_gp_exceptions = CAPTURE_PF_GP_EXCEPTIONS,     \
                .create_zero_base_enclave = CREATE_ZERO_BASE_ENCLAVE,     \
                .reserved = 0                                             \
            },                                                            \
            .family_id = REMOVE_PARENTHESES FAMILY_ID,                                       \
            .extended_product_id = REMOVE_PARENTHESES EXTENDED_PRODUCT_ID,                   \
            .attributes = OE_MAKE_ATTRIBUTES(ALLOW_DEBUG, REQUIRE_KSS),   \
            .start_address =                                              \
                CREATE_ZERO_BASE_ENCLAVE ? ENCLAVE_START_ADDRESS : 0,     \
        },                                                                \
        .image_info =                                                     \
        {                                                                 \
            0, 0, 0, 0, 0, 0                                              \
        },                                                                \
        .sigstruct =                                                      \
        {                                                                 \
            0                                                             \
        },                                                                \
        .end_marker = 0xecececececececec,                                 \
    };                                                                    \
    OE_INFO_SECTION_END
    """

    _fields_ = [
        ("header", OEEnclavePropertiesHeader),
        ("config", OESgxEnclaveConfig),
        ("image_info", OESgxEnclaveImageInfo),
        ("sigstruct", ctypes.c_uint8 * OE_SGX_SIGSTRUCT_SIZE),
        ("end_marker", ctypes.c_uint64),
    ]

    def __str__(self):
        return f"Open Enclave SGX Properties: \nHeader: {str(self.header)}\nConfig: {str(self.config)}\nImage Info: {str(self.image_info)}\nsigstruct is {len(self.sigstruct)} bytes long\nend_marker: {hex(self.end_marker)}"
