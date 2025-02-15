import binascii
import ctypes

import claripy
import ui.log_format

import archinfo

import logging
logger = logging.getLogger(__name__)

def create_versioned_struct(versioned_type, version_major, version_minor):
    fields = []
    added_names = []
    for (major_from, minor_from, name, ctype) in versioned_type._fields_versioned_:
        # note: in case of revised fields, specify newest revision first
        # -> any older ones with the same  name will not be added
        if version_major >= major_from and version_minor >= minor_from and not name in added_names:
            # recursively apply versioning to any contained subtypes
            if hasattr(ctype,'_fields_versioned_'):
                ctype = create_versioned_struct(ctype, version_major, version_minor)
            fields.append((name,ctype))
            added_names.append(name)

    # create and return the versioned type class dynamically
    t = type(f'{versioned_type.__name__}v{version_major}{version_minor}',
            (ctypes.LittleEndianStructure, ), {
            '_fields_' : fields,
            '__str__'  : versioned_type.__str__,
            'to_dict'  : versioned_type.to_dict
    })

    logger.debug(f'Dynamically created {t.__name__} struct with {len(fields)} members')
    return t

def write_struct_to_memory(state, addr, struct, with_enclave_boundaries=False):
    # logger.debug(f'Writing struct {str(type(struct))} to addr {addr:#x}. Struct bytes are {binascii.hexlify(bytes(struct))}')
    state.memory.store(addr, bytes(struct), size=ctypes.sizeof(struct), with_enclave_boundaries=with_enclave_boundaries)

def write_bvv_to_memory(state, addr, bvv_str, bits):
    bvv = claripy.BVV(bvv_str, bits)
    enclave_file_base = state.project.loader.main_object.mapped_base
    addr = enclave_file_base + addr
    logger.debug(f'Writing BVV {bvv} to addr {addr:#x}.')
    state.memory.store(addr, bvv, endness=archinfo.Endness.LE, with_enclave_boundaries=False)

def load_struct_from_memory(state, addr, struct_type):
    """
    Helper function to convert a struct from angr memory.

    NOTE: The returned struct is a copy, so updating it won't update the memory.
    """
    # first load content as a bit vector
    struct_bv = state.memory.load(addr, size=ctypes.sizeof(struct_type), with_enclave_boundaries=False)

    # now evaluate the bit vector to bytes to get the actual data
    struct_bytes = state.solver.eval(struct_bv, cast_to=bytes, endness=archinfo.Endness.LE)
    # logger.debug(f'Reading struct {str(type(struct_type))} from addr {addr:#x}. Struct bytes are {binascii.hexlify(struct_bytes)}')

    # finally convert to the requested struct type
    struct = struct_type.from_buffer_copy(struct_bytes)
    return struct

################################################################################
# Architectural SGX structure definitions.
# --> stable across SDKs, as defined in the SGX ISA).
################################################################################

class Tcs(ctypes.LittleEndianStructure):
    """
    typedef struct _tcs_t
    {
        uint64_t            reserved0;       /* (0) */
        uint64_t            flags;           /* (8)bit 0: DBGOPTION */
        uint64_t            ossa;            /* (16)State Save Area */
        uint32_t            cssa;            /* (24)Current SSA slot */
        uint32_t            nssa;            /* (28)Number of SSA slots */
        uint64_t            oentry;          /* (32)Offset in enclave to which control is transferred on EENTER if enclave INACTIVE state */
        uint64_t            reserved1;       /* (40) */
        uint64_t            ofs_base;        /* (48)When added to the base address of the enclave, produces the base address FS segment inside the enclave */
        uint64_t            ogs_base;        /* (56)When added to the base address of the enclave, produces the base address GS segment inside the enclave */
        uint32_t            ofs_limit;       /* (64)Size to become the new FS limit in 32-bit mode */
        uint32_t            ogs_limit;       /* (68)Size to become the new GS limit in 32-bit mode */
    #define TCS_RESERVED_LENGTH 4024
        uint8_t             reserved[TCS_RESERVED_LENGTH];  /* (72) */
    }tcs_t;
    """
    _fields_ = [
        ("reserved0", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
        ("ossa", ctypes.c_uint64),
        ("cssa", ctypes.c_uint32),
        ("nssa", ctypes.c_uint32),
        ("oentry", ctypes.c_uint64),
        ("reserved1", ctypes.c_uint64),
        ("ofs_base", ctypes.c_uint64),
        ("ogs_base", ctypes.c_uint64),
        ("ofs_limit", ctypes.c_uint32),
        ("ogs_limit", ctypes.c_uint32),
        ("reserved", ctypes.c_uint8 * 4024),
    ]

    def __str__(self):
        fields = {n: getattr(self, n) for n, _ in self._fields_
                  if n not in ['reserved', 'reserved0', 'reserved1']}
        return ui.log_format.format_fields(fields)


class SgxAttributes(ctypes.LittleEndianStructure):
    """
    Attributes is just 2 x uint64 large for a flags and an xfrm field:
        https://github.com/intel/linux-sgx/blob/321a6580fb133a4f9d80245f18556e5bd51521d3/common/inc/sgx_attributes.h#L58
    typedef struct _attributes_t
    {
        uint64_t      flags;
        uint64_t      xfrm;
    } sgx_attributes_t;
    """
    _fields_ = [
        ('flags', ctypes.c_uint64),
        ('xfrm', ctypes.c_uint64),
    ]

    def __repr__(self):
        return 'Attributes with flags {0} and xfrm {1}'.format(self.flags, self.xfrm)


class Secs(ctypes.LittleEndianStructure):
    """
    https://github.com/intel/linux-sgx/blob/1efe23c20e37f868498f8287921eedfbcecdc216/common/inc/internal/arch.h#L62

    typedef struct _secs_t
    {
        uint64_t                    size;           /* (  0) Size of the enclave in bytes */
        PADDED_POINTER(void,        base);          /* (  8) Base address of enclave */
        uint32_t                    ssa_frame_size; /* ( 16) size of 1 SSA frame in pages */
        sgx_misc_select_t           misc_select;    /* ( 20) Which fields defined in SSA.MISC */
    #define SECS_RESERVED1_LENGTH 24
        uint8_t                     reserved1[SECS_RESERVED1_LENGTH];  /* ( 24) reserved */
        sgx_attributes_t            attributes;     /* ( 48) ATTRIBUTES Flags Field */
        sgx_measurement_t           mr_enclave;     /* ( 64) Integrity Reg 0 - Enclave measurement */
    #define SECS_RESERVED2_LENGTH 32
        uint8_t                     reserved2[SECS_RESERVED2_LENGTH];  /* ( 96) reserved */
        sgx_measurement_t           mr_signer;      /* (128) Integrity Reg 1 - Enclave signing key */
    #define SECS_RESERVED3_LENGTH 32
        uint8_t                     reserved3[SECS_RESERVED3_LENGTH];  /* (160) reserved */
        sgx_config_id_t             config_id;      /* (192) CONFIGID */
        sgx_prod_id_t               isv_prod_id;    /* (256) product ID of enclave */
        sgx_isv_svn_t               isv_svn;        /* (258) Security Version of the Enclave */
        sgx_config_svn_t            config_svn;     /* (260) CONFIGSVN */
    #define SECS_RESERVED4_LENGTH 3834
        uint8_t                     reserved4[SECS_RESERVED4_LENGTH];/* (262) reserved */
    } secs_t;
"""
    _fields_ = [
        ("size", ctypes.c_uint64),
        ("base", ctypes.c_uint64),
        ("ssa_frame_size", ctypes.c_uint32),
        ("misc_select", ctypes.c_uint32),
        # NOTE: some reserved fields have since been used for CET
        ("cet_leg_bitmap_offset", ctypes.c_uint64),
        ("cet_attributes", ctypes.c_uint8),     
        ("reserved1", ctypes.c_uint8 * 15),
        ("attributes", SgxAttributes),
        ("mr_enclave", ctypes.c_uint8 * 32),
        ("reserved2", ctypes.c_uint8 * 32),
        ("mr_signer", ctypes.c_uint8 * 32),
        ("reserved3", ctypes.c_uint8 * 32),
        ("config_id", ctypes.c_uint8 * 64),
        ("isv_prod_id", ctypes.c_uint16),
        ("isv_svn", ctypes.c_uint16),
        ("config_svn", ctypes.c_uint16),
        ("reserved3", ctypes.c_uint8 * 3834),    
    ]

    def __str__(self):
        fields = {n: getattr(self, n) for n, _ in self._fields_
                  if not 'reserved' in n}
        return ui.log_format.format_fields(fields)


class SgxReport(ctypes.LittleEndianStructure):
    """
    typedef struct _report_body_t
    {
        sgx_cpu_svn_t           cpu_svn;        /* (  0) Security Version of the CPU */
        sgx_misc_select_t       misc_select;    /* ( 16) Which fields defined in SSA.MISC */
        uint8_t                 reserved1[SGX_REPORT_BODY_RESERVED1_BYTES];  /* ( 20) */
        sgx_isvext_prod_id_t    isv_ext_prod_id;/* ( 32) ISV assigned Extended Product ID */
        sgx_attributes_t        attributes;     /* ( 48) Any special Capabilities the Enclave possess */
        sgx_measurement_t       mr_enclave;     /* ( 64) The value of the enclave's ENCLAVE measurement */
        uint8_t                 reserved2[SGX_REPORT_BODY_RESERVED2_BYTES];  /* ( 96) */
        sgx_measurement_t       mr_signer;      /* (128) The value of the enclave's SIGNER measurement */
        uint8_t                 reserved3[SGX_REPORT_BODY_RESERVED3_BYTES];  /* (160) */
        sgx_config_id_t         config_id;      /* (192) CONFIGID */
        sgx_prod_id_t           isv_prod_id;    /* (256) Product ID of the Enclave */
        sgx_isv_svn_t           isv_svn;        /* (258) Security Version of the Enclave */
        sgx_config_svn_t        config_svn;     /* (260) CONFIGSVN */
        uint8_t                 reserved4[SGX_REPORT_BODY_RESERVED4_BYTES];  /* (262) */
        sgx_isvfamily_id_t      isv_family_id;  /* (304) ISV assigned Family ID */
        sgx_report_data_t       report_data;    /* (320) Data provided by the user */
    } sgx_report_body_t;

    typedef struct _report_t                    /* 432 bytes */
    {
        sgx_report_body_t       body;
        sgx_key_id_t            key_id;         /* (384) KeyID used for diversifying the key tree */
        sgx_mac_t               mac;            /* (416) The Message Authentication Code over this structure. */
    } sgx_report_t;
"""
    _fields_ = [
        ("cpu_svn", ctypes.c_uint8 * 16),
        ("misc_select", ctypes.c_uint32),
        ("cet_attributes", ctypes.c_uint8),
        ("reserved1", ctypes.c_uint8 * 11),
        ("isv_ext_prod_id", ctypes.c_uint8 * 16),
        ("attributes", SgxAttributes),
        ("mr_enclave", ctypes.c_uint8 * 32),
        ("reserved2", ctypes.c_uint8 * 32),
        ("mr_signer", ctypes.c_uint8 * 32),
        ("reserved3", ctypes.c_uint8 * 32),
        ("config_id", ctypes.c_uint8 * 64),
        ("isv_prod_id", ctypes.c_uint16),
        ("isv_svn", ctypes.c_uint16),
        ("config_svn", ctypes.c_uint16),
        ("reserved3", ctypes.c_uint8 * 42),  
        ("isv_family_id", ctypes.c_uint8 * 16),
        ("report_data", ctypes.c_uint8 * 64),
        ("key_id", ctypes.c_uint8 * 32),
        ("mac", ctypes.c_uint8 * 16),
    ]

    def __str__(self):
        fields = {n: getattr(self, n) for n, _ in self._fields_
                  if not 'reserved' in n}
        return ui.log_format.format_fields(fields)


class SgxSsaGpr(ctypes.LittleEndianStructure):
    """
    https://github.com/intel/linux-sgx/blob/1efe23c20e37f868498f8287921eedfbcecdc216/common/inc/internal/arch.h#L133

    typedef struct _ssa_gpr_t
    {
        REGISTER(   ax);                    /* (0) */
        REGISTER(   cx);                    /* (8) */
        REGISTER(   dx);                    /* (16) */
        REGISTER(   bx);                    /* (24) */
        REGISTER(   sp);                    /* (32) */
        REGISTER(   bp);                    /* (40) */
        REGISTER(   si);                    /* (48) */
        REGISTER(   di);                    /* (56) */
        uint64_t    r8;                     /* (64) */
        uint64_t    r9;                     /* (72) */
        uint64_t    r10;                    /* (80) */
        uint64_t    r11;                    /* (88) */
        uint64_t    r12;                    /* (96) */
        uint64_t    r13;                    /* (104) */
        uint64_t    r14;                    /* (112) */
        uint64_t    r15;                    /* (120) */
        REGISTER(flags);                 /* (128) */
        REGISTER(   ip);                 /* (136) */
        REGISTER( sp_u);                 /* (144) untrusted stack pointer. saved by EENTER */
        REGISTER( bp_u);                 /* (152) untrusted frame pointer. saved by EENTER */
        exit_info_t exit_info;              /* (160) contain information for exits */
        uint32_t    reserved;               /* (164) padding to multiple of 8 bytes */
        uint64_t    fs;                     /* (168) FS register */
        uint64_t    gs;                     /* (176) GS register */
    } ssa_gpr_t;
    """

    _fields_ = [
        ("rax", ctypes.c_uint64),
        ("rcx", ctypes.c_uint64),
        ("rdx", ctypes.c_uint64),
        ("rbx", ctypes.c_uint64),
        ("rsp", ctypes.c_uint64),
        ("rsp", ctypes.c_uint64),
        ("rsi", ctypes.c_uint64),
        ("rdi", ctypes.c_uint64),
        ("r8", ctypes.c_uint64),
        ("r9", ctypes.c_uint64),
        ("r10", ctypes.c_uint64),
        ("r11", ctypes.c_uint64),
        ("r12", ctypes.c_uint64),
        ("r13", ctypes.c_uint64),
        ("r14", ctypes.c_uint64),
        ("r15", ctypes.c_uint64),
        ("rflags", ctypes.c_uint64),
        ("rip", ctypes.c_uint64),
        ("ursp", ctypes.c_uint64),
        ("urbp", ctypes.c_uint64),
        ("exitinfo", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("fsbase", ctypes.c_uint64),
        ("gsbase", ctypes.c_uint64),
    ]

    def __str__(self):
        fields = {n: getattr(self, n) for n, _ in self._fields_
                  if not 'reserved' in n}
        return ui.log_format.format_fields(fields)