
import ctypes
import logging

from explorer import taint
from sdks.AbstractSDK import AbstractSDK
from sdks.common import Secs, SgxSsaGpr, load_struct_from_memory
from sdks.intel_linux_sgx_structs import Tcs
from ui import log_format
from utilities.angr_helper import get_reg_value, set_memory_value, set_reg_value

logger = logging.getLogger(__name__)

class AbstractSGXSDK(AbstractSDK):
    def __init__(self, elffile, init_state, version_str, **kwargs):
        self.tcs = None  # to be set by subclass
        self.init_state = init_state
        self.unmeasured_regions = []

    def get_unmeasured_pages(self):
        return self.unmeasured_regions

    def get_tcs(self):
        """
        Returns TCS as the address in memory where the TCS is stored.
        """
        return self.tcs

    def get_tcs_struct(self, state):
        return load_struct_from_memory(state, self.get_tcs(), Tcs)

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

    def rebase_addr(self, addr, name):
        base = self.get_base_addr()
        addr_rebased = base + addr
        logger.debug(f'Rebasing {log_format.format_inline_header(name)} from {addr:#x} to {addr_rebased:#x}')
        return addr_rebased

    def get_max_inst_size(self):
        # we safely over-approximate this here to the maximum length
        # of an x64 instruction (15 bytes)
        return 15

    def get_entry_addr(self):
        tcs_struct = self.get_tcs_struct(self.init_state)
        return self.rebase_addr(tcs_struct.oentry, 'oentry')

    def init_eenter_state(self, eenter_state):
        """
        From Intel SDM:
            > The ENCLU[EENTER] instruction transfers execution to an enclave.
            > At the end of the instruction, the logical processor is executing
            > in enclave mode at the IP computed as EnclaveBase + TCS.OENTRY.

            > RBX = Address of a TCS
            > RCX = Address of IP following EENTER

            > EAX = TCS.CSSA
            > FS  = TCS.OFSBASE
            > GS  = TCS.GSBASE

        In Intel SDK the entry code looks like this (sample)
        https://github.com/intel/linux-sgx/blob/effae6280234302a12169f89c561b96e54d80723/sdk/trts/linux/trts_pic.S#L95

        NOTE: We leave RCX symbolic as we're not interested in executing the
              untrusted runtime.
        """

        # Get tcs_struct and addr from SDK manager
        tcs_addr = self.get_tcs()
        tcs_struct = self.get_tcs_struct(eenter_state)

        set_reg_value(eenter_state, 'rip', self.get_entry_addr())
        set_reg_value(eenter_state, 'rbx', tcs_addr)
        set_reg_value(eenter_state, 'rax', tcs_struct.cssa)
        set_reg_value(eenter_state, 'fs', self.rebase_addr(tcs_struct.ofs_base, 'fs_base'))
        set_reg_value(eenter_state, 'gs', self.rebase_addr(tcs_struct.ogs_base, 'gs_base'))

        # EENTER saves the untrusted RSP and RBP in the SSA frame
        ssa = self.rebase_addr(tcs_struct.ossa, 'ossa')
        ssa_framesize = self.get_secs().ssa_frame_size * 4096
        ssa_gpr_pt = ssa + ((tcs_struct.cssa+1) * ssa_framesize) - ctypes.sizeof(SgxSsaGpr)
        ursp = get_reg_value(eenter_state, 'rsp')
        urbp = get_reg_value(eenter_state, 'rbp')
        set_memory_value(eenter_state, ssa_gpr_pt + SgxSsaGpr.ursp.offset, ursp)
        set_memory_value(eenter_state, ssa_gpr_pt + SgxSsaGpr.urbp.offset, urbp)
        logger.debug(f'eenter: saved {ursp} and {urbp} in SSA.GPRSGX at {ssa_gpr_pt:#x}')

        # ID flag: software can use this to test for CPUID support (cf Intel
        # SDM). Attacker control is irrelevant for ID flag, so we always set
        # this to zero.
        set_reg_value(eenter_state, 'id', 0)

        # Init shadow registers that we keep track of in XRSTOR/etc but that are
        # unknown to angr
        eenter_state.globals['pandora_mxcsr'] = taint.get_tainted_reg(eenter_state, 'mxcsr', 16)

    @staticmethod
    def get_angr_arch():
        return 'x86_64'
