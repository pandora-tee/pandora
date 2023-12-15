import logging

from angr.storage import MemoryMixin

import ui.report
from explorer.enclave import buffer_entirely_inside_enclave, buffer_touches_enclave
from explorer.taint import get_tainted_mem_bits
from sdks.SDKManager import SDKManager
from ui.action_manager import ActionManager
from ui.report import Reporter

logger = logging.getLogger(__name__)

class EnclaveMemoryFillerMixin(MemoryMixin):
    """
    The EnclaveMemoryFillerMixin makes sure that default memory behaves differently depending
    on which address it has.

    Enclave Memory:
     - Measured pages: Are treated as zero
     - Unmeasured pages: Are treated as attacker controlled
    Non-enclave memory:
     - Treateed as attacker controlled

    Note that this mixin should only be called on addresses UNKNOWN to the memory backend, so any data
     loaded during Pandora loading should already be returned before this is called. This is just the last
     resort if angr can't resolve the address.

    """

    def _default_value(self, addr, size, inspect=True, events=True, **kwargs):
        if type(addr) is not int:
            raise RuntimeError(f'Unexpected {addr} not as an int at the bottom of mixins')
        logger.debug(f'Uninitialized read for {addr:#x} (size={size} bytes)')

        if SDKManager().addr_in_unmeasured_uninitialized_page(addr, size):
            # Address is in an unmeasured enclave page. Return a purely symbolic value
            mem = get_tainted_mem_bits(self.state, size*8, inspect=inspect, events=events)
            logger.log(logging.WARNING if inspect else logging.DEBUG, # If we are not inspecting, this is not an issue
                       f'Buffer {addr:#x} (size {size}) lies within unmeasured memory! Returning tainted memory {str(mem)}.')

            if inspect:
                # Only report this if we want to have the read inspected (i.e., disable if this is an internal load made on purpose).
                info = 'Unmeasured memory read without prior initialization'
                extra = {
                    'Address': hex(addr),
                    'Size (bytes)': size,
                    'Description': f'Continued with tainted symbolic memory {str(mem)}',
                }
                Reporter().report(info,
                                  self.state,
                                  logger,
                                  ui.report.SYSTEM_EVENTS_REPORT_NAME,
                                  severity=logging.WARNING,
                                  extra_info=extra
                                  )
                # Trigger a user action if requested
                ActionManager().actions['system'](info=info, state=self.state)

            return mem

        if buffer_entirely_inside_enclave(self.state, addr, size):
                # Address is in a measured page. Then, we actually want to treat this as zero
                # TODO: Maybe taint as uninitialized?
                mem = self.state.solver.BVV(0, size * 8)
                logger.debug(f'Buffer {addr:#x} (size {size}) lies in measured memory. Returning zero buffer {str(mem)}.')
                return mem
        else:
            if buffer_touches_enclave(self.state, addr, size):
                # Buffer is not _entirely_ inside the enclave but _touches_ the enclave. This is not good.
                raise RuntimeError('Unexpected default called on buffer partially inside enclave')

            else:
                # This should technically never happen: The EnclaveAwareMixin
                # should interrupt such calls and return a new tainted memory
                # every time
                mem = get_tainted_mem_bits(self.state, size*8, inspect=inspect, events=events)
                logger.debug(
                    f'Buffer {addr:#x} (size {size}) lies outside the enclave. Returning tainted memory {str(mem)}.')

                return mem
