from angr import BP_AFTER, BP_BEFORE
from angr.storage import MemoryMixin
import logging
import pandora_options as po

from explorer.enclave import buffer_touches_enclave, buffer_entirely_inside_enclave
from explorer.taint import is_tainted, get_tainted_mem_bits, add_taint

logger = logging.getLogger(__name__)

class EnclaveAwareMixin(MemoryMixin):

    def store(self, addr, data, with_enclave_boundaries=True, size=None, **kwargs):
        breakpoint_event = ''

        if size is None:
            size = len(data)

        # Only enable the mixin if store is called with_enclave_boundaries (default on)
        mixin_enabled = self.category == 'mem' \
                        and with_enclave_boundaries \
                        and po.PANDORA_ENCLAVE_MIXIN_ENABLE in self.state.options

        if mixin_enabled:
            if buffer_entirely_inside_enclave(self.state, addr, size):
                """
                Case: Store on buffer that fully lies inside the enclave
                """
                breakpoint_event = 'trusted_mem_write'

            elif buffer_touches_enclave(self.state, addr, size):
                """
                Case: Store on Buffer that can lie outside OR inside the enclave
                """
                # --> Trigger touches breakpoint
                breakpoint_event = 'inside_or_outside_mem_write'

            else:
                """
                Case: Store on fully untrusted buffer
                """
                breakpoint_event = 'untrusted_mem_write'

            self.state._inspect(
                breakpoint_event,
                BP_BEFORE,
                mem_write_address=addr,
                mem_write_length=size,
                mem_write_expr=data,
            )

            if breakpoint_event != 'trusted_mem_write':
                """
                Addresses that are not FULLY in enclave range: Ignore the store
                This is the conservative approach to simulating enclave memory:
                 - Buffers fully inside the enclave are simulated normally
                 - ALL other buffers are completely symbolized and ignored
                 Note, that the breakpoint has already triggered, so we still allow all reports of the security 
                  implications of such stores. But for Pandora, we now functionality-wise symbolize this store
                  by ignoring it. 
                This also impacts partial buffers that may lie outside OR inside. These are also ignored for stores and
                  the ptrsan plugin needs to make sure we report it properly as a security issue.
                """
                logger.debug(f'Ignoring untrusted {self.category} store @ {addr}.')

                # The post load breakpoint does not make too much sense here, but we trigger it still
                #   as to not break the developers expectations
                self.state._inspect(
                    breakpoint_event,
                    BP_AFTER,
                    mem_write_address=addr,
                    mem_write_length=size,
                    mem_write_expr=data,
                )

                return None

        # All other stores are performed normally by passing them down
        r = super().store(addr, data, size=size, **kwargs)

        if mixin_enabled:
            # After the store, call the breakpoint again
            self.state._inspect(
                breakpoint_event,
                BP_AFTER,
                mem_write_address=addr,
                mem_write_length=size,
                mem_write_expr=data,
            )

        return r

    def load(self, addr, size=None, with_enclave_boundaries=True, **kwargs):
        read_was_in_trusted_mem = False
        breakpoint_event = ''

        # Only enable the mixin if load is called with_enclave_boundaries (default on)
        # For enclave memory, we only care about memory loads
        mixin_enabled = with_enclave_boundaries \
                        and po.PANDORA_ENCLAVE_MIXIN_ENABLE in self.state.options \
                        and self.category == 'mem'

        if mixin_enabled :
            if buffer_entirely_inside_enclave(self.state, addr, size):
                logger.log(logging.TRACE, f'Reading enclave memory @{addr} size {size}')
                breakpoint_event = 'trusted_mem_read'

            else:
                if buffer_touches_enclave(self.state, addr, size):
                    breakpoint_event = 'inside_or_outside_mem_read'
                else:
                    # Addr is NOT in enclave range
                    breakpoint_event = 'untrusted_mem_read'

            # Trigger read BEFORE breakpoint
            self.state._inspect(
                breakpoint_event,
                BP_BEFORE,
                mem_read_address=addr,
                mem_read_length=size
            )

            if breakpoint_event != 'trusted_mem_read':
                """
                 Note: this else case is triggered:
                  1. when the load touches partly the enclave (i.e. half of the load is outside and half is inside), or
                  2. when the load fully lies outside the enclave
                 Both cases will be handled by returning a fully symbolic attacker tainted data. 
                 This is the conservative handling of partially untrusted loads.
                 However, we first triggered the respective breakpoint, create the load, and then trigger the post 
                  breakpoint before returning.
                """
                mem = get_tainted_mem_bits(self.state, size * 8)
                logger.debug(f'Simulating untrusted {self.category} load @ {addr} with a tainted BVS {mem}.')

                # The post load breakpoint does not make too much sense here, but we trigger it still
                #   as to not break the developers expectations
                self.state._inspect(
                    breakpoint_event,
                    BP_AFTER,
                    mem_read_address=addr,
                    mem_read_length=size,
                    mem_read_expr=mem,
                )
                # Early return the untrusted read
                return mem

        # Trusted reads proceed normally
        r = super().load(addr, size=size, **kwargs)

        if mixin_enabled:
            # Trigger post load trusted_mem_read
            self.state._inspect(
                breakpoint_event,
                BP_AFTER,
                mem_read_address=addr,
                mem_read_length=size,
                mem_read_expr=r,
            )

        return r
