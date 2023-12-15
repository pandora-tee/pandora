from angr.storage.memory_mixins import PagedMemoryMixin, SymbolicMergerMixin, DefaultFillerMixin, UltraPagesMixin, \
    PrivilegedPagingMixin, DictBackerMixin, ClemoryBackerMixin, ConcreteBackerMixin, StackAllocationMixin, \
    DirtyAddrsMixin, ConvenientMappingsMixin, ConditionalMixin, ActionsMixinLow, AddressConcretizationMixin, \
    SizeNormalizationMixin, SizeConcretizationMixin, UnderconstrainedMixin, ActionsMixinHigh, InspectMixinHigh, \
    DataNormalizationMixin, NameResolutionMixin, UnwrapperMixin, SmartFindMixin

from explorer.memory.EnclaveAwareMixin import EnclaveAwareMixin
from explorer.memory.EnclaveMemoryFillerMixin import EnclaveMemoryFillerMixin


class EnclaveAwareMemory(
    # HexDumperMixin, # adds the hex_dump function which is quite slow
    SmartFindMixin,
    UnwrapperMixin, # description: processes SimActionObjects by passing on their .ast field.
    NameResolutionMixin, # description: allows you to provide register names as load addresses, and will automatically translate this to an offset and size.
    DataNormalizationMixin, # description: Normalizes the data field for a store and the fallback field for a load to be BVs.
    # SimplificationMixin, # hooks stores and first calls state.solver.simplify(data) if options.SIMPLIFY_[MEMORY/REGISTER]_WRITES is set
    InspectMixinHigh, # The logic to inspect memory/register reads/writes --> calls ._inspect before/after.
    ActionsMixinHigh,
    UnderconstrainedMixin,
    SizeConcretizationMixin,
    SizeNormalizationMixin,
    EnclaveAwareMixin,      # Added for Pandora. Executed before the AddresConcretization to catch untrusted memory accesses.
    AddressConcretizationMixin,
    #InspectMixinLow,
    ActionsMixinLow,
    ConditionalMixin,
    ConvenientMappingsMixin,
    DirtyAddrsMixin,
    # -----
    StackAllocationMixin,
    ConcreteBackerMixin,
    ClemoryBackerMixin,
    DictBackerMixin,
    PrivilegedPagingMixin,
    UltraPagesMixin,
    # DefaultFillerMixin,
    EnclaveMemoryFillerMixin, # Our own enclave filler mixin
    SymbolicMergerMixin,

    # Paged memory that dispatches to individual pages.
    # Needs size and addr of both store and load to be concretized (int)
    # PagedMemoryMixin does not return a context and is the last mixin to execute
    PagedMemoryMixin,

):
    pass