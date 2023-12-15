"""
Pandora exposes additional breakpoints to the developer but uses the same angr backend.
That way, developers can use the known angr frontend to access enclave-specific events, just by creating a breakpoint.

The list of additional events is:
| Event | Description | Triggered by |
| eenter | Triggered on every eenter | eenter in explorer |
| eexit | Triggered on every eexit | SimEnclu |
| untrusted_mem_read |  reads from non-enclave memory | EnclaveAwareMixin |
| inside_or_outside_mem_read |  reads from memory that may lie inside the enclave (touch) | EnclaveAwareMixin |
| trusted_mem_read |  reads from enclave memory | EnclaveAwareMixin |
| untrusted_mem_write | writes to untrusted mem | EnclaveAwareMixin |
| inside_or_outside_mem_write | writes to mem that may touch the enclave (or fully lie inside) | EnclaveAwareMixin |
| trusted_mem_write | writes to trusted mem | EnclaveAwareMixin |

Note, that the BP_AFTER breakpoint does not make a lot of sense for the following events:
 - untrusted_mem_read : BP_AFTER is the same as BP_BEFORE with the difference in mem_read_expr which has
                        a fully symbolic, attacker tainted BVS
 - inside_or_outside_mem_read: Same as untrusted_mem_read
 - untrusted_mem_write : BP_AFTER is the exact same call as (and happens right after) BP_BEFORE. This call is only
                         done to support BP_AFTER and does not give more information than the BP_BEFORE call before.
 - inside_or_outside_mem_write: Same as untrusted_mem_write

Additionally, these are the attributes that are supported in each event:
eenter/eexit:
No attributes supported yet

eenter:
No attributes supported yet

all enclave mem reads support:
- mem_read_address
- mem_read_length

BP_AFTER mem reads additionally support:
 - mem_read_expr - With the loaded data

all enclave mem writes support:
- mem_write_address
- mem_write_length
- mem_write_expr

"""

PANDORA_EVENT_TYPES = {
    # Enclave events
    'eenter',
    'eexit',

    # Reads
    'untrusted_mem_read',
    'inside_or_outside_mem_read',
    'trusted_mem_read',

    # Writes
    'untrusted_mem_write',
    'inside_or_outside_mem_write',
    'trusted_mem_write',
}
PANDORA_INSPECT_ATTRIBUTES = {
    # Put additional attributes that may be Pandora-specific here
}
