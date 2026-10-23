/* SPDX-License-Identifier: Apache-2.0 */
/* BP08 producer task/exec identity ABI (host-packaged, 32 bytes, align 8).
 *
 * ADAPT p11scope 2c2713e `crates/ebpf/native/image_identity.h:20-53`
 * (status-enum discipline, identity/control ABI static asserts; the donor
 * carries the session domain in the retained consumer while this spec
 * layout carries 16 domain bytes inline, offsets 0/16/24).
 * Grant: OWNER-2026-10-23 + D03 (user-owned GPL donor, library destination).
 * Donor START/privacy/discovery layouts, loader control cells, BPF map
 * definitions and helper tables are NOT copied; only the status discipline
 * and assert-the-ABI practice port.
 */
#ifndef SCOPEBASE_TASK_IDENTITY_H
#define SCOPEBASE_TASK_IDENTITY_H

#include <stddef.h>
#include <stdint.h>

/* Fixed producer identity, initial x86-64 profile: 32 bytes, align 8,
 * offsets producer_domain=0, task_cookie=16, exec_generation=24.
 * Cookie 0 is unavailable; exec generation 0 is a valid birth epoch. */
struct scopebase_producer_identity_v1 {
    uint8_t producer_domain[16];
    uint64_t task_cookie;
    uint64_t exec_generation;
};

enum scopebase_identity_status_v1 {
    SCOPEBASE_IDENTITY_OK = 0,
    SCOPEBASE_IDENTITY_ZERO_COOKIE = -1,
    SCOPEBASE_IDENTITY_EXHAUSTED = -2
};

_Static_assert(sizeof(struct scopebase_producer_identity_v1) == 32,
               "producer identity ABI size");
_Static_assert(_Alignof(struct scopebase_producer_identity_v1) == 8,
               "producer identity ABI alignment");
_Static_assert(offsetof(struct scopebase_producer_identity_v1, producer_domain) == 0,
               "producer domain offset");
_Static_assert(offsetof(struct scopebase_producer_identity_v1, task_cookie) == 16,
               "task cookie offset");
_Static_assert(offsetof(struct scopebase_producer_identity_v1, exec_generation) == 24,
               "exec generation offset");

#endif /* SCOPEBASE_TASK_IDENTITY_H */
