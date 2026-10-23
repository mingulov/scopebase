/* SPDX-License-Identifier: Apache-2.0 */
/* BP08 producer contract helpers: task assignment and exec advance.
 *
 * ADAPT p11scope 2c2713e `crates/ebpf/native/image_identity.c:121-137`
 * (`identity_for`: both fields come from the same typed task, exec zero
 * valid, outputs start zeroed) and `:38-119` (zero-cell and quota refusal
 * discipline). This host-packaged seam validates BEFORE writing, so a
 * refusal leaves the output unchanged (the donor zeroes first inside the
 * kernel hook instead; same refusal, different commit point).
 * Grant: OWNER-2026-10-23 + D03 (user-owned GPL donor, library destination).
 * Task-storage allocation, ticket CAS, BPF maps and production hooks are
 * NOT copied; only the assign/advance refusal contract ports.
 *
 * Production-hook obligations (NOT implemented here): allocate task tickets
 * from a bounded budget; emit identities only from the birth hook for
 * non-CLONE_THREAD tasks (`image_identity_fork.c:16-63` discipline);
 * advance exec only on successful exec of the same typed task; apply the
 * CO-RE existence-before-size/read scalar/bitmap guards (`exec_task.c:18-76`
 * discipline) before optional-field access; never infer exec success from
 * userspace polling. See fixtures/identity-v1/exec-shapes.json for the
 * host-checkable guard-order truth table.
 */
#ifndef SCOPEBASE_PRODUCER_CONTRACT_H
#define SCOPEBASE_PRODUCER_CONTRACT_H

#include "task_identity.h"

#include <stdint.h>
#include <string.h>

/* Bind a task ticket to an identity: copies the caller domain, requires a
 * nonzero cookie and initializes exec to the birth epoch 0. Returns
 * SCOPEBASE_IDENTITY_OK on success; on refusal (null output/domain or
 * zero cookie) returns SCOPEBASE_IDENTITY_ZERO_COOKIE with *out unchanged.
 * This helper does not allocate tickets, access maps or prove continuity. */
static inline int scopebase_identity_assign_task_v1(
    struct scopebase_producer_identity_v1 *out,
    const uint8_t producer_domain[16], uint64_t nonzero_cookie)
{
    if (!out || !producer_domain || nonzero_cookie == 0)
        return SCOPEBASE_IDENTITY_ZERO_COOKIE;
    memcpy(out->producer_domain, producer_domain, sizeof(out->producer_domain));
    out->task_cookie = nonzero_cookie;
    out->exec_generation = 0;
    return SCOPEBASE_IDENTITY_OK;
}

/* Advance one exec epoch: requires a nonzero cookie and a generation below
 * UINT64_MAX (no wrap). Returns SCOPEBASE_IDENTITY_OK on success;
 * SCOPEBASE_IDENTITY_ZERO_COOKIE for null/zero-cookie input and
 * SCOPEBASE_IDENTITY_EXHAUSTED at the top generation, both with *identity
 * unchanged. This helper does not infer exec success or provide ordering. */
static inline int scopebase_identity_advance_exec_v1(
    struct scopebase_producer_identity_v1 *identity)
{
    if (!identity || identity->task_cookie == 0)
        return SCOPEBASE_IDENTITY_ZERO_COOKIE;
    if (identity->exec_generation == UINT64_MAX)
        return SCOPEBASE_IDENTITY_EXHAUSTED;
    identity->exec_generation += 1;
    return SCOPEBASE_IDENTITY_OK;
}

#endif /* SCOPEBASE_PRODUCER_CONTRACT_H */
