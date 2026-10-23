/* SPDX-License-Identifier: Apache-2.0 */
/* BP08 producer fixture: host-compilable exercise of the packaged C
 * identity contract (NOT a BPF production hook).
 *
 * Build (host gcc, no BPF toolchain):
 *   cc -std=c11 -Wall -Wextra -I crates/scopebase-bpf/include \
 *      crates/scopebase-bpf/fixtures/identity-v1/producer.c -o /tmp/bp08-producer
 *
 * Returns 0 when assign/advance accept the happy path and every refusal
 * leaves its output unchanged, including exec saturation at UINT64_MAX.
 * Grant: OWNER-2026-10-23 + D03; user-owned donor discipline only, no
 * third-party lines. Production hooks, maps and CO-RE relocations stay
 * with the TT05/TC05/TC06 object/live bindings (NOT_RUN here).
 */
#include "scopebase/producer_contract.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        printf("FAIL %d: %s\n", __LINE__, #cond); \
        failures += 1; \
    } \
} while (0)

static int identity_equal(const struct scopebase_producer_identity_v1 *a,
                          const struct scopebase_producer_identity_v1 *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

int main(void)
{
    const uint8_t domain[16] = {
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
        0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
    };
    struct scopebase_producer_identity_v1 id;
    struct scopebase_producer_identity_v1 before;

    memset(&id, 0x5A, sizeof(id));
    CHECK(scopebase_identity_assign_task_v1(&id, domain, 7) == SCOPEBASE_IDENTITY_OK);
    CHECK(memcmp(id.producer_domain, domain, sizeof(domain)) == 0);
    CHECK(id.task_cookie == 7);
    CHECK(id.exec_generation == 0);

    /* Zero-cookie assignment refuses and leaves the output unchanged. */
    before = id;
    CHECK(scopebase_identity_assign_task_v1(&id, domain, 0)
          == SCOPEBASE_IDENTITY_ZERO_COOKIE);
    CHECK(identity_equal(&id, &before));

    /* Exec advances one step per successful call. */
    CHECK(scopebase_identity_advance_exec_v1(&id) == SCOPEBASE_IDENTITY_OK);
    CHECK(id.exec_generation == 1);
    CHECK(id.task_cookie == 7);

    /* A zero-cookie record never advances. */
    memset(&before, 0, sizeof(before));
    memcpy(before.producer_domain, domain, sizeof(domain));
    id = before;
    CHECK(scopebase_identity_advance_exec_v1(&id)
          == SCOPEBASE_IDENTITY_ZERO_COOKIE);
    CHECK(identity_equal(&id, &before));

    /* Saturation refuses without wrapping. */
    CHECK(scopebase_identity_assign_task_v1(&id, domain, 9) == SCOPEBASE_IDENTITY_OK);
    id.exec_generation = UINT64_MAX;
    before = id;
    CHECK(scopebase_identity_advance_exec_v1(&id) == SCOPEBASE_IDENTITY_EXHAUSTED);
    CHECK(identity_equal(&id, &before));
    CHECK(id.exec_generation == UINT64_MAX);

    /* F02: self-domain re-assignment is well-defined (memmove, not
     * memcpy): the domain survives, the cookie updates, exec resets.
     * The uniform cookie keeps the shifted case below endian-free. */
    const uint64_t uniform = 0x0B0B0B0B0B0B0B0Bull;
    CHECK(scopebase_identity_assign_task_v1(&id, id.producer_domain, uniform)
          == SCOPEBASE_IDENTITY_OK);
    CHECK(memcmp(id.producer_domain, domain, sizeof(domain)) == 0);
    CHECK(id.task_cookie == uniform);
    CHECK(id.exec_generation == 0);

    /* F02 shifted variant: an interior self-pointer makes source and
     * destination partially overlap (the copy also picks up byte 16,
     * the cookie's first byte; layout is padding-free per the header
     * static asserts). memmove defines this; memcpy is UB that ASan
     * flags as memcpy-param-overlap. */
    {
        const uint8_t expect_shift[16] = {
            0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
            0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0x0B
        };
        /* Laundered through an integer so the compiler sees an opaque
         * caller pointer (as a real consumer would pass), not a 15-byte
         * tail it can reason about. Same address: &id + 1. */
        const uint8_t *shifted =
            (const uint8_t *)((uintptr_t)(const void *)&id + 1);
        CHECK(scopebase_identity_assign_task_v1(&id, shifted, 12)
              == SCOPEBASE_IDENTITY_OK);
        CHECK(memcmp(id.producer_domain, expect_shift, sizeof(expect_shift)) == 0);
        CHECK(id.task_cookie == 12);
        CHECK(id.exec_generation == 0);
    }

    if (failures == 0)
        printf("bp08 producer fixture: all checks passed\n");
    return failures != 0;
}
