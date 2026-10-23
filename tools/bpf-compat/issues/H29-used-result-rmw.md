# H29: BPF atomic RMW returns the wrong old value

Family H29 (backlog C01, C03). Register: `llvm-used-result-rmw`.
Provenance: `fixtures/bpf/atomic-rmw/provenance.json`.

## Trigger

Any BPF program that uses the result of an `atomicrmw add/sub/and/or/xor`
on 32 bits, or `add/sub` on 64 bits, compiled by LLVM 21+ (observed on
21.1.8, pristine 23.1.2, and the Rust LLVM 22.1.4 path). Minimal IR:

```llvm
%old = atomicrmw add ptr %cell, i32 13 monotonic, align 4
```

## Defect

The stored value is correct and the verifier accepts the program, but the
returned old value is wrong. Seven live-result cases fail: 32-bit
add/sub/and/or/xor and 64-bit add/sub. Unused-result cases, the chosen
64-bit bitwise cases and CAS hit/miss controls pass throughout, so a
stored-value-only oracle cannot see the bug: old and new must be checked
separately (e.g. initial 7, operand 3: old must be 7 and stored 10).

## Evidence pins

- Upstream issue llvm/llvm-project#210280; fix PR #210371, head
  `2554c9fc`; merged as `9d18ac3e` (research observed 2026-10-13).
- Oracle: 28 kernel-oracle cases (op x width x live/dead plus CAS and
  load controls), each an owned unattached socket filter run once with
  `BPF_PROG_TEST_RUN` on kernel 7.0.0-31-generic, x86-64, stack memory.
- Matrix: LLVM 18.1.8/v3 24/24 compiled pass; 21.1.8/v3 17/24;
  21.1.8/v4 21/28; pristine 23.1.2 same 17/24 and 21/28; patched
  23.1.2 24/24 and 28/28. Upstream `atomics_mem_order_v3.ll` checks
  fail on the old backend and pass on the patched one.

## Tier limits

Stack-memory single-run checks only. No concurrent-update, memory-ordering
or performance claim; those are separate TC07 live schedules. The product
decision that consumed this work (parked, CAS-only rule) is product
history, not a ScopeBase gate.

## Removal rule

The `llvm-used-result-rmw` record expires only after H29 old/new controls
pass on the selected fixed consumer backend, the final consumer artifact
path is exercised, relevant kernel cells are bound, and downstream checks
pass. The upstream merge alone does not expire it.
