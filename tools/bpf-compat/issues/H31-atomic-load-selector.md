# H31: aligned 64-bit atomic load aborts selection on generic/v3

Family H31 (backlog C01, C02). No patch record: this issue is separate
from the H29 RMW fix, which does not repair it.
Provenance: `fixtures/bpf/atomic-load/provenance.json`.

## Trigger

Minimal IR, compiled for `generic` or `v3`:

```llvm
target triple = "bpfel"
define i64 @f(ptr align 8 %p) {
  %v = load atomic i64, ptr %p monotonic, align 8
  ret i64 %v
}
```

`llc -mtriple=bpfel -mcpu=v3 -O2` aborts with
`Cannot select ... AtomicLoad`. Equivalent C via `__atomic_load_n` with
`__ATOMIC_RELAXED` fails the same way at machine-code generation (IR
emission succeeds). No application, map, header or kernel interaction is
involved.

## Defect

Observed on LLVM 18.1.8 (all CPUs), 21.1.8 (generic/v3), pristine 23.1.2
(generic/v3) and Rust LLVM 22.1.4 through bpf-linker 0.10.4. v4 lowers
the load to an ordinary u64 load. The relaxed-load pattern sits inside
the `BPFHasLoadAcqStoreRel` predicate, so disabling the acquire/release
feature on v4 also removes the plain load: feature subtraction is not a
repair. Source hypothesis only (inspected `BPFInstrInfo.td` /
`BPFSubtarget.cpp` at `977f9154`); no semantic weakening is requested.

## Tier limits

Compiler-only: failing code never reaches the verifier, so no verifier
or runtime failure is claimed. The upstream report is a local draft;
nothing was submitted. Related but distinct: #210280 (RMW old value),
#57595 (older atomic-selection crash).

## Oracle rule (TC04)

Expectation tables must distinguish three outcomes per feature mask:
compile refusal, ordinary u64 load, acquire load. A successful ordinary
load must never be labeled an acquire-opcode kernel requirement, and a
compiler failure must never be classified as a verifier rejection.
