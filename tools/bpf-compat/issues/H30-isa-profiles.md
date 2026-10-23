# H30: explicit ISA admission, not CPU-preset names

Family H30 (backlog C02). No patch record: admission is an explicit
effective-CPU/feature contract (TC03), not a workaround.
Provenance: `fixtures/bpf/isa/provenance.json`.

## Lesson

BPF `v4` is a compiler preset whose meaning expanded across LLVM
releases; it is not a kernel promise:

- LLVM 18 v4 (original bundle): signed loads/moves, byte swapping,
  signed division/remainder, long direct jumps, immediate stores.
- Acquire/release loads/stores joined later; x86 indirect jumps first
  enter Linux 6.19 (`493d9e0d6083`).
- Linux 6.9 implements the original bundle only, so unrestricted
  LLVM 23 v4 output is not 6.9-compatible.

Kernel boundaries (6.9 / 6.15 / 6.19) are pinned source/ancestry
observations, not runtime qualification: the donor runtime matrix ran
on one host only. An LLVM upgrade must never silently raise an
advertised old-kernel requirement.

## Contract rule (TC03)

Every advertised ISA family needs a minimal emitted fixture with its
exact expected encoding class. Empty CPU, `generic`, `v3` and
feature-masked `v4` are independently recorded effective inputs;
preset drift (a preset silently broadening a profile) and
forbidden-opcode mutants must fail admission even when the compiler
exits zero. Final opcodes, not release strings, control support.
