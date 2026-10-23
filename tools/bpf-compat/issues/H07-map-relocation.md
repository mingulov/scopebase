# H07: exact-definition map relocation

Family H07 (backlog C04, B05, B06). Register: `aya-obj-map-relocation`.
Provenance: `fixtures/bpf/object-graph/provenance.json`.

## Rule

Compiler-emitted local section-symbol relocations resolve the exact map
definition at the referenced section offset:

- two definitions at distinct offsets resolve two distinct sentinels;
- interior, ambiguous, missing or signed-confused references refuse.

A forced same-FD alias is the bad control and must fail per-map identity
assertions. Correct section-symbol-plus-addend emission is loader
behavior; it must not be mislabeled an LLVM bug.

## Scope

TC01 records register-level provenance only (patch identity, preimage
hashes, scope, tests). Emitted/translated-image checks are TC05 work;
loaded-map-ID checks need an advertised loader backend (BP10/BP11).
No patch is removed on a merged PR or version bump alone: removal
needs the same minimized bad/valid controls on the replacement path
plus the relevant kernel cells and downstream checks.
