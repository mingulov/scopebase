# H32: mixed Rust/C debug metadata must survive every link pass

Family H32 (backlog C04). Register: `bpf-linker-debug-records`.
Provenance: `fixtures/bpf/metadata/provenance.json`.

## Trigger

Full p11scope `build.rs` pipeline: Rust + native BPF objects linked by
bpf-linker 0.11.1 with private LLVM 23.1.2 + PR 210371, assertions
enabled. Detailed-object codegen aborts on LLVM's internal
`Expected inlined-at fields to agree` in `SelectionDAG::getDbgValueList`.

## Defect

Exact-input replays isolate a linker defect, not an LLVM regression:
the merged input IR has no mismatched scopes and compiles directly
with debug data intact. After the linker's debug sanitation and
optimization, ten debug assignment records in one function refer to
inconsistent old/new subprogram scopes: the sanitizer replaces the
subprogram for static BTF linkage but does not traverse the new LLVM
23 debug records. The private repair (commit `4727b15` on bpf-linker
`24ccdfd`) preserves variable/label scopes, uses typed subprogram
accessors, and verifies the live module after linking, sanitation and
optimization. Repaired pipeline: Detailed (22 maps/13 programs) and
Inventory (13 maps/12 programs) both build with nonempty
DWARF/BTF/BTF.ext and no linker diagnostics.

## Exit-zero lesson

A parser-based replay can return success while LLVM diagnoses invalid
debug info and discards it, yielding an object without `.BTF` /
`.BTF.ext`. Qualification must therefore verify the in-memory module
immediately after sanitization, fail on debug diagnostics, and inspect
emitted BTF as well as the exit status. Preserved final objects:
Detailed `1b09dfcd…51999`, Inventory `341b9cc0…0ff75`.

## Removal rule

The `bpf-linker-debug-records` record expires only after the selected
replacement linker path reproduces the retained-metadata controls,
the unrepaired RED matrix still fails, and downstream checks pass.
Host-binary, kernel/capture, supported-kernel and performance gates
remain open regardless.
