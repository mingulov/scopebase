# SB02 dependency experiments

These unpublished `sb02-*` crates test the exact public APIs selected by the ratified SB02 packet. They are not ScopeBase libraries, donor ports, delivered conformance packages, or runtime qualification. Each crate is an independent edition-2021 workspace declaring Rust 1.88.0. The matrix fixes both 1.88.0 and 1.98.1; compiler installation and BPF operations are excluded.

The matrix's `features` and `default_features` describe the named candidate dependency. Its manifest supplies those dependency features directly; they are not features on the test-only probe package. Other direct dependencies are explicit: procfs-parsers uses procfs-core and the same exact rustix for `OFlags`, serde-json uses serde with derive, and aya-btf uses the same exact object for the public `Endianness` argument. Their resolved unions must be recorded separately from each direct declaration.

| Case | Fixed positive evidence | Sensitive control or observed gap |
|---|---|---|
| rustix-fs | Owned `abcdefgh`, cursor 5, pread offset 2 gives `cde` without cursor movement; raw path, descriptor/status flags, fstat parity, EOF/error | Cursor-relative read gives `fgh` and cursor 8, which fails the same positional assertion |
| rustix-process | Uncalled typed pidfd function | Compile evidence only; no process or identity claim |
| nix-fs | Same owned file/descriptor observations; checked signed offset at MAX/MAX+1 | Cursor-relative read and wrapping cast fail their named semantic assertions before any out-of-range syscall |
| object-elf | Independently encoded ELF32/ELF64 PT_LOAD layout; malformed/truncated header twins | Valid non-executable segment fails the RX assertion; symbol/section/relocation methods are type-checked on intentionally empty tables |
| goblin-elf | Same independent bytes through a separate dependency/workspace | Same RX control; public symbol/relocation fields are type-checked on empty tables |
| procfs-parsers | Fixed maps/mount records and literal expected identities; raw bytes, permissions, reverse/overlap, escapes/deleted suffix, duplicate ID and N/N+1 observations | Each strictness mismatch has a valid parse before its stronger contract assertion fails; no strict parser is implemented |
| btf-rs | Literal base IDs 1/2 named `dup`, ID3 pointer to ID1; split ID4 and distinct name; truncated header/invalid ID | Collapsing rival IDs and reusing a base-domain ID fail their named assertions; chain iteration is capped at 4 |
| aya-host | Uncalled loader/map/program/ring/uprobe functions | Compile evidence only; no syscall/load/attach/ring behavior claim |
| aya-btf | Fixed bounded base BTF parse and public name/kind query | Rival-name first-match observation; separate private-method E0624 crate must fail only after this public positive compiles |
| serde-json | Fixed integers above 2^53 and u64 MAX; derive exact JSON literal; overflow/bool/negative refusal | f64 conversion loses the literal unit; generic Value accepts last-wins duplicate members, a strict-replay gap |

All ELF and BTF vectors are independently authored from their standard header/type layouts; they are not donor fixtures or parser output. File and procfs inputs are literal owned bytes. Expected numbers, IDs, names, flags and cursor positions are fixed independently of the candidate parser. Wrong controls use a caught assertion panic after setup succeeds; unrelated setup failures are not caught and cannot pass a control.

The `aya-btf-private` crate deliberately fails compilation on `Btf::type_by_id`. It is a separate workspace, not an automatic member of any positive probe. Its expected diagnostic is E0624 naming `type_by_id`; resolver, lock, source, feature or dependency compilation failure is not that result.

`dependency-probes.json` binds private immutable input inventories and explicit reviewed execution approvals. Inventory enumeration records available bytes and does not grant build permission. Run the actual policy tool under `bin/scopebase-build` with private fresh output/Cargo/target roots. Preparation, source inspection, lock generation and vendoring are not probe results. See the job's private report for executed scope and missing rows; no result is asserted here.

Original donor regressions remain NOT_RUN here. LX02–LX05 own held-file/maps/mount/offset preservation and real filesystem cells; BP05/BP06/BP10 own backend fixes and retirement; BP09 owns BTF domains/bounds and the original corpus; CP10 owns strict replay. BTF/parser limits, kernel behavior, Btrfs/overlay/namespaces, installed consumers and package readiness are not inferred from these tiny vectors.
