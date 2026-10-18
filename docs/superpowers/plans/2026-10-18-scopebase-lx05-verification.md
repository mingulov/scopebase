# LX05 strict bounded proc parsers verification and implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans with the controller-selected execution method. Steps use checkbox (`- [ ]`) syntax for tracking. The controller supplies the separately frozen implementation dispatch.

**Goal:** Implement the reviewed raw-byte maps/mountinfo observations and prove the bounded increment through original regressions, independent oracles, semantic controls and actual package consumers.

**Architecture:** Adapt the 15 selected P source ranges, preserving every selected original regression. Add only the three named missing seams: bounded fixed arenas/accounting, complete raw mountinfo grammar and borrowed table-instance provenance. Keep 16 source ranges reference-only and all runtime identity/acquisition/proof work with later owners.

**Tech Stack:** Rust 2021, MSRV 1.88.0/current 1.98.1, x86_64-unknown-linux-gnu, std plus unchanged admitted rustix 1.1.5 std/fs/pipe; Python 3.11+ package helper. Actual libFuzzer tooling has a separate unclosed admission prerequisite.

**Spec:** [Frozen successor contract](../specs/2026-10-18-scopebase-lx05-proc-contract.md). Intended canonical destination: `docs/superpowers/plans/2026-10-18-scopebase-lx05-verification.md`. Status: normative controller-adopted verification plan, 2026-10-18; product checks NOT_RUN and LX05 NOT_ACCEPTED.

## Global constraints

- Preserve the two exact parser signatures, complete public surface, nominal identity domains, private layout, features, grammar and eight-phase error/charge order in the contract. No parser observation becomes runtime authority.
- No runtime dependency or feature change, BPF toolchain, privilege/proc read, sysctl/limit/credential/namespace/signal change, file owner, backing-file resolution, process acquisition or calibration.
- Source origins, hashes, lines, history/WIP mappings, grant recommendations and reference-only boundaries are frozen in source-selection.json. Source admission is a separate root artifact. O-S27 remains reference-only; its new population is independently authored.
- Preserve 13 selected original P correspondences, 10 deferred/reference originals and 11 new groups. A1–A3 are subcases/controls, not new H/UC/G IDs or new canonical tasks. Required unavailable checks remain incomplete.
- Six affected Linux package cells, twelve distinct parser-client/compiler/configuration cells each exercised against source and archive (24 client executions), and two actual libFuzzer campaigns of 10,000 engine runs each remain required. No full 20 or full runtime profile claim follows.
- Use the controller-bound absolute wrapper `/home/user/src/m/bpfscope/.scopebase/controller/build-routing-20261018/scopebase-build` for local compiler launches, including private HOME; the package helper itself has no repository-wrapper dependency.

## Review focus

1. Octal values outside the old four-value whitelist must parse; exactly three digits and one decoding pass preserve opaque bytes and reject NUL/out-of-byte/truncated forms (Task2/A1).
2. Three equal IDs or multiple duplicate groups must yield the specified original input row without reordering records (Task2/A2).
3. A valid row prefix followed by malformed input must never produce partial success; O's original literals stay unselected (Task2/A3).
4. A syntactically complete LF prefix, equal maps tuple or table-local ParsedMountId must never acquire acquisition completeness, namespace identity or file/process authority (Tasks1–3).
5. Capacity overgrant, refusal after work and archive-normalized test target changes must retain charges and run the intended delivered tests against the actual subject version/features/lock (Tasks3–5).

## File and interface ownership

The exact paths, source-to-destination map, shared-file serialization and root-only edits are in `.scopebase/controller/lx05-final-packet-20261018/packet.md` and `.scopebase/controller/lx05-final-packet-20261018/source-map.md`. Task1 owns fixture/oracle/UI/test sources; Task2 adds A1–A3 populations within those same sources; Task3 owns procfs implementation and the root-assigned mechanical exports/error/identity edits; Task4 owns the package-local helper and independent consumers; Task5 owns receipts in private outputs; Task6 owns the separately admitted fuzz project. One LX05 writer performs the dependent sequence. Root retains shared ledgers, grants, policy inventory and canonical documents.

## Task 1: Preserve all thirteen original regressions

**Files:** Create `crates/scopebase-linux/tests/proc_parsers.rs`, `tests/support/proc_reference.rs`, literal `tests/fixtures/procfs/*` and the declared `tests/ui/proc_*.rs` cases. Do not copy any O source/test/vector.

**Interfaces:** Consume only the API in contract.md and exact P source slices in source-selection.json. Produce public tests and an independently authored reference returning plain facts/error expectations; it never calls a production parser, serializer, lookup helper or native owner constructor.

- [ ] Copy/adapt every selected original population, including every malformed vector and endpoint. Keep a literal sorted version of P's five-row fixture and its original unsorted sequence as refusal. Append LF to nonempty line-level vectors; the original empty-line vector becomes LF-only malformed while empty byte input remains valid absence.
- [ ] Write literal expected scalar/path/address tables before implementation. u128 arithmetic determines decimal/hex overflow and `offset+(address-start)` independently; a linear interval scan checks containing. O(E²) pair checks detect overlap/duplicate facts without production sorting or indexing.
- [ ] Run the new target with an admitted compiler/offline closure in an owned target directory to establish the missing API/behavior baseline. Missing API failure is labeled preimplementation evidence, never a semantic mutant kill.

Each row below is mandatory and retains its later owner/support limit from preservation-map.json.

### Original 1: `parses_entries_and_preserves_path_bytes`

Source: `P:crates/manifest/src/maps.rs:329`. Destination: `crates/scopebase-linux/tests/proc_parsers.rs::ported_parses_entries_and_preserves_path_bytes`.

- [ ] Assert: All original five entries and their exact scalar/path values survive. Sorted literal input is used; unsorted original order is separately refused.
- [ ] Independent expected result: Literal numeric/path table independent of parser; raw byte equality including trailing suffix.
- [ ] Valid twin: Original valid sorted five-row fixture; no spaces/nonUTF8 removal.
- [ ] Compiling bad-production control: Replace raw path remainder with split_whitespace/join or lossy UTF8; intended raw equality fails. Require the intended assertion to fail after valid setup; then restored identical candidate bytes pass.

### Original 2: `resolves_with_segment_offset_arithmetic`

Source: `P:crates/manifest/src/maps.rs:357`. Destination: `crates/scopebase-linux/tests/proc_parsers.rs::ported_resolves_with_segment_offset_arithmetic`.

- [ ] Assert: 0x7f2b40000abc -> offset 0x21abc; 0x400010 -> 0x10, with original row key/perms/path.
- [ ] Independent expected result: Literal expected offsets and independent u128 offset + address - start equation.
- [ ] Valid twin: Both original addresses with original offsets; unchanged production restored afterward.
- [ ] Compiling bad-production control: Return address-start only, ignoring nonzero segment offset; offset semantic assertion fails. Require the intended assertion to fail after valid setup; then restored identical candidate bytes pass.

### Original 3: `classifies_anonymous_and_unmapped`

Source: `P:crates/manifest/src/maps.rs:384`. Destination: `crates/scopebase-linux/tests/proc_parsers.rs::ported_classifies_anonymous_and_unmapped`.

- [ ] Assert: Anonymous missing path and stack path remain distinct data; gap and exclusive end are None. No backing-file classification authority.
- [ ] Independent expected result: Literal expected path_kind/raw bytes and inclusive-start/exclusive-end predicate.
- [ ] Valid twin: Both original anonymous/pseudo rows and address inside each.
- [ ] Compiling bad-production control: Containing uses <= end; gap/exclusive-end semantic assertion fails. Require the intended assertion to fail after valid setup; then restored identical candidate bytes pass.

### Original 4: `unusable_file_paths_remain_file_evidence`

Source: `P:crates/manifest/src/maps.rs:393`. Destination: `crates/scopebase-linux/tests/proc_parsers.rs::ported_unusable_file_paths_remain_file_evidence`.

- [ ] Assert: All three original nonUTF8, literal \012, deleted-suffix rows retain absolute path evidence and original raw bytes; no false openable path.
- [ ] Independent expected result: Literal byte vectors and independent marker/suffix classification.
- [ ] Valid twin: Each original troublesome path accepted as descriptive data.
- [ ] Compiling bad-production control: Drop or lossy-convert unusable path; raw/flag assertion fails after all three rows parse. Require the intended assertion to fail after valid setup; then restored identical candidate bytes pass.

### Original 5: `malformed_nonempty_line_is_rejected`

Source: `P:crates/manifest/src/maps.rs:417`. Destination: `crates/scopebase-linux/tests/proc_parsers.rs::ported_malformed_nonempty_line_is_rejected`.

- [ ] Assert: Malformed row refuses ParseMaps/Malformed and never becomes empty/partial success. Preserve original location assertion via LinuxError::parse_line()==Some(1); a valid first row followed by bad row reports Some(2).
- [ ] Independent expected result: Literal malformed line plus valid row concatenation; expected error classified structurally.
- [ ] Valid twin: One actual complete valid row with same limits.
- [ ] Compiling bad-production control: Skip malformed line then return snapshot; refusal assertion fails. Require the intended assertion to fail after valid setup; then restored identical candidate bytes pass.

### Original 6: `map_index_requires_sorted_non_overlapping_intervals`

Source: `P:crates/manifest/src/maps.rs:429`. Destination: `crates/scopebase-linux/tests/proc_parsers.rs::ported_map_index_requires_sorted_non_overlapping_intervals`.

- [ ] Assert: Retain swap, overlap, descending disjoint, equal-start, zero/reverse range cases. Parse refuses globally.
- [ ] Independent expected result: Independently enumerate all interval pairs and compare u128 endpoints; never production sort/re-serialize.
- [ ] Valid twin: Original sorted disjoint intervals, exact adjacency and each valid single row.
- [ ] Compiling bad-production control: Remove previous_end > start guard; overlap must parse and fail explicit is_err assertion, not crash. Require the intended assertion to fail after valid setup; then restored identical candidate bytes pass.

### Original 7: `invalid_snapshot_is_distinguishable_from_valid_absence`

Source: `P:crates/manifest/src/maps.rs:502`. Destination: `crates/scopebase-linux/tests/proc_parsers.rs::ported_invalid_snapshot_is_distinguishable_from_valid_absence`.

- [ ] Assert: Invalid later overlap refuses whole snapshot independent of lookup address; valid gap stays None.
- [ ] Independent expected result: Same literal prefix plus valid/overlap final row, explicit expected whole-input refusal.
- [ ] Valid twin: Original valid file+anonymous rows with known file hit and 0x9000 gap.
- [ ] Compiling bad-production control: Validate only matching row during lookup; invalid snapshot returns value/absence and fails refusal. Require the intended assertion to fail after valid setup; then restored identical candidate bytes pass.

### Original 8: `map_index_rejects_file_offset_overflow`

Source: `P:crates/manifest/src/maps.rs:549`. Destination: `crates/scopebase-linux/tests/proc_parsers.rs::ported_map_index_rejects_file_offset_overflow`.

- [ ] Assert: Two-byte range with offset MAX refuses; MAX-1 accepts and last-byte offset is MAX; single-byte offset MAX accepts.
- [ ] Independent expected result: u128 arithmetic with explicit <=u64::MAX inequality.
- [ ] Valid twin: Original MAX-1 twin plus added one-byte MAX boundary.
- [ ] Compiling bad-production control: Use wrapping_add or omit validation; overflow refusal assertion fails. Require the intended assertion to fail after valid setup; then restored identical candidate bytes pass.

### Original 9: `map_index_resolves_gaps_adjacency_and_exclusive_ends`

Source: `P:crates/manifest/src/maps.rs:579`. Destination: `crates/scopebase-linux/tests/proc_parsers.rs::ported_map_index_resolves_gaps_adjacency_and_exclusive_ends`.

- [ ] Assert: Original 0x1000/0x1fff/0x2000/0x3000/0x3fff/0x4000/0x5000 outcomes retained.
- [ ] Independent expected result: Literal address-to-row/None table and O(N) interval reference.
- [ ] Valid twin: Every original hit plus adjacent start; unchanged control restoration.
- [ ] Compiling bad-production control: Binary-search fencepost uses preceding entry or inclusive end; address table assertion fails. Require the intended assertion to fail after valid setup; then restored identical candidate bytes pass.

### Original 10: `probed_maps_line_parses_hex_devices_and_decimal_inodes`

Source: `P:crates/manifest/src/identity.rs:992`. Destination: `crates/scopebase-linux/tests/proc_parsers.rs::ported_probed_maps_line_parses_hex_devices_and_decimal_inodes`.

- [ ] Assert: 00:15 -> (0,21), 0A:fF -> (10,255), decimal inode 712355/42; fields stay maps domain.
- [ ] Independent expected result: Literal expected components, independently generated byte strings.
- [ ] Valid twin: Original lower/uppercase device rows and expected exact tuples.
- [ ] Compiling bad-production control: Packed stat-style device cast returns major=(major<<8)|minor,minor=0; semantic key component assertion fails. Require the intended assertion to fail after valid setup; then restored identical candidate bytes pass.

### Original 11: `probed_maps_line_matches_only_its_own_range`

Source: `P:crates/manifest/src/identity.rs:1020`. Destination: `crates/scopebase-linux/tests/proc_parsers.rs::ported_probed_maps_line_matches_only_its_own_range`.

- [ ] Assert: Original start,last,end,before,after addresses retained as containing result.
- [ ] Independent expected result: Literal original table; separate linear predicate.
- [ ] Valid twin: 0x1000 and 0x1fff exact original positive hits.
- [ ] Compiling bad-production control: End inclusive comparator; assertion at 0x2000 fails. Require the intended assertion to fail after valid setup; then restored identical candidate bytes pass.

### Original 12: `malformed_probed_maps_lines_fail_closed`

Source: `P:crates/manifest/src/identity.rs:1037`. Destination: `crates/scopebase-linux/tests/proc_parsers.rs::ported_malformed_probed_maps_lines_fail_closed`.

- [ ] Assert: Retain every original empty/short/range/device/numeric/inode-overflow vector; append LF to nonempty line vectors for complete-snapshot API. Empty donor line becomes b"\n" malformed; b"" separately remains valid absence.
- [ ] Independent expected result: Explicit literal invalid vector list, u128 independent conversion, no production-generated expected data.
- [ ] Valid twin: Clean 1000-2000 row for each mutated field; bytes/spec constraints recorded.
- [ ] Compiling bad-production control: Numeric parse uses unwrap_or(0) or accepts signs; corresponding malformed refusal fails semantically. Require the intended assertion to fail after valid setup; then restored identical candidate bytes pass.

### Original 13: `retained_process_view_mount_table_controls_the_mapping_device`

Source: `P:crates/manifest/src/identity.rs:675`. Destination: `crates/scopebase-linux/tests/proc_parsers.rs::table_local_numbers_preserve_device`.

- [ ] Assert: Pure tables A/B with equal raw id 17 and differing decimal devices preserve their own row/device; ParsedMountId equality differs across tables, same-table clones equal. Missing raw id returns None only on valid table.
- [ ] Independent expected result: Literal A=17 1 8:1 / /a rw - ext4 /dev/a rw; B=17 1 9:2 / /b rw - ext4 /dev/b rw; independent tuple map.
- [ ] Valid twin: Same A table/same number equal; both A/B rows parse and return their own device.
- [ ] Compiling bad-production control: Compare ParsedMountId by number alone; A.id != B.id assertion fails after both tables parse. Require the intended assertion to fail after valid setup; then restored identical candidate bytes pass.

## Task 2: Eleven required new groups and the three reviewed amendments

**Files:** Same public/private regression and oracle fixtures as Task1, plus `crates/scopebase-linux/src/procfs/tests.rs` for private allocation injection after Task3 exists.

**Interfaces:** Consume contract.md's exact limits/grammar/error accounting and Task1's independent fact representation. Produce the following eleven groups; A1/A2 are subcases of groups4/6, A3 is a reference-counterexample subcase. There is no fourteenth selected P regression.

### New group 1: `limits_exact_boundaries`

Target: `crates/scopebase-linux/tests/proc_parsers.rs::limits_exact_boundaries`.

- [ ] Assert: B/B+1 input, N/N+1 rows, L/L+1 line; zero configurations refuse before scan/allocation; L excludes LF; final LF does not create row; usize MAX comparisons never overflow
- [ ] Positive twin and exact setup: Use one literal valid row and independently counted B=input.len(), N=1, L=row.len()-1. Limits(B,1,L) succeeds; change only B-1/N admission with a second valid row/L-1 for refusal. Test each zero field with otherwise valid limits; admitted empty bytes allocates nothing. Checked arithmetic/private request overflow is injected without huge allocations.
- [ ] Sensitive control: Remove one admission guard; error category assertion fails; exact boundary twin passes

### New group 2: `complete_absence_and_unterminated_are_distinct`

Target: `crates/scopebase-linux/tests/proc_parsers.rs::complete_absence_and_unterminated_are_distinct`.

- [ ] Assert: empty bytes success; LF/blank/whitespace row malformed; valid final LF success; remove final LF malformed; complete LF prefix does not claim acquisition completeness
- [ ] Positive twin and exact setup: b"" succeeds with zero entries; one complete valid row ending LF succeeds; the same row minus only its last LF refuses. b"\n", SP+LF, HT+LF, an interior blank and a raw NUL refuse; complete LF-only prefixes remain descriptive.
- [ ] Sensitive control: Permit unterminated input or skip blank; intended refusal fails

### New group 3: `numeric_grammar_and_full_range_overflow`

Target: `crates/scopebase-linux/tests/proc_parsers.rs::numeric_grammar_and_full_range_overflow`.

- [ ] Assert: u64 MAX/MAX+1 all numeric domains, +,-,0x rejected; zero mount/group IDs refuse; leading zeros accepted and duplicate alias caught; nonabsolute maps row offset overflow also refuses
- [ ] Positive twin and exact setup: Independent literal MAX in each allowed u64 field is representable where other predicates permit; MAX+1 refuses. Mount/group positive 1 versus zero 0, maps device/inode zero allowed, leading-zero unique numbers accepted, adjacency and one-byte MAX offset accepted. Apply +, -,0x, empty/bad digits one field at a time; nonabsolute maps two-byte MAX offset refuses.
- [ ] Sensitive control: Accept + or wrap multiplication; intended refusal fails; MAX/leading-zero twins pass

### New group 4: `mount_escapes_are_single_pass_raw_and_decoded`

Target: `crates/scopebase-linux/tests/proc_parsers.rs::mount_escapes_are_single_pass_raw_and_decoded`.

- [ ] Assert: Every textual field preserves raw/decoded opaque bytes. Decode exactly three octal digits 001..377 once; 040/011/012/134/043/054/075 and 001/377 valid; 000/400/777/099/04/bare-backslash refuse at correct row. A fourth digit stays ordinary; 134040 and 134043 remain literal backslash sequences after one decode. NonUTF8/parentheses/spaces and deleted text retained; decoded comma/equals never split options.
- [ ] Positive twin and exact setup: The exact A1 valid rows and boundary spellings below pass with literal raw/decoded expected bytes. Use the same valid surrounding fields for each malformed spelling and each textual-slot substitution.
- [ ] Sensitive control: Four-only whitelist fails valid 043/054 acceptance; double decoder fails exact literal backslash043 output; permissive malformed escape accepts 000/400/777/099/04/bare backslash and fails refusal; every mutant compiles after valid setup, and restored twin passes.

### New group 5: `mount_optional_known_unknown_and_fixed_tail`

Target: `crates/scopebase-linux/tests/proc_parsers.rs::mount_optional_known_unknown_and_fixed_tail`.

- [ ] Assert: shared/master/propagate_from/unbindable; malformed or duplicate known fields refuse; unknown key/value preserved; missing/extra fixed fields refuse; source - valid; source nonempty; parent absent/self valid
- [ ] Positive twin and exact setup: One valid row for each Shared(1),Master(2),PropagateFrom(3),Unbindable and coexistence; unknown nonUTF8/colon/escaped-whitespace tokens and duplicate unknowns retained in order. Source -/none, absent/self parent pass. Mutate only known value/duplicate kind or fixed token count for refusal; decode normalization aliases count as duplicate known kinds.
- [ ] Sensitive control: Silently ignore invalid known field or reject every unknown; exact classification assertion fails

### New group 6: `mount_duplicate_ids_and_input_order`

Target: `crates/scopebase-linux/tests/proc_parsers.rs::mount_duplicate_ids_and_input_order`.

- [ ] Assert: Unsorted unique IDs accepted in original order. Duplicate numeric IDs including leading-zero aliases refuse. Sort index by (number,original_zero_based_row); select lowest duplicated number, then second-earliest original row: 9,17,017,9 => parse_line Some(4), entries_validated 4; 17,2,017,3,0017 => Some(3), entries_validated 5. Lookup compares numeric component only.
- [ ] Positive twin and exact setup: Unique A2 twins [9,17,18,10] and [17,2,18,3,19] preserve that exact order, return each numeric lookup, and return None for 0/missing. Duplicated A2 arrays below refuse after every valid row counts.
- [ ] Sensitive control: Duplicate acceptance fails whole-table refusal; first-original-row diagnostic mutant fails exact location assertion separately. Unique twins 9,17,18,10 and 17,2,18,3,19 parse, preserve input order and exact lookup.

### New group 7: `maps_path_evidence_is_not_resolution`

Target: `crates/scopebase-linux/tests/proc_parsers.rs::maps_path_evidence_is_not_resolution`.

- [ ] Assert: trailing spaces/CR, raw HT, no path, brackets, relative, literal \999, literal (deleted), invalid UTF8 retained; only four-byte \012 marker flags ambiguity
- [ ] Positive twin and exact setup: Absolute, absent, bracket and relative raw suffixes are literal independent byte fixtures; exact trailing SP/HT/CR and high byte 255 survive. Only the four-byte backslash012 marker and exact terminal SP(deleted) set those flags, without stripping/resolution.
- [ ] Sensitive control: Strip suffix/unescape or trim trailing path bytes; exact evidence assertion fails

### New group 8: `parse_capacity_and_allocation_accounting`

Target: `crates/scopebase-linux/src/procfs/tests.rs::parse_capacity_and_allocation_accounting`.

- [ ] Assert: private seam: every reserve position fails Allocation with exact prior charges; capacity overgrant refuses BufferCapacity with actual charged peak; no retry; no partial snapshot; all old errors parse None
- [ ] Positive twin and exact setup: Valid single-row maps/mount inputs require respectively 2/4 successful reservations and no hidden publication allocation; empty/shape refusal makes 0. Inject failure at every position and overgrant immediately after each success, preserve the charged historical peak/attempt, refuse before the next reserve/copy and restore the successful seam.
- [ ] Sensitive control: Refund charges or retry reserve; historical peak/attempt assertion fails

### New group 9: `all_parser_errors_are_effect_free_and_bounded`

Target: `crates/scopebase-linux/tests/proc_parsers.rs::all_parser_errors_are_effect_free_and_bounded`.

- [ ] Assert: every error stage/reason/source/effects/parse charges; <=256 ASCII diagnostics including malicious raw bytes; no payload leakage
- [ ] Positive twin and exact setup: A well-formed valid row succeeds first. For each named refused population assert stage/reason/source None, zero operation/syscall/FD/mapping counters, NotNeeded/NotAttempted, read None, parse Some, expected line and validated prefix. Inspect default/alternate Debug and Display <=256 printable ASCII bytes with independent malicious-byte canaries absent.
- [ ] Sensitive control: Format raw path or source input; ASCII/bound assertion fails

### New group 10: `parser_public_domain_and_ownership_refusals`

Target: `crates/scopebase-linux/tests/proc_parsers.rs::parser_public_domain_and_ownership_refusals`.

- [ ] Assert: downstream UI: MapsFileKey vs StatFileKey Eq/From absent, ParsedMountId vs numeric/mount runtime ID absent, fields private, no owner conversion, no ParseLimits Default, borrowed view cannot outlive snapshot
- [ ] Positive twin and exact setup: The ordinary public positive client compiles/runs. Each one-change UI negative reaches its exact operation diagnostic; an owned forbidden-API mutant makes that negative unexpectedly compile, and restoring candidate bytes restores refusal. Do not import unimplemented future MountId types merely to obtain an unresolved-import error.
- [ ] Sensitive control: Add forbidden From<StatFileKey> or public field in owned control; exact downstream refusal becomes successful compile; ordinary positive client still runs

### New group 11: `reference_population_generated_independently`

Target: `crates/scopebase-linux/tests/proc_parsers.rs::reference_population_generated_independently`.

- [ ] Assert: checked-in positive and active-negative literal cases; independent u128 numeric/linear pair interval/quadratic duplicate/escape table oracle; no production reserialization
- [ ] Positive twin and exact setup: Literal valid disjoint rows [1000,1800),[1800,2400),[2400,2800), keys(11,2,91) and known address offsets pass. Overlap/default-zero/flattened-device wrong-production variants compile, reach and fail the named reference assertion, then restored bytes pass.
- [ ] Sensitive control: Overlap and device-domain production mutants fail named semantic assertions after valid setup

### A1: Exact octal-byte populations and oracle

In this section, code blocks show literal input bytes with one LF after each displayed row. `\043` in prose refers to a single backslash followed by ASCII043; do not double the backslash in the actual binary fixture. Every case first uses limits `{max_bytes:4096,max_entries:64,max_line_bytes:512}`. Its expected result is handwritten independently of production parsing.

```text
17 1 0:42 / /mnt rw - fuse.demo\043tag source\043tag rw
18 1 0:43 / /merged rw - overlay overlay rw,lowerdir=/lower\054part
19 1 0:44 / /mnt rw - tmpfs none rw,key\075part=value
```

- [ ] Row17: filesystem raw `fuse.demo\043tag`, decoded `fuse.demo#tag`; source raw `source\043tag`, decoded `source#tag`; every other scalar/text fact matches its literal expected value.
- [ ] Row18: super-options raw `rw,lowerdir=/lower\054part`, decoded exactly `rw,lowerdir=/lower,part`, returned as one opaque field. No decoded-comma option split occurs.
- [ ] Row19: super-options raw `rw,key\075part=value`, decoded exactly `rw,key=part=value`, returned as one opaque field. These three rows are source-derived emitter counterexamples, not live FUSE/overlay mount receipts.
- [ ] Independently author a slot-substitution table for root, point, mount_options, each optional token, filesystem, source and super_options. Root/point retain a leading `/`; unknown optional tokens use an `x:` prefix so decoded known-tag policy does not mask the escape assertion. Each slot accepts `\001`, `\011`, `\012`, `\040`, `\043`, `\054`, `\075`, `\134`, `\377`; assert exact raw/decoded byte slices, including nonUTF8. Values 001/377 are grammar boundaries, not claimed kernel-emitted examples.
- [ ] Use the same source-field position in a complete valid row, ending the source token before SP: `\000`, `\400`, `\777`, `\099`, `\04` and one terminal bare backslash all give ParseMounts/Malformed at the literal row. Prefixing one valid row moves each expected parse_line from 1 to 2 and entries_validated from 0 to 1. Positive twins in the same position are `\040`, `\043`, `\054`, `\075`, `\134`, `\377`. Raw NUL in any slot is separately malformed in preflight.
- [ ] Exact single-pass source input `\134043` returns decoded bytes `[92,48,52,51]` (literal backslash043), never byte 35 (`#`). Input `\134040` returns `[92,48,52,48]`, never SP. Input `\0437` returns `[35,55]` (`#7`): the fourth digit is a following ordinary byte.
- [ ] The independent decoder consumes one backslash plus exactly three radix8 digits, computes with u16/u128 `64*d0+8*d1+d2`, accepts only 1..255 and advances past exactly those original input bytes. It never feeds decoded output back into its scanner. Raw decoded comma/equals are opaque facts.
- [ ] Run three separate compiling mutants: old four-value whitelist fails row17 or18 acceptance; recursive/double decoder fails the exact `[92,48,52,51]` assertion; permissive malformed escape fails the whole-row refusal. Valid twin and identical restored bytes pass for each. Put the same literal expectations in source tests, actual archive helper data and mountinfo fuzz seed metadata.

### A2: Exact deterministic duplicate location and independent oracle

For each token `ID` below, independently construct the literal row `ID 1 0:42 / /m rw - tmpfs none rw` followed by LF. Every row is individually valid; literal ID spelling is preserved in the fixture.

| Input ID tokens in original order | Result | parse_line | entries_validated |
|---|---|---|---|
| `9,17,017,9` | ParseMounts/Malformed | Some(4) | 4 |
| `17,2,017,3,0017` | ParseMounts/Malformed | Some(3) | 5 |
| `9,17,18,10` | success; that order retained | n/a | 4 |
| `17,2,18,3,19` | success; that order retained | n/a | 5 |

- [ ] Use pairwise numeric equality in the independent oracle, select the minimum numeric ID with at least two occurrences, enumerate its original rows in increasing order and choose its second row. Do not call production sorting or index lookup. Assert unique-twin iteration order and numeric lookups independently.
- [ ] Production sorts complete `(number,original_zero_based_row)` tuples in the existing preallocated index; records remain unchanged. The index's first adjacent equal-number pair determines the error's second original row plus1. A number-only binary comparator is used only after uniqueness succeeds.
- [ ] A first-original-row diagnostic mutant separately fails the exact Some(4)/Some(3) assertion after returning Malformed with all rows counted. A duplicate-acceptance mutant separately returns a snapshot and fails the whole-table refusal. Both unique twins and restored candidate pass. This is lowest-ID duplicate selection, not earliest duplicate event in input order.

### A3: Independently authored reference counterexample

Keep O-S27 origin/grant unchanged. Inspect its defect description only; author these exact new bytes, each row ending LF, without copying O's original literal/test body:

```text
1000-1800 r--p 0000 0b:02 91 /fixtures/alpha
1800-2400 r-xp 0800 0b:02 91 /fixtures/alpha
2400-2800 rw-p 1400 0b:02 91 /fixtures/alpha
broken
```

- [ ] The three-row prefix succeeds with len 3, permissions `r--p/r-xp/rw-p`, offsets 0/0x800/0x1400, key components 11/2/91 and exact raw path `/fixtures/alpha`. Literal addresses 0x1000/0x17ff/0x1800/0x23ff/0x2400/0x27ff return offsets 0/0x7ff/0x800/0x13ff/0x1400/0x17ff;0x2800 is None.
- [ ] Adding the fourth `broken` row yields ParseMaps/Malformed, parse_line Some(4), entries_validated 3, no snapshot and zero effects. The independent whole-input oracle requires every row to parse.
- [ ] A compiling skip-bad-row mutant returns a three-entry snapshot and fails the explicit whole-input-refusal assertion. The three-good-row positive twin and restored candidate pass. Keep this under `refuses_mixed_valid_and_malformed` in the reference-counterexample section, not the 13 P original-port list. Add its independently authored seeds to maps fuzz corpus and package fixtures with hashes/outcomes.

## Task 3: Port the parser and preserve bounds/error invariants

**Files:** `src/procfs/{mod.rs,maps.rs,mountinfo.rs,tests.rs}` and only root-assigned mechanical edits in lib.rs/error.rs/identity.rs/file/held.rs/file/read.rs/control.rs. **Produces:** the exact contract.md API. No placeholder exported API.

- [ ] Implement the eight contract phases in order: limits; no-allocation shape; checked capacity formula; exact fallible reservations/overgrant refusal; arena copy and per-slot single decode; input-order validation; complete-tuple mount index/duplicate detection; infallible publication. Adapt actual P scanner/index/offset/numeric mechanisms under the admitted ranges.
- [ ] Preserve precedence: zero configuration before byte scan; InputBytes before shape; same-row LineBytes before Entries before empty/NUL; complete shape errors before earlier lexical errors; within-limit unterminated tail malformed; overlong tail LineBytes. Every refused row's expected one-based location and entries_validated prefix is literal test data.
- [ ] Add private reserve seams testing every2/4 failure/overgrant position; no public injection callback, retry or allocating publication. Request overflow refuses BufferCapacity before reserve. Retained-capacity bounds use actual size_of on the admitted target; error charges retain actual historical peaks after temporary buffers drop.
- [ ] Existing non-parser constructors gain only parse None/parse_line None under exclusive shared ownership. Existing controls/held/read behavior and FD_TABLE test discipline remain intact. Any old private control template must compile after its required mechanical field addition before it can count as a semantic kill.
- [ ] Run focused new public/private tests, all reached original Linux all-targets/doc/trait tests, exact UI controls and compiling semantic mutants/restored twins. Store each receipt's expected assertion and reached failure separately from build/setup failures. A parser-created table ID never enters an authority constructor.

UI expected diagnostics: MapsFileKey/StatFileKey equality E0308; `.into()` StatFileKey->MapsFileKey or snapshot->HeldFile E0277; key/charge private access E0451/E0616 at the operation line; ParseLimits::default E0599; drop(snapshot) while entry later used E0505; ParsedMountId==u64 E0308. Bind primary code/line to each new cases.json source and a positive counterpart. Do not accept any unrelated diagnostic as refusal. Runtime types not yet exported are checked by API inventory, not an unresolved-import surrogate.

## Task 4: Deliver two distinct clients and the package-local route

**Files:** `tests/support/{maps_inventory.rs,mount_audit.rs,run_proc_parser_checks.py}`, literal fixtures, package README/Cargo test declaration; root owns package-policy package_files. **Consumes:** exact candidate0.1.0 with actual feature/lock closure. **Produces:** an offline package check usable from source projection or actual extracted archive, without testkit or repository scripts.

- [ ] Maps inventory client uses only maps APIs, literal fixture facts/address table, executable-region counts and global invalid-table refusal. Mount auditor uses only mount APIs, raw/decoded slots/optional fields, input order, lookups and simultaneous equal-number/different-device tables. Keep their algorithms/expected data separate; neither acquires procfs or treats data as namespace/file authority.
- [ ] Implement the exact helper CLI already fixed in packet.md. Validate Python>=3.11, explicit tool paths, fresh outputs, offline closure and source/archive identity; scrub inherited overrides; create an enclosing resolver2 one-member workspace while keeping package source/manifest/lock unchanged. Copy the bound lock to the outer workspace. Create two standalone independent client manifests against the exact package path; initial offline lock creation is preparation, then all executions are offline/locked. Bind actual cargo metadata canonical manifest/version/features/dependency graph and all input/output hashes.
- [ ] For source cells, stage the exact candidate Linux package bytes into a fresh projection outside repository/Cargo ancestors; explicitly supply the bound root lock as projection preparation. For archive cells, use the actual extracted normalized manifest and delivered lock; do not edit archive bytes to run checks. Before/after subject hashes must match.
- [ ] Explicitly declare `[[test]] name="proc_parsers", path="tests/proc_parsers.rs"` in delivered normalized manifest even when autotests=false. Every fixture/helper/UI/test file appears in package_files/archive inventory. Preserve accepted read-adopted/read-opened clients and feature wiring; empty old placeholders never substitute for parser consumers.
- [ ] Execute six compiler/configuration cells for each of two clients, once source and once archive:2 compilers×3 configurations×2 clients×2 subject forms=24 client executions. Helper proc_parsers runs are additional named rows; do not count them as extra independent clients. Inspect nonzero named case inventory and A1–A3 assertions from actual delivered bytes.

## Task 5: Exact affected package and source verification

Use the two admitted absolute tool roots `/home/user/.rustup/toolchains/1.88.0-x86_64-unknown-linux-gnu` and `/home/user/.rustup/toolchains/1.98.1-x86_64-unknown-linux-gnu`. `minimal` means default_features=false/features=[]; `default` means true/[]; `union` means false/[mapping,process,supervision,walk]. Product argv flags are respectively `--no-default-features`, no extra feature flag, `--all-features`. These are six Linux cells, not a full 20 rerun.

- [ ] Root assigns a fresh execution checkout/origin and isolated `/tmp` output resource overlay. Use explicit cargo/rustc/rustdoc binaries, admitted isolated CARGO_HOME, fresh per-cell CARGO_TARGET_DIR and the absolute shared build wrapper; no rustup proxy or ambient wrapper. Bind expanded argv arrays, cwd and environment to receipts. Preserve every failed attempt.
- [ ] For every cell run the following offline/locked target selections with the appropriate feature argv:

```text
T/bin/cargo test --offline --locked -p scopebase-linux FLAGS --test proc_parsers
T/bin/cargo test --offline --locked -p scopebase-linux FLAGS --lib procfs::tests
T/bin/cargo test --offline --locked -p scopebase-linux FLAGS --all-targets
T/bin/cargo test --offline --locked -p scopebase-linux FLAGS --doc
```

`T`/`FLAGS` are notation, not literal shell arguments. Actual invocations use the absolute wrapper and expanded binary paths. Existing held_file/controls/positional_read/traits tests are reached with nonzero inventory, not silently filtered away.

- [ ] Construct a Linux-only derived gate in the assigned fresh output root: preserve candidate crate digest, root workspace.package defaults/license/MSRV, root lock inputs and Linux policy/dependencies/toolchains/clients. Narrow only projected members/default-members/policy members to Linux; record any offline lock pruning as preparation. Run the currently supported `tools/build/check_features.py --manifest ABS_GATE/Cargo.toml --matrix ABS_GATE/package-policy.json --output-dir FRESH --report FRESH.json` through the bound absolute wrapper. No invented member flag or framework change. Keep the exact policy/archive file inventory and normalized test targets.
- [ ] Run the Task4 helper on source projection and actual archive in all six cells, with distinct target/output roots. Source, archive, fixtures, oracle, clients, normalized metadata, lock, binary/compiler versions and result inventories are receipt-bound. A generated client lock's first creation is preparation; only subsequent locked execution can be reported as locked.
- [ ] Independent Sol max review checks source preservation, new grammar/identity/borrow bounds, allocation/privacy/precedence, actual semantic control kills, source/archive client identity and required incomplete gates. Root validates actual candidate-bound selected-port receipts, not just intake. Root canonical checks are `python3 tools/check_planning_docs.py`, structural traceability if changed, package-policy unittest suite and `git diff --check` plus added-file inspection. Coordination/planning-tool tests run only when their tools change. No docs validator result is a product test.

## Task 6: Two real libFuzzer campaigns after separate tool admission

**Files:** Separate `fuzz/scopebase-linux/{Cargo.toml,Cargo.lock,README.md,fuzz_targets/maps.rs,fuzz_targets/mountinfo.rs,corpus/maps/*,corpus/mountinfo/*}`. Normal product workspace/default closure remains unchanged. **Dependency:** LX05-FUZZ-TOOLS, a subitem of LX05; not a new canonical task ID or source gate for pure parser implementation.

The exact metadata inventory proposes cargo-fuzz 0.13.2/libfuzzer-sys 0.4.13. It is PROPOSED_NOT_ADMITTED, not installed, built or proven compatible with a Rust/native/sanitizer closure. The nightly candidate remains unqualified. The inventory's source-supported CLI observations do not constitute an executable admission.

- [ ] Root admits the complete exact locked tool graph/checksums/licenses, cargo-fuzz binary, libfuzzer native runtime, Rust/nightly/host/target triples, C++17 compiler/linker and sanitizer requirements into an immutable tool admission. Confirm the exact supported CLI argument placement and artifact paths from those admitted bytes. Record fully expanded argv arrays then; this draft deliberately supplies no guessed cargo-fuzz flags or native environment. Missing resources are BLOCKED_ENVIRONMENT for this gate.
- [ ] Build two actual libFuzzer targets against the reviewed path dependency and independently authored oracle. Each raw input uses ParseLimits{max_bytes:4096,max_entries:64,max_line_bytes:512}. Compare full acceptance/stage/reason/line and all accepted scalar/raw/decoded/path facts, numeric/offset endpoints and duplicate location to independent u128/linear-or-quadratic/one-pass-original-byte references. Allocator-injection tests stay a separate evidence tier.
- [ ] Freeze independently authored positive and active-negative seed manifests/outcomes. Include every selected P original population, A3's new three-good-plus-bad bytes, every A1 valid/malformed/single-pass boundary, A2 duplicate/unique twins, nonUTF8/deleted/escape paths, all interval/numeric/optional/absence/limit boundaries. Do not copy O's original fixture or generate expected data by production serialization. Copy seeds into owned fresh campaign corpora; never mutate tracked seeds or donors.
- [ ] Run `maps` and `mountinfo` separately to engine completion at exactly the required 10,000-run cap each. Fixed single-process seeds 500501/500502 and input ceiling 4096 are retained campaign requirements. Timeout/RSS/artifact routing must be explicitly admitted and recorded from supported engine syntax; they describe test-engine controls, not product time/RSS bounds. CARGO_NET_OFFLINE and exact frozen lock/closure are mandatory. Bind final parser/oracle/target/engine/binary/toolchain/native/corpus/argv/environment/log hashes; record actual engine run count and process retirement.
- [ ] A setup/tool failure is BLOCKED_ENVIRONMENT; a semantic mismatch/panic is FAILED. Minimize the input, preserve crash/minimized hashes and add deterministic regression. Changed parser/oracle bytes require affected deterministic tests/controls and both affected fuzz campaign bindings refreshed; unchanged inputs do not justify gratuitous stress repeats. No random-loop, property-loop or seed-replay substitute closes this requirement.

## Ten reference-only originals and later owners

These original tests are inspected knowledge, not LX05-port/pass claims. A3 uses an independently authored counterexample while preserving O-S27's reference status.

- `O:src/discovery/maps.rs::parses_and_skips_malformed` (line128): LX05 strictness counterexample only; independently author a three-good-plus-bad population under A3; no original O literal/test copying or port claim. tests/proc_parsers.rs::refuses_mixed_valid_and_malformed.

- `O:src/discovery/maps.rs::mapping_lookup_rejects_stale_pathname` (line142): LX06/LX07. No live file lookup in LX05.

- `O:src/discovery/maps.rs::mapping_lookup_rejects_cross_filesystem_ino_collision` (line194): LX06/LX07. No inode-only proof in LX05.

- `O:src/discovery/maps.rs::mapping_lookup_binds_mapping_path_identity` (line217): LX06/LX07. Path/fd association needs actual retained owners.

- `O:src/discovery/maps.rs::mapping_lookup_by_same_file_identity` (line259): LX06/LX07. Hardlink/replacement/deleted real filesystem assertions deferred.

- `P:src/process.rs::mountinfo_is_read_only_after_the_fd_is_open_with_retained_rechecks` (line1416): LX08. Parser never opens a file or retains a process.

- `P:src/process.rs::a_changed_mount_namespace_after_open_is_rejected_before_table_use` (line1444): LX08. Actual namespace handle/order evidence deferred.

- `P:src/discovery/identity.rs::retained_mount_table_controls_manifest_mapping_identity` (line4189): LX08/LX06. Pure local table regression is not runtime view binding.

- `P:src/discovery/identity.rs::raw_grouping_normalizes_path_aliases_but_keeps_mount_namespaces_distinct` (line4210): LX06/LX08. No application aggregation/path normalization copied.

- `P:crates/manifest/src/identity.rs::the_missing_mount_classifier_matches_only_the_missing_mount_error` (line700): LX08/LX06. String classifier excluded; preserve typed missing-vs-malformed and exact retry policy later.

## Exit and claim limits

- [ ] Every13 original correspondence,11 new groups and A1–A3 subcases has observed destination assertions, independent expected facts, positive twins and intended compiling bad-control failures; all applicable source/archive/UI checks use actual final bytes.
- [ ] Both independent consumers run in24 source/archive executions, six affected Linux package cells pass, actual normalized archive inventory is complete, and old accepted consumers remain intact.
- [ ] Both real 10,000-engine-run campaigns pass after tool admission. Required unavailable tools/fixtures remain incomplete and block LX05 acceptance; no task denominator is reduced.
- [ ] Root separately validates the 15 copying ranges' actual selected-port receipts and reviewed destination bindings, integrates canonical documents/ledgers and records acceptance only for the bounded pure parser increment.

These conditions do not qualify real Btrfs/overlay/namespace identity, retained process/view/birth/epoch behavior, mapping proof/calibration/custody, full developer/runtime conformance, installed operator profiles, product migration or publication. LX08 consumes the parsers next; LX06/LX07/TT03/TT04 and LX11/LX12/TT07 retain their stated gates. No preparation, source inspection, proposed command or completed draft is a product test result.
