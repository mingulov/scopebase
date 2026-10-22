# LX05 selected parser preservation, 2026-10-22

This selected-port record describes actual destination source correspondences for the bounded pure parser increment. It is not test execution, independent approval, task promotion, package qualification or runtime authority. All copied input comes from completed private frozen captures; no live donor or Git operation was used to draft it.

The five-file, 31-slice study boundary is unchanged: 15 selected P ranges (13 ADAPT plus two VECTORS_ONLY ranges) across two P source files; 16 reference-only ranges across the complete five-file study. No O source range is copied. The 13 selected regression routes are twelve parser regression adaptations plus S16's pure table-vector counterpart, not thirteen complete runtime tests. Ten reference-only original regression routes remain with their named later owners.

## Source authority and exact inputs

- Source admission: [2026-10-18-lx05-proc.json](../admissions/2026-10-18-lx05-proc.json), SHA256 `9cef97b541284a32455019e1b05dd60b614b211d0d8e154601e034d45faaca71`.
- Selected P pin: `2c2713e66292b0d2688508a25f79e813ae823d81`, captured `w003` v040-integration checkout with independent `p11scope-ws/history/r001.git` history. Comparison O pin: `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a`, captured checkout-018; reference only.
- Frozen expert source-selection SHA256 `2d0d9071b37e3c5d46b278f98b3c8ccbcc1989ff780ff9fd6f147b45fff6264d`; expert preservation-map SHA256 `30b7cd5c29e9f136a303956b845c29a81e10f67191e2b75851ab62ab003a1afb`; expert index SHA256 `d5c95d790a05f3eeba291fe9930ae81b53f896082b85553b65804c58945cab2c`. The immutable controller overlay supersedes the packet's historical draft/admission-pending wording; actual worker origin is `1b50923eaa0651801ae963e4a0562bb6c7a3bda0`.
- User-owned selected historical source is GPL-3.0-or-later; destination authorization is Apache-2.0 under OWNER-2026-10-18 as recorded in the source admission. These are separate facts; no unrelated third-party or BPF code is relicensed. The admitted selected records identify no third-party fragments.
- The companion selected-port receipt binds exact complete destination-file hashes and exact inclusive source ranges. Slice hashes below preserve LF and use no normalization. The frozen input file/slice hashes were rechecked locally; this is not a fresh complete donor audit.

## Selected correspondence

| Slice / source range | Destination symbols and regression route | Preservation / intentional scope change |
|---|---|---|
| LX05-S01 `P:crates/manifest/src/maps.rs:9-54` | `src/identity.rs` `MapsFileKey`; `src/procfs/maps.rs` `MapRecord`, `MapsEntry::{file_key,raw_path,permissions}`; `tests/support/maps_inventory.rs` `main (new consumer of lexical map keys/raw fields)` | Device/ObjectKey/MapEntry becomes a private nominal MapsFileKey plus raw-extent MapRecord/borrowed MapsEntry. The key remains maps text, separate from stat device/physical-file identity. No overlay or Btrfs reconciliation is supplied. |
| LX05-S02 `P:crates/manifest/src/maps.rs:56-67` | `src/procfs/maps.rs` `parse_maps`, `parse_inner (whole-input refusal)`; `tests/proc_parsers.rs` `ported_malformed_nonempty_line_is_rejected`, `complete_absence_and_unterminated_are_distinct` | The parse-every-row-or-refuse contract is preserved; unbounded collect/skipped blank lines become bounded preflight/reserves and strict complete-LF snapshot refusal. Empty bytes remain valid absence; blank rows and missing final LF refuse. |
| LX05-S03 `P:crates/manifest/src/maps.rs:85-162` | `src/procfs/maps.rs` `field`, `parse_line`; `src/procfs/mod.rs` `split_once`, `number` | The five structural fields, raw pathname remainder, four-byte permission alphabet and checked range/device/inode conversion survive. Structural whitespace narrows to SP/HT; exactly-one separator and strict digit/overflow rules replace UTF8/String diagnostics and allocation. |
| LX05-S04 `P:crates/manifest/src/maps.rs:213-261` | `src/procfs/maps.rs` `parse_inner (ordered/nonoverlap/extent admission)`, `MapsSnapshot::{entries,containing}`; `tests/support/maps_inventory.rs` `main (new literal address/offset inventory consumer)` | Validation completes before MapsSnapshot escapes; partition_point/preceding interval with exclusive end survives. Input order is retained, never repaired by sorting. Checked end-offset extent applies to every row, extending the donor absolute-file-only guard. |
| LX05-S05 `P:crates/manifest/src/maps.rs:268-287` | `src/procfs/maps.rs` `MapsEntry::{raw_path,path_kind,path_evidence}`, `MapsPathEvidence::{is_utf8,has_escaped_newline,has_deleted_suffix}` | Deleted suffix, literal backslash012 ambiguity and UTF8 evidence are preserved as independent flags over original bytes. MappedPath usable/unusable decisions and PathBuf/file-resolution policy are deliberately absent. |
| LX05-S06 `P:crates/manifest/src/maps.rs:294-297` | `src/procfs/maps.rs` `MapsEntry::file_offset_at`; `tests/support/maps_inventory.rs` `main (new consumer of checked segment offsets)` | Offset is checked segment offset + (address - start), with explicit half-open bounds. The destination returns Option instead of donor Resolved/File classification or panic based on a previous index proof. |
| LX05-S07 `P:crates/manifest/src/maps.rs:320-420` | `tests/proc_parsers.rs` `SORTED`, `ported_parses_entries_and_preserves_path_bytes`, `ported_resolves_with_segment_offset_arithmetic`, `ported_classifies_anonymous_and_unmapped`, `ported_unusable_file_paths_remain_file_evidence`, `ported_malformed_nonempty_line_is_rejected` | All five selected original parser regression routes are present. The same five literal rows are sorted for the stricter snapshot contract and their original unsorted order is separately rejected. Paths/spaces/deleted/nonUTF8/escaped evidence, two segment-offset addresses, anonymous/pseudo data and malformed row/line evidence remain asserted; no application resolution union is claimed. |
| LX05-S08 `P:crates/manifest/src/maps.rs:429-499` | `tests/proc_parsers.rs` `ported_map_index_requires_sorted_non_overlapping_intervals` | All selected swap, overlap, descending-disjoint, equal-start, empty-range and reversed-range populations have source-authored malformed-row assertions. The destination checks via text admission instead of constructing invalid MapEntry structs. |
| LX05-S09 `P:crates/manifest/src/maps.rs:502-546` | `tests/proc_parsers.rs` `ported_invalid_snapshot_is_distinguishable_from_valid_absence` | A clean file-plus-anonymous pair permits both a file hit and a gap. Appending the original overlapping third range refuses the entire snapshot before either lookup can be made; this replaces two resolve-error calls with the stronger no-snapshot boundary. |
| LX05-S10 `P:crates/manifest/src/maps.rs:549-576` | `tests/proc_parsers.rs` `ported_map_index_rejects_file_offset_overflow` | Two-byte extent at u64::MAX offset refuses; u64::MAX-1 permits final-byte offset u64::MAX. A separate one-byte u64::MAX success is retained. These are literal arithmetic assertions, not emitted-object or runtime mapping evidence. |
| LX05-S11 `P:crates/manifest/src/maps.rs:579-606` | `tests/proc_parsers.rs` `ported_map_index_resolves_gaps_adjacency_and_exclusive_ends` | Original seven address cases preserve start, last byte, adjacency, gaps and exclusive end. The destination observes the selected entry start or None instead of the donor Resolved::Unmapped application variant. |
| LX05-S12 `P:crates/manifest/src/identity.rs:607-631` | `src/procfs/mod.rs` `split_once`, `number`; `tests/proc_parsers.rs` `numeric_grammar_and_full_range_overflow`, `numeric_domains_each_reject_sign_prefix_and_overflow`; `tests/support/proc_reference.rs` `number (new independent u128 test oracle)` | Digit-only hex/decimal acceptance and sign rejection are adapted to checked multiply/add u64 accumulation without input UTF8 conversion. Exactly-one separator strengthens the donor helper. New u128 test conversion provides an independent oracle; it is not copied donor source. |
| LX05-S14 `P:crates/manifest/src/identity.rs:139-158` | `src/procfs/mountinfo.rs` `parse_line (decimal mount number/device facts)`, `MountTableSnapshot::entry_by_number`, `MountEntry::device`; `src/identity.rs` `MountDevice`; `tests/support/mount_audit.rs` `main (new lexical table/device consumer)` | Only decimal mount-number selection and decimal major:minor facts are adapted. Full raw-byte mountinfo grammar, sorted lookup index, borrowed descriptive table IDs and arenas are NEW seams. No FD mount-id acquisition, fstat inode binding or retained namespace/view is ported here. |
| LX05-S16 `P:crates/manifest/src/identity.rs:674-697` | `tests/proc_parsers.rs` `table_local_numbers_preserve_device (pure vector counterpart only)`; `tests/support/mount_audit.rs` `main (new equal-number/different-table device audit)` | VECTORS_ONLY: equal raw mount number 17 in two literal tables yields devices (8,1)/(9,2), with table-local ID inequality and clean missing-row absence. The original open(/bin/sh), fdinfo/fstat, inode and retained-process-view mechanism is NOT ported; it remains LX08/LX06. |
| LX05-S18 `P:crates/manifest/src/identity.rs:991-1056` | `tests/proc_parsers.rs` `ported_probed_maps_line_parses_hex_devices_and_decimal_inodes`, `ported_probed_maps_line_matches_only_its_own_range`, `ported_malformed_probed_maps_lines_fail_closed` | VECTORS_ONLY: retain original lower/upper hex device tuples, decimal inode values, five address outcomes and every malformed field/overflow vector. Append LF for the complete-snapshot API; original empty line becomes malformed single-LF row while empty bytes separately mean valid absence. parse_probed_maps_line itself is reference-only S15, not copied. |

## Exact source slice hashes

| Slice | SHA256 |
|---|---|
| LX05-S01 | `c808ef48716d94a8f6c4c2e794fb46992897bf849ebea850dbe1c62e3a4b0ee6` |
| LX05-S02 | `830be0bb1b876de2c48b54074b6b9c558523909920177d73328cde51c5daae26` |
| LX05-S03 | `a8599693d9ae25c7b890ec1dee6c2f110ecab720d0739eab72dc83fa26a43ad3` |
| LX05-S04 | `861994e9fd68c8bb81457df71e74630dba879ac93ae5107f988c79eced0f57b3` |
| LX05-S05 | `79de64df56584cfcb7b7beca9dc37b3656a4caf31254b7578add34f04fa7d63e` |
| LX05-S06 | `5cfa6d4de9b1a9b6f3f5fd1828f83f1fd597a0c9f377aa74bb8a333b3a53c26c` |
| LX05-S07 | `bf05d113305c0e4cfb6817b9531ad5ab0ee5641e717c992a6535ae373ff6a587` |
| LX05-S08 | `cd468db01b30b911d1a9606ddc3db2285403e26cc9b48596454ad8733e40c899` |
| LX05-S09 | `813344670e2069e8a10d1f47a332f45f83b20c25f6e8257f7ec9d4dc0821a511` |
| LX05-S10 | `8173ac051b56a4847cc217eaa1123d233cdbe5334e18287cb0e9a48bedd8c790` |
| LX05-S11 | `6b8ff3142aa249c3db33391ae87eda2d52710ea1fbb21c7fb5a903c0a8c30ebe` |
| LX05-S12 | `b39e462a30a01a92c2dadb73ec4a2ad563b16764e37aae4196864a60efe51ce4` |
| LX05-S14 | `31adf649554a89308abb0175bb65c7935587282dd5c0f2ef102b746da8f70d8a` |
| LX05-S16 | `b1795fc4a6517cbe1788ad742f95853a9a18345b7488f0c837b577ecde918cf8` |
| LX05-S18 | `15a34757a982f32111d654887c454e9517492f0c71924ba9e5bb46ae6a4b1157` |

## Retained regression boundaries and oracles

The five S07 source regressions, four S08-S11 source regressions and three S18 probe-line regressions are adapted by name in proc_parsers.rs. S16 supplies only the descriptive table-selection population. None of these claims includes the remainder of either donor file or all donor project tests. Literal expected keys, offsets, paths and address tables precede production parsing. The delivered proc_reference.rs uses independent u128 numeric conversion, linear interval lookup, quadratic duplicate detection and separately allocated byte decoding; maps_inventory.rs and mount_audit.rs have distinct literal oracles and API routes. These newly authored verification/client sources are supporting uses, not extra copied source slices.

The known-bad controls remain separately required evidence: nonzero-offset omission, inclusive end, overlap/order bypass, packed stat-style key confusion, number-only table IDs, malformed/defaulted numeric acceptance, raw path loss, blank/unterminated acceptance, and exact A1 escape/A2 duplicate/A3 skip-malformed assertions. A source mapping or inspected assertion does not prove a control compiled, reached its semantic assertion, was killed, or had a restored positive. UI refusal is a separate compile-boundary tier. The exact current-byte package/fuzz/control receipts and independent final review remain the acceptance gates recorded by the canonical verification plan and handoff.

## Reference-only source ranges

| Slice | Source range | Original role / retained boundary |
|---|---|---|
| LX05-S13 | `P:crates/manifest/src/identity.rs:117-138` | mapping_file_key_in_mountinfo acquisition/fdinfo; REFERENCE_ONLY, not copied by this receipt |
| LX05-S15 | `P:crates/manifest/src/identity.rs:639-667` | parse_probed_maps_line; REFERENCE_ONLY, not copied by this receipt |
| LX05-S17 | `P:crates/manifest/src/identity.rs:699-718` | the_missing_mount_classifier_matches_only_the_missing_mount_error; REFERENCE_ONLY, not copied by this receipt |
| LX05-S19 | `P:src/process.rs:295-327` | ProcessViewId/MountNamespaceId/ensure_same_mount_namespace; REFERENCE_ONLY, not copied by this receipt |
| LX05-S20 | `P:src/process.rs:343-354` | read_view_mountinfo; REFERENCE_ONLY, not copied by this receipt |
| LX05-S21 | `P:src/process.rs:458-469` | open_then_mountinfo_checked; REFERENCE_ONLY, not copied by this receipt |
| LX05-S22 | `P:src/process.rs:1415-1476` | mountinfo read-order and changed-namespace regressions; REFERENCE_ONLY, not copied by this receipt |
| LX05-S23 | `P:src/discovery/identity.rs:1850-1895` | identity_of_in_mountinfo/reread_on_missing_mount; REFERENCE_ONLY, not copied by this receipt |
| LX05-S24 | `P:src/discovery/identity.rs:4188-4226` | retained table and raw namespace grouping regressions; REFERENCE_ONLY, not copied by this receipt |
| LX05-S25 | `O:src/discovery/maps.rs:1-54` | Mapping/read_maps/parse_maps; REFERENCE_ONLY, not copied by this receipt |
| LX05-S26 | `O:src/discovery/maps.rs:56-116` | provider_mapping; REFERENCE_ONLY, not copied by this receipt |
| LX05-S27 | `O:src/discovery/maps.rs:122-134` | parses_and_skips_malformed; REFERENCE_ONLY, not copied by this receipt |
| LX05-S28 | `O:src/discovery/maps.rs:136-187` | mapping_lookup_rejects_stale_pathname; REFERENCE_ONLY, not copied by this receipt |
| LX05-S29 | `O:src/discovery/maps.rs:189-211` | mapping_lookup_rejects_cross_filesystem_ino_collision; REFERENCE_ONLY, not copied by this receipt |
| LX05-S30 | `O:src/discovery/maps.rs:213-252` | mapping_lookup_binds_mapping_path_identity; REFERENCE_ONLY, not copied by this receipt |
| LX05-S31 | `O:src/discovery/maps.rs:254-300` | mapping_lookup_by_same_file_identity; REFERENCE_ONLY, not copied by this receipt |

S13/S15/S17 reserve FD mount-id acquisition, probe implementation and missing-mount classifier policy. S19-S24 retain actual process/mount namespace views, ordering/rechecks, file association and aggregation. All O ranges S25-S31 remain reference-only, including S27's skip-malformed counterexample. Exact A3 fixtures and skip-malformed controls are independently authored and do not make an O copying or original-test port claim.

## Deferred original regression routes

| Original source/test | Later owner / boundary |
|---|---|
| `O:src/discovery/maps.rs::parses_and_skips_malformed` | LX05 strictness counterexample only; independently author a three-good-plus-bad population under A3; no original O literal/test copying or port claim; tests/proc_parsers.rs::refuses_mixed_valid_and_malformed |
| `O:src/discovery/maps.rs::mapping_lookup_rejects_stale_pathname` | LX06/LX07; No live file lookup in LX05 |
| `O:src/discovery/maps.rs::mapping_lookup_rejects_cross_filesystem_ino_collision` | LX06/LX07; No inode-only proof in LX05 |
| `O:src/discovery/maps.rs::mapping_lookup_binds_mapping_path_identity` | LX06/LX07; Path/fd association needs actual retained owners |
| `O:src/discovery/maps.rs::mapping_lookup_by_same_file_identity` | LX06/LX07; Hardlink/replacement/deleted real filesystem assertions deferred |
| `P:src/process.rs::mountinfo_is_read_only_after_the_fd_is_open_with_retained_rechecks` | LX08; Parser never opens a file or retains a process |
| `P:src/process.rs::a_changed_mount_namespace_after_open_is_rejected_before_table_use` | LX08; Actual namespace handle/order evidence deferred |
| `P:src/discovery/identity.rs::retained_mount_table_controls_manifest_mapping_identity` | LX08/LX06; Pure local table regression is not runtime view binding |
| `P:src/discovery/identity.rs::raw_grouping_normalizes_path_aliases_but_keeps_mount_namespaces_distinct` | LX06/LX08; No application aggregation/path normalization copied |
| `P:crates/manifest/src/identity.rs::the_missing_mount_classifier_matches_only_the_missing_mount_error` | LX08/LX06; String classifier excluded; preserve typed missing-vs-malformed and exact retry policy later |

## New seams, limits and later retirement

Complete strict raw-byte mountinfo grammar, single-pass octal decoding, duplicate diagnostics, bounded two-pass arenas/accounting and pointer/borrow-scoped ParsedMountId are frozen NEW seams. S14 does not turn them into copied complete donor mechanisms. The public parser consumes caller-provided bytes, performs no procfs acquisition, opens no target, creates no mapping and supplies no retained process/namespace/file authority. MapsFileKey is descriptive maps metadata; decimal MountDevice, stat identity and runtime mount identities remain distinct.

LF-complete bytes cannot prove acquisition completeness or detect a missing complete-row suffix. Byte, row and line admission, allocation attempts and charged actual capacities are separate from wall-clock/RSS/kernel interruption or worker-retirement guarantees. No live Btrfs/overlay/namespace, image association, calibration, task-birth/exec, native BPF or installed full-profile claim follows.

The parser package-local helper and two standalone clients are delivered check routes; ordinary downstream cargo test does not run dependency tests. Full developer/installed operator profile owners remain LX11/LX12/TT03/TT04/TT07 and the canonical dependency graph. LX06/LX08 own retained view and association, LX07/TT03/TT04 own real filesystem cells. Later application migrations retain their own actual-consumer and duplicate-retirement criteria: no donor implementation is removed until its migrated consumer covers the same raw evidence, malformed refusal, bounds, identity separation and original regression obligations.

The current-byte independent review, affected six package cells, both delivered clients across source/archive/feature/compiler cells, exact A1-A3 semantic controls and required two ASan fuzz campaigns remain separate evidence. This preservation document records inspected correspondence only and changes no canonical task/profile status.
