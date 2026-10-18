# scopebase-linux selected-source register

LX01 registers future preservation obligations; it copies no donor implementation.
Every source row is **SELECTED**, **NOT_ADOPTED**, **NOT_PORTED**, **NOT_TESTED**.
No original regression or runtime profile has been executed by registration. The
[contract](contract.md) records this increment's package/import-only scope.

## Frozen inputs and observation limits

The [completed capture index](../../provenance/frozen-donors-2026-10-18.md) is the
source authority. All selected copied bytes listed below were SHA256-verified
against the bound historical assessment. No live donor, Git command, branch
refresh, build or behavior run was used. Capture is non-atomic and is not donor
runtime qualification. The [structured register](source-register.json) retains
full source symbols/lines, original test names, all 43 present distinct variant
blobs plus the historical pidns absence, carrier refs/commits, selected-path
history comparisons and exact capture metadata hashes. Carrier refs are historical
observations; they do not prove current publication or whole-branch equivalence.

P: commit `2c2713e66292b0d2688508a25f79e813ae823d81`, captured branch
`v040-h7-object-wire`, selected checkout w003. Frozen tree
`p11scope-ws/tree/.worktrees/v040-integration`; independent history
`p11scope-ws/history/r001.git`; saved WIP/index/status `p11scope-ws/metadata/w003`.
O: commit `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a`, captured branch
`task/integration-preview-r21`, selected checkout checkout-018. Frozen tree
`osslscope-ws/checkout/osslscope/.worktrees/preview-r21`; independent history
`osslscope-ws/histories/repo-001/history.git`; WIP/index/status
`osslscope-ws/metadata/checkout-018`. Paths are relative to
`/home/user/src/m/bpfscope/.scopebase/donor-snapshots/2026-10-18/`.
Gitless checkouts never imply parent-repository Git history. Selected historical
preparation paths were clean; saved capture WIP remains independent evidence and
is not replaced by that earlier clean observation. Exact metadata hashes in JSON
preserve that distinction, including non-selected dirty/untracked source.

Historical preparation evidence SHA256s (durable facts, not links required to
use this register):

| Input | SHA256 |
|---|---|
| `p-selected.json` | `299c7c54dda348bb9e62de46430b9d567c7e9d3e0b32ba47c8bbe4401b8718a7` |
| `o-selected.json` | `5cf7298b6c1008e6dd6cdc60d2d9e6ca4bf4199a19e5318b918f8ba6586a2038` |
| `p-variants.json` | `cbca24b9f23e20edc98abd31980b051b7debe137ed8eeae793ccc19e0a8884dd` |
| `o-variants.json` | `1869c8b69ec547e7c3242056e2c193323de42da89c50783d3715a6406980dc6c` |
| `variant-review/variant-assessment.md` | `b2efef960d3a1ec39a597ef14d066327d2d741f6dd91b5b533283070290d8085` |
| `variant-review/variant-assessment.json` | `d1ee74fb9f7a85ea5cb285fe33545f5be5f65843c15935cdc461647bf1920359` |

The bounded historical review found no alternate-only selected-path fix requiring
source replacement. It covered 16 present P blobs plus one absence and 27 present O
blobs. Maps' private/public visibility delta is not a parser fix. P's denial module
is byte-equivalent to its nominated integration; selected-path patch equivalence
and combined integration are distinct from whole-branch equivalence. Full variant
relationships and their limits are retained in the JSON and the narrative below.

## Selected files and adoption custody

[SB01 adoption records](../../provenance/donors.json) retain their own source
observations and unresolved scope/ownership classifications. Their IDs below are
references, not adoption approvals. All currently referenced selected slices need
expert selection before copying; pidns is explicitly pending intake. The nearby
P `src/discovery/inventory_attach_set.rs` regression source remains pending its
selected-slice intake before any copied test or implementation; its SHA256 is
`f9255695f5ad546c02c6addcd609569d28aafd3a2cf95ef94687d0279cd859f5`.

| Donor | Path | Selected-file SHA256 | Adoption record / current disposition |
|---|---|---|---|
| P | `crates/manifest/src/identity.rs` | `03969328ba13caaf054a64e839732f91a74ded3647d4ff15c4a63264e17b0d64` | `P:crates/manifest/src/identity.rs` / NEEDS_DECISION |
| P | `crates/manifest/src/maps.rs` | `6ddaefb21190e1fa52b98426ba91bfdc591c524444e3027c74db8e00095d8cb1` | `P:crates/manifest/src/maps.rs` / NEEDS_DECISION |
| P | `src/discovery/identity.rs` | `ff5a08d4ce93a24f8b3c2c712d5c30e4bcdd83e417124facbdf8c3e8b96c6a7f` | `P:src/discovery/identity.rs` / NEEDS_DECISION |
| P | `src/process.rs` | `b9b74b111ca830d18a12ad1c65c4ede58e014a95817ccc12f2403b2fe22e1e3e` | `P:src/process.rs` / NEEDS_DECISION |
| P | `src/pidns.rs` | `49d4c3d381f82675484c17f26807a6d3fe95d4304f0cdeee74d90312d4b3aba9` | `pending intake: P:src/pidns.rs` / PENDING_INTAKE |
| O | `src/pin.rs` | `3d1b709eb9182a5d1a9c80abff8b8c6bceb5d9eec52dc0064f5986df8db85956` | `O:src/pin.rs` / NEEDS_DECISION |
| O | `src/plan.rs` | `18132719eb9d770118568a560985e2f3bb8d33cabdcc56318e81cee9c3a26299` | `O:src/plan.rs` / NEEDS_DECISION |
| O | `src/target.rs` | `b47b0014bac599226897dfee784657d3924f1614d1458520cafead830b02ebaa` | `O:src/target.rs` / NEEDS_DECISION |
| O | `src/discovery/maps.rs` | `959d1b0377a77b040e4214e80b93415ce4b64ebc86dfbd05143e7ad8d7596371` | `O:src/discovery/maps.rs` / NEEDS_DECISION |
| O | `src/discovery/elf.rs` | `0bfc20a2bc9565f954ea80d4c9052b2e23b6bbb59d5c7473b6be5d335de09f01` | `O:src/discovery/elf.rs` / NEEDS_DECISION |
| O | `tests/site_identity.rs` | `8fd32150537033869a12acefe6dfd68d7eb51241a6f726a1ba06ec1cf212d9fa` | `O:tests/site_identity.rs` / NEEDS_DECISION |
| O | `tests/identity_domain_audit.rs` | `e1df1b17d04fe6de1bd4965af486fc722cb596fb87e49bce8ee49ec644e37c36` | `O:tests/identity_domain_audit.rs` / NEEDS_DECISION |
| O | `tests/target_lifecycle.rs` | `3e1457daaa3ee50cbeb1b859b9b82b28c59c3c704d42f57d540012f7cb02af19` | `O:tests/target_lifecycle.rs` / NEEDS_DECISION |

The historical source grant for these donor inputs is GPL-3.0-or-later (including
repository-default observation for the unheaded identity-domain audit). Preserve
that raw observation separately from author authorization `OWNER-2026-10-18`,
which provisionally permits Apache-2.0 for the user's selected host contributions
under [D03](../../superpowers/specs/2026-10-18-scopebase-decisions.md#d03--license-by-code-ownership-and-actual-build-destination).
Actual upstream portions still need their original terms and third-party notices;
this register does not invent grants, change donor labels or approve a source copy.
LX01's newly written host boundary is Apache-2.0 and bundles no donor source.
Controller/SB01 owns missing intake and adoption decisions, with the owning LX task
required to freeze slice, destination and third-party classification before copying.

## Future mechanism ownership, oracle and bad control

The table is an obligation register for later tasks, never an implementation list.
PORT/ADAPT starts from those selected sources and preserves every applicable
original regression and setup/assertion. NEW is limited here to absent import-only
clients and boundary documentation. Later real consumers and duplicate retirement
are LX11/LX13 and MG01/MG02 gates; import clients do not satisfy those gates.

| Source symbols and original regressions | Future destination / retained difference / oracle and wrong control |
|---|---|
| P `identity::open_regular`; O `plan::{PinnedFile,resolve_pinned,resolve_pinned_retry}`; `resolve_pinned_stats_the_open_file`, `h4_t2_pin_open_retries_bounded_then_fails` | ADAPT LX02 `file/held.rs`: use P O_PATH/nonregular refusal and held-inode reopen; O direct File::open is not equivalent. Real A/B inode fixture, rename/unlink/FIFO and retained FD oracle; path-reopen mutant must retarget or block and fail. O finite retries remain documented donor policy, not automatic ScopeBase retries. |
| P `read_object_bytes_with`, `an_early_zero_read_is_rejected_as_a_short_read`; O `FileBytes,bound_bytes,read_bounded_from,read_file_bounded`, every R14 cap/growth/replacement/empty/clone regression, `bound_bytes_requires_identity_match`, `h5_t2_bound_bytes_refuses_xfs_same_ino` | ADAPT LX03 `file/read.rs`: preserve N/N+1 and preallocation refusal, Arc allocation sharing and before/after observations; replace cursor-based assumption with specified positional behavior. Independent known bytes + aliased nonzero cursor; suffix reader/removed final stat/oversize sentinel controls. P/O 256/128 MiB caps remain application-local; same-size metadata-restored mutation is not proven absent. |
| P `maps::{parse_maps,MapIndex::new,mapped_path}` and all byte-path/malformed/ordering/offset-overflow/gaps/exclusive-end tests; `mapping_file_key_in_mountinfo`, missing-mount classifier tests | ADAPT LX05 `procfs/{maps,mountinfo}.rs`, LX06 view conversion: strict bytes and tagged view/identity domains. Independent interval/field oracle and overlap/domain-cast controls. Older private mapped_path changes visibility only. O tolerant zero/default/skipped-row parser cannot replace strict behavior. Retry only the recorded missing-mount case, not all errors. |
| P `RetainedMappedIdentities::{from_targets,identity_for}`, `MappedFile::may_retain`, `Entry::reusable_mapped_file`, `pin_scanned_object`; all retained-file/proof, changed scan pin, filesystem allowlist, equal-inode and mount collision regressions | ADAPT LX06 mapping proof/custody, QUALIFY LX07: original Arc and metadata pins remain; no-new mode audited over all transitions. Spec deliberately narrows donor reuse: initial ordinary ext4 only; donor Btrfs reuse does not expand it. Real distinct-object collision/copy-up/view fixtures plus independent address/FD oracle; raw-key-equality, fresh-target-mmap and early-owner-drop mutants. Scripted calibrated keys remain model evidence. |
| O `maps::provider_mapping`; stale pathname, cross-filesystem inode collision, mapping-path identity and same-file tests; P `PinnedContentKey`/held-object comparison and stale-alias tests in `inventory_attach_set.rs` | LX06/LX07 counterexamples; application reducers/alias registries stay local. O same-namespace path-stat join is not foreign-view or retained map_files proof. Equal content narrows lookup only; compare actual held physical objects. Equal-key different-file twin must reject; pathname/hash-only mutant fails. |
| P `ProcessView,PidPin,ProcPin,acquire_proc_dir_with,read_maps_with,mapped_file_identity`, strict proc/birth/liveness/mount-view tests, hostile-comm/short-read/EINTR tests; O `TargetPin::{pin,verify}`, `ExternalTarget`, tricky-comm and no-signal tests | ADAPT LX08 process observation/epoch: retain original pidfd+birth+proc-view bracket, bound stat/maps reads; no signal/wait authority. P fallback observation differs from strict ProcPin; O starttime verify lacks exit polling/retained proc view. Independently synchronized owned child, pidfd poll and proc-dir identity; PID-reuse or ignored transport-error mutant fails. Birth is not exec/current-mm. |
| P `pidfd_denial_helper`, `real_pidfd_denial_preserves_proc_identity_without_signal_authority`; byte-identical denial module already in nomination | LX08 preserve EPERM/ENOSYS canaries, thread filter delta, token phases, live/zombie/reaped distinction and owned-child cleanup. ScopeBase strict acquire refuses; donor stat-only fallback is a documented counterexample, never signal authority. Wrong fallback-to-control mutant fails. Privileged/restricted setup result remains separate from semantic refusal. |
| P `pidns::{classify,classify_proc_view,PidNumbering::agrees,numbering}`; all 14 tests indexed in next-obligations.md | ADAPT LX08 after intake addition: Initial/Nested/Unknown separate from Own/Foreign/Unserved; malformed/unreadable remains unknown. Preserve actual namespace/proc composition oracle and foreign/unserved twins. OnceLock's no-remount assumption is not library authority: observer/retained-proc epoch invalidation required. Never export `agreeing()` or leaked test seam as production authority. |
| O `target::{normalize_setup_key,PrestopGuard}` and worker-owned disposal/registry/custody mechanisms; early-cancel/expiry/discarded-result tests; lifecycle prestop/cancel/fork-failure/stuck-worker/late-worker tests; `external_pid_target_is_never_signaled`, `r20_exec_replaces_image_custody_survives` | ADAPT LX09 supervision and LX04 effects, with TT03 helper. Preserve child custody and unresolved effects, positive phase acknowledgements and exact-child wait oracle; timeout-as-retirement or duplicate-release mutants fail. Output staging/alias/CLI/privacy/connector event stream remain product-local. Existing specified pools/helper boundaries need their own later bounded packet; no globals/pre-exec callbacks are imported. |
| O `discovery/elf.rs`, ELF cache regressions and identity-domain audits; duplicate ambiguity/installed-at/first-attempt environment tests | Retain as reference/cross-component constraints for appropriate BP/migration owners and LX13 handoff. No ELF parser/cache, attach state machine, kernel event runner or app evidence schema in this Linux boundary. Structural source-spelling audit is not semantic runtime proof. Record every excluded application behavior explicitly rather than dropping its history. |

P `src/pidns.rs` is still a concrete intake addition, owner controller/SB01-records + LX01 register, consumer LX08. Exit before LX08: append exact observation/adoption reference, retain classifiers and all original regressions, classify ownership/third-party scope under D03, pass total-reference checks and freeze lifecycle/cache adaptation. It need not delay this no-copy package boundary if the register marks it pending. Do not claim that it was among accepted 124 files. Historical GPL labels are not an automatic ban on user-authorized destination terms.


## Accepted dependencies and deferred evaluation

[SB02 decisions](../../dependencies.md) are accepted at integration
`3cf6dd9fb4b719ccd4059075c083d45f989ffcb7`. LX01 has zero dependencies.
The primary syscall candidate is rustix `=1.1.5`, defaults off, `std,fs`;
LX02/LX03 introduce it only for actual mechanisms. Add `process` with LX08's
actual observation work; its SB02 pidfd trial only typed the function. Nix 0.31.3
`fs,uio` is a comparator. Object `=0.39.1`, defaults off, `read_core,elf,std`
is primary for TC05/TC06; goblin 0.10.7 `std,elf32,elf64,endian_fd` is a comparator.
LX13 retains application ELF/export/cache boundaries. No duplicate libraries are
wired merely to fill a manifest.

Procfs/procfs-core 0.18.0, defaults off, has recorded raw-byte/malformed-row and
bound gaps. LX05 preserves the strict donor maps/mount adapter; LX04 provides
controls and LX08 retained authority. A successful public parser call does not
meet those contracts. cap-std/pathrs remain **EVALUATE at LX10**, or the first
actual confined traversal consumer: versions/source/API/negative controls must be
frozen there. No traversal comparison was executed or adopted here. No new generic
syscall, procfs or path framework follows from this register.

## Preserved historical source assessment

The following source facts and named regressions are transcribed from the bound
static variant assessment. Statements about tests describe inspected source only.
Its source-slice conclusions remain historical evidence, while SB02's former
pending status and live-refresh instructions are superseded by the accepted
integration and frozen capture contract above. Line numbers refer to donor bytes.

### P manifest identity and maps

All inventoried refs share `crates/manifest/src/identity.rs` blob `a917c7b0d211f51602618815457a47d1b1f390a4`. Keep its mechanisms: `open_regular` (177) pins with O_PATH before rejecting nonregular objects and opening the retained inode for reads; `mapping_file_key_in_mountinfo` (121) resolves the held FD's mount ID in the supplying process view, and `is_missing_mount_id_error` (169) permits only the specific retry; `read_object_bytes_with` (277) rejects an early zero read rather than hashing a prefix. The contract still needs the caller's before/after content guard and operation limits; the low-level byte reader alone does not freeze mutable file content.

The sole maps alternate, task3 blob `5d30d1004bcf96505054d9f884e0593cc4d28f29`, changes only `mapped_path` visibility from public to private. Its parser/interval semantics and tests are otherwise identical to nominated `6711fe0e2173742c7a69d10190c675aff6d3ba71`. This is an older API visibility choice, not an omitted fix. Preserve `parse_maps`, byte paths, deleted/unusable file evidence, `MapIndex::new` validation and checked offset arithmetic; O's tolerant parser is not an equivalent oracle.

Original test source to retain when selecting these mechanisms (not run):

- `identity.rs`: `retained_process_view_mount_table_controls_the_mapping_device` (675), `the_missing_mount_classifier_matches_only_the_missing_mount_error` (700), `an_early_zero_read_is_rejected_as_a_short_read` (721), `equal_fd_and_maps_keys_accept_without_consulting_the_probe` (861), `overlay_probe_match_accepts_a_split_identity` (877), `overlay_probe_mismatch_refuses` (892), `non_overlay_mismatch_refuses_without_probing` (906), `inconclusive_probe_refuses` (922), `real_probe_refuses_when_the_budget_is_exhausted` (1166). Scripted probe cases and live-file tests are distinct evidence tiers; neither was executed here.
- `maps.rs`: `parses_entries_and_preserves_path_bytes` (329), `unusable_file_paths_remain_file_evidence` (393), `malformed_nonempty_line_is_rejected` (417), `map_index_requires_sorted_non_overlapping_intervals` (429), `invalid_snapshot_is_distinguishable_from_valid_absence` (502), `map_index_rejects_file_offset_overflow` (549), `map_index_resolves_gaps_adjacency_and_exclusive_ends` (579).

### P discovery identity: preserve the newest retained-proof fixes

Keep nominated discovery blob `24de5ec261ac875dfc2186a7424bdc9ceb0d2d4e`. The ancestor blobs `3a99eaadcd26…`, `d2cd35865b37…` and `2a9bc7b0ed5b…`, and divergent-but-older `e9f97fc04d71…`, all lack the current retained-calibration mechanism. Historical task3 `aa8d9dda3e4a…` additionally lacks the later strict scan-file identity and nonunique-filesystem defenses. None supplies a replacement fix missing from the nomination.

The latest relevant change is nominated-history commit `6adbe91f118191dbb423c2b94c65d06c9e3c47bd` (reuse retained file identity during collection). `RetainedMappedIdentities::{from_targets,identity_for}` (170, 197), `MappedFile::may_retain` (496), `Entry::reusable_mapped_file` (747), and `pin_scanned_object` (2831) retain the original file Arc, cache only a proven allowed filesystem's mapping identity, and compare both the current and original held metadata pins. Btrfs may reuse the held proof with its fstat subvolume identity while still requiring each target map_files confirmation; overlay, collapsed, unknown and changed files do not gain this reuse. The borrowed lookup does not replace ownership with a pathname or bare maps key.

Preserve the counterexamples in `retained_mapped_identity_keeps_the_original_file_and_rejects_changes` (5196), `retained_mapped_identity_refuses_overlay_unknown_and_unproved_files` (5244), and `a_retained_pin_reuses_calibration_but_still_checks_the_scanned_file` (5287). The first test retains a deliberately different scripted calibrated identity, checks equal-byte distinct files, original-Arc custody, in-place changes and pathname replacement. This is scripted privileged-proof input with real regular files, not a live Btrfs/overlay qualification result.

Also preserve `the_pin_refuses_a_reopened_file_that_is_not_the_one_the_scan_read` (5351), `a_key_is_its_files_identity_only_on_an_allowlisted_filesystem` (5154), `two_mounts_of_one_filesystem_image_are_not_merged` (5767), `two_different_files_sharing_an_inode_number_are_never_merged` (5786), and `the_mapping_that_decoded_the_tables_is_the_one_kept` (5857). Nominated `789d017ed28f0ce0b5efc5a8c5b4415dd4877b33` supplies held scanned-file anchors; `3f556e9794939d5f0667faa08215eb36b08ce821` and `5c77efa02ddef10fcd1ed9d7b3110b7077735f07` supply the later maps-proof hardening. Older probes that repeat self-mapping are not interchangeable with retained calibration under a no-new-target-mapping contract.

Two task3 commits without individual exact patch matches are already integrated together: `9582fa353ae2c2219ecc179ef5eb9e90277efc3e` and `92e39abd78f02af2d25d814607e0b1634985441a` are included by nominated-history `509331a026477c6e699933fdcbc8686487914eb6`. Inspection confirmed the same added `PinnedContentKey`, `RetainedInventoryTarget::{content_key,same_object_as,same_kernel_file_as}`, `PinnedObjects::content_key`, and real-file test fixture. The latter fixes stale alias keys without treating another inode as a mutation of the original retained file. No separate cherry-pick is indicated.

To validate that conclusion rather than relying on commit subjects, inspected only relevant call sites/tests in P `src/discovery/inventory_attach_set.rs`, nominated commit as above, blob `040ba3e7f2d198af4ab5789b7e5d4a336745c7b7`, SHA256 `f9255695f5ad546c02c6addcd609569d28aafd3a2cf95ef94687d0279cd859f5`: comparisons at 666/699/881; `the_same_object_proof_needs_the_same_kernel_file` (2306), `an_impostor_under_a_stale_alias_key_leaves_the_object_extendable` (2448), `a_stale_alias_of_a_changed_object_is_dropped_not_blocked` (2585). These are original application regressions demonstrating primitive counterexamples; the inventory state machine remains product-local. The content key only narrows lookup; the held-file comparison supplies the needed physical-object check.

### P process: strict retained proc acquisition plus distinct fallback evidence

Keep nominated process blob `1e749777b110886ace2dbf7637008e4e326cbc49`. All four other process blobs are historical subsets, including divergent pre-linearization `64306a74e651…` and task3 `2ee0f4c7dab6…`. The pre-linearization lifecycle patch `e37a1d203c21373a737d3e92a495067bf203bc0a` has an exact selected-path patch equivalent at nominated-history `c2f83fea5c4d3629d882494afcc57a6657ae1f2c`. It is not omitted.

The newest strict-proc mechanism is in nominated-history `b992999b573a789310c9fcd3f98287fe86efdabb`: `PidPin::open_proc_dir` (781), `acquire_proc_dir_with` (726), `ProcPin` (756), relative member opens (761), `read_maps`/`read_maps_with` (835/843), and `mapped_file_identity` (901). It requires original pidfd plus birth evidence, PID/proc numbering agreement, liveness before/after acquisition and the retained directory's birth check. Maps are read relative to that directory through EOF with byte/deadline/liveness checks. It retains a struct-pid view, not an mm or immutable executable image.

Original regressions, all present in the nomination and not run: `pid_reuse_between_pin_and_proc_open_refuses` (945), `changed_admission_birth_during_proc_open_refuses` (961), `strict_proc_acquisition_requires_birth_and_original_pidfd` (973), `stable_proc_acquisition_keeps_directory_after_final_liveness_check` (987), `original_pin_death_during_actual_maps_read_refuses` (1004); `mountinfo_is_read_only_after_the_fd_is_open_with_retained_rechecks` (1416), `a_changed_mount_namespace_after_open_is_rejected_before_table_use` (1444), `a_generation_change_stops_before_the_next_target_action` (1481), `a_pidfd_poll_error_is_never_generation_evidence` (1511), `original_exit_probe_distinguishes_exit_from_transport_failure` (1529), `original_generation_state_distinguishes_exit_from_pid_reuse` (1555), `original_pidfd_is_the_only_signal_authority` (1620).

Keep the hostile-comm and reader regressions at `stat_read_retries_interrupted_reads` (1792), `stat_read_accumulates_short_reads_and_the_buffer_overflow` (1834), and `stat_fields_survive_a_comm_with_parens_spaces_and_a_fake_state` (1883). These guards appear in nominated-history `3c0d64d6564dda70c7a12cf578e17bbfb69424b1` and `42fa246cbcc309768f4bb405cffa8fa0cad5c7b4`; older variants using direct read_to_string do not supersede them. ScopeBase's read/work/memory limits still need their own frozen implementation; the donor's overflow tail can read beyond its first 4096-byte buffer.

The apparent task3-only pidfd denial tests are **already present**. Original `203a5089b910b09291948c2d463d367696f9952a` and confined-runner correction `73e62b9868ab7f2e51cc1ba71df7d21e1b4320bd` were integrated in nominated-history `c73c1370a06b95ec1511aa474ee05a2068cd7e10`. The whole denial-module slice (its leading documentation through EOF) is byte-identical between the nomination and task3 `40e0a557e20050c436c13052d3ef711f42ff23ec`; its slice SHA256 is in JSON. Preserve `process::tests::pidfd_denial::pidfd_denial_helper` (2054) and `real_pidfd_denial_preserves_proc_identity_without_signal_authority` (2422): raw syscall errno canary, EPERM and ENOSYS separately, per-thread filter-count delta under a confined runner, token/phase acknowledgements, live→zombie→reaped behavior, no signal/wait authority and owned-child cleanup. The helper is private/ignored and run by the parent regression; this report did not run it.

**Adaptation boundary:** donor `PidPin::open` (1084) permits pidfd-or-stat fallback, while `open_proc_dir` refuses the fallback. The fallback test deliberately recognizes that an unreaped zombie remains the same stat generation and is not proof of retirement. ScopeBase LX08's strict acquisition cannot silently inherit the permissive fallback; retain these counterexamples while using the specified denial/refusal result. `Tracker`, NOFILE raising, product policy and PidPin's signaling methods do not belong in observation authority. Original-generation liveness, birth identity, mount view and exec continuity must remain separate.

### P PID namespace module: no alternate omission, intake and lifecycle remain open

The nominated pidns blob is `89b3f1ca9ab871b7b3bd532eb7683a2520a30e9f`, SHA256 `49d4c3d381f82675484c17f26807a6d3fe95d4304f0cdeee74d90312d4b3aba9`. Its historical `427b2b860af8…` differs only by lacking `require_inventory_cgroup_numbering`; task3 lacks the module. The omitted intake entry identified in `next-obligations.md` remains real; this report does not add or accept it.

Preserve `classify`, `classify_proc_view`, `PidNumbering::agrees`, and composition of `ObserverPidNs::{Initial,Nested,Unknown}` with `ProcView::{Own,Foreign,Unserved}`. Initial namespace does not establish that the currently mounted procfs serves the observer's numbering. Named original test source: `the_initial_inode_is_the_kernel_abi_constant` (446), `only_the_initial_inode_classifies_initial` (456), `an_unreadable_namespace_is_unknown_never_initial` (471), `a_link_that_is_not_a_pid_namespace_is_unknown` (485), `only_this_namespaces_own_proc_classifies_own` (595), `a_foreign_proc_under_an_initial_observer_is_a_mismatch` (641), `an_unserved_proc_refuses_every_capture_by_name` (693), `the_numbering_composes_the_mounted_procs_view` (729), `the_test_seam_injects_on_this_thread_only` (776), `the_live_read_is_a_pid_namespace_link` (791). The full published-label/policy tests remain indexed in JSON and the existing preparation note.

`numbering()` (209) caches via OnceLock and explicitly excludes mid-run proc remount. ScopeBase must bind this observation to its observer/retained-proc epoch and detect/refuse invalid context changes, rather than importing global cached truth. `PidNumbering::agreeing()` is a public constructor in the donor; it is not production observation authority in ScopeBase. The thread-local test seam's leaked values are a test expedient, not a lifecycle design. Refusal wording, cgroup/CLI recommendations and evidence schema remain product-local.

### O process pin is not a regular-file pin

`src/pin.rs` is byte-identical across the inventories: keep blob `19d9c6cfeef4b11fdbd4c0c5c60006e1a34e0d47` as provenance. `TargetPin`, `pin` (69), `parse_starttime` (45), `verify` (100), and `ExternalTarget` (119) describe process identity/observation. `ExternalTarget` deliberately exposes no signal/wait method. Preserve `pin_self_verifies` (145), `external_target_adopts_without_signaling` (154), `dead_pid_fails_to_pin` (163), and `stat_parse_tolerates_tricky_comm` (170).

The code brackets pidfd acquisition with starttime reads; `TargetPin::verify` rechecks starttime but does not poll the pidfd for exit. It neither retains procfs directory authority nor establishes unchanged executable image. Comments describing live tasks or unique starttime must not be promoted into stronger library guarantees. P's strict proc/birth/liveness regressions supply the richer selected mechanism; O's external/owned type separation supplies another required boundary. No alternate O process pin fixes this limitation.

### O regular-file acquisition and bounded bytes

Keep nominated plan blob `fc1b317bada4cd01ecd272b74cc4f64c9782ffb6`. Older main `9db96ed0bac2…` lacks bounded reads and the later ELF cache; older P7 `025c483e6b51…` has the cache but lacks bounded reads. Both are ancestors. R14 alternate commits have exact nominated-history selected-path equivalents: `ca963d57a9f138cc1fb746d834da9ad955a93b4e` → `2643dae0386b6c2cb8321494929f8dfaf7a773c2`, and `9aa0156454e0111c15d56b5f3ef2c6363f598a99` → `00d1a959974bde9937069b83151676a81dddea96` for the changed test source. No R14 fix is missing.

File symbols: `PinnedFile` (206), `link_path` (219), `resolve_pinned` (231), `resolve_pinned_retry` (256); byte symbols `FileBytes` (288), `bound_bytes` (310), `ReadBoundedSource` (339), `read_bounded_from` (373), `read_file_bounded` (425). The pin retains the opened FD through detach, uses fstat identity and an FD-path attach, and retries a bounded number of open attempts. It must not be replaced by `TargetPin`. Conversely O's direct `File::open` is not P's nonregular-safe O_PATH acquisition; keep P's FIFO/device refusal mechanism for the library.

The bounded reader rejects huge advertised lengths before allocation/read, reads at most cap+1 for overflow detection, compares before/after encoded stat-device/inode/length, and shares immutable bytes through Arc. It does not promise a deadline interrupts a blocking read, nor does equal identity/length alone authenticate same-size content. The 128 MiB O cap and 256 MiB P cap are application policy, not a single inherited ScopeBase default.

Original `src/plan.rs` tests: `h4_t2_pin_open_retries_bounded_then_fails` (998), `bound_bytes_requires_identity_match` (1058), `h5_t2_bound_bytes_refuses_xfs_same_ino` (1092), `resolve_pinned_stats_the_open_file` (1124), `elf_cache_parses_once_per_identity` (793). Original `tests/site_identity.rs` R14 tests (present in nominated blob `644c2cf95406222434bc6f9b4d2982c4e0870f88`): `r14_bounded_read_accepts_exactly_at_cap` (1221), `r14_bounded_read_refuses_cap_plus_one` (1237), `r14_bounded_read_refuses_huge_advertised_length` (1247), `r14_bounded_read_refuses_growth_mid_read` (1287), `r14_bounded_read_refuses_replacement_mid_read` (1322), `r14_bounded_read_empty_file_with_zero_budget` (1345), `r14_legacy_wrapper_caps_single_object` (1358), `r14_fix_filebytes_clone_shares_allocation` (1382). Their scripted growth/replacement and metered no-read controls must remain distinguishable from real filesystem tests.

The other site-identity differences are already retained application regressions: conservative duplicate ambiguity in both orders (`duplicate_merge_preserves_ambiguity_in_both_orders`, 588) is integrated by `afe955835397…` from alternate `b3e563a9beaa…`; installation timestamp cases (`attach_stamps_installed_at_on_first_bind`, 937, through `straggler_bucket_carries_installed_at`, 1096) exist in the nominated source and P7. These attach/evidence policies do not justify a universal Linux-file state machine.

### O maps, ELF and identity-domain audit

All inventoried refs share maps blob `7df324a9fde5c3021ab5299cae679e19140d7159` and ELF blob `485c2a10e4302a8012aeb77e256321ccd1790c39`. No alternate omitted fix exists in these paths.

`maps::provider_mapping` (63) deliberately avoids comparing maps-text devices with stat devices. It uses the provider's current stat and the selected mapping path's stat in the same namespace, and refuses unavailable/deleted/foreign paths; pathname matching is not a fallback despite an older introductory comment. Preserve `mapping_lookup_rejects_stale_pathname` (142), `mapping_lookup_rejects_cross_filesystem_ino_collision` (194), `mapping_lookup_binds_mapping_path_identity` (217), `mapping_lookup_by_same_file_identity` (259). This is an application co-location assumption and path-stat join, not P's retained map_files proof or cross-namespace authority. O's `parse_maps` (24) skips malformed rows and defaults some parse errors to zero; P's rejecting byte parser/MapIndex is the selected strict source, with O's rejection counterexamples retained.

ELF `vaddr_to_offset` (205), `offset_in_x_segment` (214), `read_build_id` (312), `parse_build_id_notes` (327), `parse_elf` (368) provide byte/object checks only. Tests include `non_elf_fails_closed` (440), `build_id_note_parses` (457), `plt_stubs_valid_on_libc` (637), `header_only_elf_has_no_imports` (656), `import_scan_fails_closed_on_non_elf` (669), `dynsym_func_entries_sorted_unique_bounded` (675). The OpenSSL version/import/dispatch interpretation remains product-local and is not required to implement a held file.

All nine audit blobs define the same `h5_t3_every_device_site_names_one_domain` (105 in nomination) with different source-text pins for their branch's reached call sites. The nomination `6009d75a55f8c056e9b2bd096264e00ec44dea24` incorporates R03 reinstall, R05 ENGINE, R06 staging, R14 bound-read, R19 traversal and R20 cache/freshness changes. Older audit tables must not be copied over it: that would remove pins for already-integrated mechanisms or assert obsolete source spellings. Most divergent audit commits have exact nominated-path equivalents. `db8e5c1dcd360f62ce3b041f3ad1bf028fe41950` and nominated `131012a167adcbb2783170f4ad1d3985701802f2` do not have identical patch IDs because their surrounding ENGINE rows differ; direct diff inspection confirms the same three added/changed cache/stat/staging pins. This is context-shifted integration, not an omitted semantic fix. An audit-table update proves nothing about uninspected runtime code; its product-specific pins require retargeting to actual library call sites after implementation.

### O child custody and selected lifecycle regressions

Keep nominated target blob `9d9fab7530a3f8b27fc02bf74baee934743b6e33`. Main ancestor `21d5f8d98ef3…` predates controlled setup, pre-stop guard, staged sinks, registry and related regressions. Divergent R06 `c53a691d06bc…` contains the first custody fixes; all six changed-path commits have exact equivalents in the nomination. The nomination additionally fixes relative/absolute and root-parent fencing aliases and early cancellation/expiry cleanup (`d2b596bea58f59f1e02cc305e77668722f2371b8`, `27b74f467376a0f9f807f6c0b3291b1f82718715`). Retain `normalize_setup_key` (651), registry ownership, worker-owned disposal, `PrestopGuard`, controlled close and honest unresolved/partial cleanup outcomes if this subsystem is selected for LX09. These are not held-file API prerequisites and the output-destination/CLI rules remain product-local.

Original target-unit regressions: `setup_key_root_parent_aliases_key_identically` (2331), `setup_key_unifies_relative_and_absolute_spellings` (2362), `control_early_cancel_and_expiry_run_on_exit` (2376), `control_discarded_result_destroys_on_worker` (2105), `registry_fences_distinct_ids_and_releases` (2414). The R06 branch lacks the first three; they are present in the nomination.

`tests/target_lifecycle.rs` nomination `0b1f46c1bd052fbaf6c592eaa3c148133fd94193` contains all tests in its main, R06 and R20 variants plus the later F1 first-attempt environment regression. R06 setup tests include `prestop_deadline_reaps_child` (865), `setup_cancel_before_fork_spawns_nothing` (1049), `pinned_sink_survives_path_replacement` (1247), `pinned_sink_survives_closed_stdio` (1386), `fork_failure_disposes_sink_under_control` (1457), `abandoned_prep_worker_never_truncates_successor` (1502), `file_truncate_runs_under_setup_control` (1558), `abandoned_late_worker_never_truncates_successor` (1653), `abandonment_bounded_with_stuck_worker` (1740), `retry_setup_refuses_while_prior_worker_live` (1901), `staging_namespace_dest_refused_before_creating` (2039). A timed return can leave a worker owned elsewhere; tests must not turn it into a retirement assertion.

Process/image/custody examples retained: `external_pid_target_is_never_signaled` (359); `r20_exec_replaces_image_custody_survives` (2180) observes exec to sleep while preserving owned-child custody/reap/status, not stable image authority; `r20fix_kernel_lifecycle_witnesses_real_fork_exec_exit` (2224), subscription/terminal-watermark tests (2425–2571), `kernel_subscribe_in_user_namespace_fails_closed` (3102). `f1_runner_requires_object_env_on_first_attempt` (2670) is absent from R20 branch `01f9e673f372…`, but present in the nomination, so no recovery from the alternate is required. Connector/live vehicle/environment gating in this donor test source remains explicit. None was run here; an environment-gated expected refusal is not a supported kernel facility.
