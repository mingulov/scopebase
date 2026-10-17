# OSSLscope reuse feasibility, 2026-10-17

Scope: read-only source/history inspection over `ssh -o BatchMode=yes -o ConnectTimeout=15 -l agent um790`. No remote builds, tests, experiments, fetches, resource changes, or source writes were performed. Findings below are static evidence and extraction recommendations, not fresh runtime qualification. Other projects' actual demand must be established by their own lanes.

## Source custody and current state

| Tree | Branch / full HEAD | Observed state |
|---|---|---|
| `/work/osslscope-ws` | `main`, `40369e5f6b93aa7925cda28c21e17ff57afc67d4` | Tracked files clean; three untracked preserved `vm-operational/` directories: `2026-09-18-sb-smoke`, `2026-10-09-continuation-a`, `2026-10-10-continuation-b` |
| `/work/osslscope-ws/osslscope` | `task/p7-traversal`, `1a481831a85375ecb2d69ca65618d37c846de8b3` | Clean; product root is older than the integrated candidate |
| `/work/osslscope-ws/osslscope/.worktrees/preview-r21` | `task/integration-preview-r21`, `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a` | Clean; authoritative latest integrated candidate; handoff says LOCAL-ONLY, coordinator verification/re-review pending; a matching remote-tracking ref also exists (see census below) |

The workspace has seven other worktrees, and the product has sixteen task worktrees plus the preview. They were inventoried with `git worktree list`; no worktrees were modified. Workspace `AGENTS.md` identifies the private workspace/public product split and says to reuse sibling concepts without copying files. Product `AGENTS.md` requires preserving the capture allowlist, Linux-first uprobes, and explicit approval for privileged/container experiments. This research does not implement extraction.

Authoritative state: `/work/osslscope-ws/docs/HANDOFF.md:17-19` explicitly says round-3 candidate `4bcb24c` is paused before coordinator gates and re-review. Lines 23-44 distinguish older accepted task work and 16/16 task-branch CI from R21's `DONE_WITH_CONCERNS`: COMPLETE 0/10; physical ledger, hot-key/per-key, P6-live, callback-latency distribution, and second-profile obligations remain. Lines 104-119 require round-3 verification, re-review, sealing, and targeted live rerun before integration. These statements override historical completion language and test-count commit titles.

All product references below use **P = `agent@um790:/work/osslscope-ws/osslscope/.worktrees/preview-r21` at `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a`**. Workspace references use **W = `agent@um790:/work/osslscope-ws` at `40369e5f6b93aa7925cda28c21e17ff57afc67d4`**. `P/src/pin.rs:69` thus names that exact remote file and line, not a local source copy. Commit abbreviations are product commits unless identified as workspace. Source was rechecked clean at the end of inspection.

## Concrete extraction candidates

### O1. Process identity and authority separation

**Source:** `P/src/pin.rs:18-22,43-104,118-137`: `TargetPin`, `pin`, `parse_starttime`, `verify`, `ExternalTarget`.

`pin` samples `/proc/<pid>/stat` starttime, opens a pidfd, then samples again; `verify` rejects changed/missing starttime. The stat parser splits after the final `)` so command names containing parentheses and spaces do not shift field 22. `ExternalTarget` has no signal/wait operation, preventing accidental custody of a foreign `--pid` target through that API. This is useful general Linux/Rust infrastructure for all observers, independent of OpenSSL and BPF.

**Preserve:** `pin_self_verifies`, `dead_pid_fails_to_pin`, `stat_parse_tolerates_tricky_comm`, and `external_target_adopts_without_signaling` at `P/src/pin.rs:144-176`; custody integration from commit `1cbb30a` and merge `17eb032`.

**Boundary / recommendation:** extract a small Linux process-identity crate, with medium difficulty because callers must still validate identity around reads and emission. Do not promise cross-boot or cross-restart identity: this type stores PID/starttime and a live fd, not boot/session/namespace identifiers. `verify` itself rechecks stat rather than polling the pidfd, and process identity does not distinguish exec; exec belongs to O3. A long-lived service needs an explicit observer-session identity and lifecycle policy.

### O2. Owned child custody and cancellable setup

**Source:** `P/src/target.rs:30-66,185-232,637-700,745-809,1325-1365,1724-1890`: `OwnedTarget`, `CustodyState`, `WorkloadDest`, `spawn_stopped_with_control`, `normalize_setup_key`, `release`, `resolve_setup_failure`, `finish_observation`, `Drop`.

The owned child progresses stopped -> released -> reaped/detached; an external PID cannot be adopted into this type. Pre-exec strings and output fds are prepared before fork; the child only performs the restricted setup path. Failed setup resolves stopped-child custody; released running applications are detached. File output uses a distinct staging inode, retained fd, atomic publish, and process-wide per-destination registry. Cancellation must not block behind a stalled filesystem worker holding the publication lock.

**History/tests to carry:** `b47339d` immediate pre-stop custody; `73123eb`/`22701f3` review fixes; `4144a49` bounded truncation; `9c08f26` staging; `9317c82` replaces lock-across-rename with lock-free abandonment and a registry; `d2b596b` and `27b74f4` normalize lexical aliases and clean early exits. Tests include `fifo_setup_cancel_reaps_child` (`P/tests/target_lifecycle.rs:802`), `prestop_deadline_reaps_child:865`, `pinned_sink_survives_path_replacement:1247`, `pinned_sink_survives_closed_stdio:1386`, `abandoned_late_worker_never_truncates_successor:1653`, `abandonment_bounded_with_stuck_worker:1740`, and `retry_setup_refuses_while_prior_worker_live:1901`.

**Boundary / recommendation:** medium/high extraction difficulty; keep custody separate from the optional output-publication subsystem. Preserve the explicit signal-ownership assumption at `target.rs:13-18`: external SIGCONT between fork and failed-setup resolution is outside the model. External writers are not fenced, symlinked-parent aliases remain separate keys (`:648-650`), and a forever-stuck worker holds its registry entry forever. The exact post-check/publish residual is deliberately exercised at `:737-744`; do not rename this a transactional filesystem API. Useful for all spawn-based Linux tools, but package policy, exit 126/127 wording, and workload-output defaults remain product adapters.

### O3. Kernel process lifecycle transport with explicit loss and close evidence

**Source:** `P/src/capture.rs:1031-1094,1414-1447,1753-1805,2384-2562`: `LifecyclePort`, `LifecycleDelta`, `SeqState`, `KernelLifecycle`, `LiveLifecycle`, `ConnectorFacility`. Additional helpers: `scan_ack:1461`, `drops_delta:1509`, `plan_close_cpus:1589`, `watermark_burst:1622`.

This is **proc-connector/netlink, not BPF**. It validates correlated subscription acknowledgments, tracks per-CPU sequence gaps and socket drops, retains fork-observed descendants through double-fork/reparenting, distinguishes process forks from same-TGID threads, preserves subscription-time CPU lanes at close, generates terminal watermarks, and balances LISTEN with unsubscribe. Polling fallback always carries PARTIAL because between-poll activity can disappear. Missing terminal evidence and pending bounded drains are separate from known drop counts.

**Preserve:** commits `131012a`, `2700949`, `5d8f49b`; tests `r20fix_kernel_lifecycle_witnesses_real_fork_exec_exit` (`P/tests/target_lifecycle.rs:2224`), `kernel_unsubscribe_is_accepted_live:2425`, `kernel_live_target_first_sighting_gaps_prefix:2475`, `kernel_subscribe_watermarks_all_cpus_pre_activity:2528`, `kernel_close_drain_establishes_terminal_watermark:2571`, `kernel_subscribe_in_user_namespace_fails_closed:3102`; controller tests `lifecycle_exec_witness_fences_without_snapshot_change` (`P/tests/capture_controller.rs:6943`) and `exec_witness_consumed_before_signal_cut_survives_to_close:8329`.

**Boundary / recommendation:** extract only after a second consumer proves the transport contract; high difficulty. This observer detects and reports descendants but does not capture multiple targets. Watermarks create/reap helper children and depend on CPU affinity/topology and connector availability. Restricted environments are supported PARTIAL, not zero-loss. Reusing the `known` PID set for a persistent service would require stronger incarnation and retirement handling; no restart continuity follows from this implementation. Good candidate for a shared Linux lifecycle layer with transport-independent loss semantics.

### O4. Descriptor-bound attachment identity and stable physical cookies

**Source:** `P/src/plan.rs:93-125,138-189,193-240` (`StableCookies`, device encodings, `PinnedFile`, `resolve_pinned`); `P/src/count_session.rs:332-374`; `P/src/discovery/maps.rs:63-115`; `P/src/discovery/session.rs:3824-3875` (`LinkSet`).

Open the file first, fstat that fd, compare the expected identity, then attach through `/proc/self/fd/N`. Keep the fd until after the link detaches. `CountSession` deliberately declares links before file pins so Rust field destruction detaches links first. Physical `(device,inode,file offset)` cookies survive pathname aliases; a replacement inode receives a new identity. Maps-rendered device strings and stat device identity are distinct domains, especially on overlayfs; current matching deliberately compares stat-derived identities.

**History/tests to carry:** `07377c2` introduced sampling/quarantine, superseded by `82f8b4b` descriptor custody; `da98030` descriptor-domain mapping; `e1771a7` identity-domain audit. `W/docs/2026-10-11-h4-descriptor-custody-design.md:14-67` explains the reproduced A->B->A attack against before/after pathname sampling and why fd pinning removes post-attach quarantine. Its lines 6-10 report host spike evidence and explicitly leave guest proof as follow-up. Tests: `h4_t1_mid_attach_swap_binds_pinned_inode_via_fd_path` (`P/tests/count_deadline.rs:599`), `h4_t3_pin_survives_path_deletion_until_session_drop:552`, `h4_unbound_cookie_hits_route_unattributed:668`, `h5_t3_every_device_site_names_one_domain` (`P/tests/identity_domain_audit.rs:105`).

**Boundary / recommendation:** strongest extraction target after qualification, medium difficulty. Export typed identity domains and an owning pinned-file/link handle rather than raw path strings. Keep naming, provider classification, and address-to-provider policy outside. FD pinning fixes replacement identity, not in-place content mutation or cross-session cookie uniqueness. Namespace-unresolvable or deleted paths fail closed in `provider_mapping`; do not silently add pathname fallback.

### O5. Bounded, identity-bound file reads and verified cache

**Source:** `P/src/plan.rs:288-310,331-437` (`FileBytes`, `ReadBoundedSource`, `read_bounded_from`, `read_file_bounded`); `P/src/capture.rs:2604-2701,4411-4417,4483-4583` (`ProcPort`, `FileStat`, `read_relevant_files`).

The general primitive fstats an open source, rejects an oversized advertised length before allocation, reads at most cap+1, checks the final identity/length, and returns immutable shared `Arc<[u8]>`. The consumer enforces remaining per-round budget before each read; caches validate device/inode/size/mtime and discard proven same-size read races, with explicit discovery loss. This is broadly reusable in Linux inventory/inspection, including non-BPF tools.

**Preserve:** `4139b0f` inode-bound fingerprints, `82fa5d8` relevance/cache scoping, `2643dae` before-allocation budgeting, `00d1a95` shared payload and cached-budget corrections, R20 freshness commits. Tests: `r14_bounded_read_refuses_huge_advertised_length` (`P/tests/site_identity.rs:1247`), growth `:1287`, replacement `:1322`, clone shares allocation `:1382`; `lifecycle_raced_file_read_is_discarded_loud` (`P/tests/capture_controller.rs:7487`), cached remaining-budget overflow `:8782`.

**Boundary / recommendation:** low/medium difficulty for the pure read primitive; medium/high for the relevance cache. Extract the primitive first, then compose cache policy separately. The read primitive checks identity and length, not content stability; the caller adds mtime checks. Same-size writes with unchanged/restored mtime are not proven impossible by this scheme. Do not describe it as a cryptographically immutable snapshot. The 128 MiB per-object cap and relevance taxonomy are policy, not universal defaults.

### O6. ELF inspection and attach-offset validation

**Source:** `P/src/discovery/elf.rs:15-81,103-145,205-220,246-327`: dynamic/symtab lookup, `plt_stub_offsets`, `vaddr_to_offset`, `offset_in_x_segment`, `needed_libraries`, `rpath_runpath`, `read_build_id`, `parse_build_id_notes`.

The useful extra value beyond an ELF parser is the attach-oriented contract: executable LOAD validation, symbol type filtering, and x86-64 PLT bytes -> GOT slot -> relocation-name resolution. Positional PLT arithmetic was wrong for split `.plt.sec` versus traditional `.plt`; commit `e805ca4` corrected it. Tests include `plt_chunk_decode_shapes` (`elf.rs:604`), `plt_resolves_self_imports_in_x:577`, `plt_stubs_valid_on_libc:637`, and `header_only_elf_has_no_imports:656`.

**Boundary / recommendation:** adopt the existing parser dependency (`goblin = "0.10"`, `P/Cargo.toml`) and extract small attach helpers rather than create another ELF parser. Medium difficulty because x86-64 byte patterns, little-endian note parsing, integer-range handling, and malformed-input behavior need explicit support contracts. `vaddr_to_offset` uses `p_memsz`, whereas executable file-offset validation uses `p_filesz`; keep those meanings distinct and audit overflow/BSS behavior before advertising a generic hostile-ELF API. OpenSSL version inference (`max_openssl_version:356`) stays product-specific.

### O7. Raw BPF syscall/UAPI bindings and functional feature diagnosis

**Source:** `P/crates/bpf-sys/src/lib.rs:94-150,169-224,239-322,338-490,492-534`: `map_create`, map access, `prog_xlated_bytes`, `btf_load`, program loads, multi-entry/return link creation. `P/src/doctor.rs:258-308,617-697,959-1018`: functional probes and denial classification.

Existing `ossl-bpf-sys` is already a dependency-lean crate (`libc` only), uses owned fds, zeroed UAPI attributes, and documents per-CPU map buffer sizing. The return-link member flag belongs at attribute offset **52**, not the common flags at offset 12; commit `86f4ca9` fixed the resulting EINVAL. Program-image reads reject a successful syscall that withholds the image (`check_xlated_copied`), rather than returning the zero-filled buffer as real instructions.

**Boundary / recommendation:** medium extraction difficulty. Prefer contribution of proven missing functionality and fixtures to the upstream library in use; the repository source establishes a problem with its pinned Aya 0.14, not current upstream status. If a local shared crate is necessary, add checked public argument validation (current `link_create_multi:471` asserts nonempty/equal arrays and `:481` casts length to u32) and keep debug-only token minting outside the production default. Feature verdicts should distinguish unsupported functionality from privilege/LSM/seccomp denial; preserve unit tests around that distinction. No version-string-only admission.

### O8. Restricted ELF-to-BPF linker/loader and callback metadata

**Source:** `P/src/loader.rs:1-13,1140-1427,1516-1975,1976-2078`: `prepare`, `check_site_contained`, `call_target`, `func_ptr_target`, `apply_func_ptr`, `check_calls_rewritten`, `check_func_ptrs_rewritten`, `synth_btf`, `load_prog`.

The custom loader exists because the pinned Aya path supplies the wrong expected attach type for multi-links. It links a restricted object shape, checks map dimensions and license, validates relocation ownership/alignment, rejects stale unresolved calls/function pointers, and creates minimal BTF/func_info for address-taken `bpf_loop` callbacks. Here “callback” means a **BPF helper callback**, distinct from the observed OpenSSL callback identity in O9/O10.

**History/tests to carry:** `93ff46e` verifier-safe classifier/loader on 6.12; `8cba9de` helper-callback BTF; `ea75eaa` execution/image/cost proof; `5900913` duplicate-name/containment/misalignment fixes; `f74f291` mixed callback graph and malformed metadata; `c8c2555` follow-up. Unit negatives at `P/src/loader.rs:3110-3611` cover function pointer/call/map site alignment, reserved bytes, cross-function sites, and huge offsets. Live-gated tests at `P/tests/d_btf_load.rs:250,405,452,652,706` cover callback load, N*M execution, kernel translated-image equality, malformed func_info rejection, and verifier cost. Tests were inspected, not executed.

**Boundary / recommendation:** high difficulty and maintenance cost; this is not a general CO-RE/BTF/object loader. Upstream the minimal missing support and adversarial corpus when feasible; otherwise extract a deliberately restricted loader with an explicit accepted-object specification and versioned fixtures. Keep product map/program inventories outside it. Quiet-first program load avoids valid programs failing solely from verifier-log ENOSPC; retry with logs only on failure (`loader.rs:2034-2075`). Do not lose that behavior during cleanup.

### O9. Generation-aware count session, attach isolation, and conserved attribution

**Source:** `P/src/count_session.rs:1-36,98-173,332-374,490,735,850-870`; `P/src/plan.rs:675-707` (`bisect_attach`); `P/crates/ebpf/src/bin/count.rs` and shared key/value ABI in `P/crates/ebpf-common/src/lib.rs:9`.

`CountBackend` separates pure routing from live BPF handles and a fake backend. Cookies denote physical sites; changed candidate sets/content fingerprints version at a fence. Retired `(generation,cookie)` provenance routes stragglers; totals are delta-read without deleting keys that in-flight increments can still update. Unbound/future cookies become explicit unattributed loss. Kernel admission uses `[start_ns,deadline_ns)`. Multi-attach bisection salvages good sites on every non-permission error, including the observed RHEL errno 524 (`ce9def4`); it costs at most 2n-1 attempts, not O(log n) total work.

**Preserve:** `2573b8f` immutable count sessions; descriptor-custody history O4; two-CPU first-hit insertion regression tests `r04_two_cpu_first_hits_both_count_fresh_key` (`P/tests/count_deadline.rs:966`) and fresh-generation `:985`; `replacement_inode_gets_new_cookie` (`P/tests/site_identity.rs:261`), aliases `:320`, changed candidates `:420`, fingerprint change `:752`, future-generation loss `:889`.

**Boundary / recommendation:** medium/high difficulty. Extract generic identities/counters behind product-supplied metadata; retain OpenSSL provider/op/algorithm adaptation in OSSLscope. Critically, close is **best-effort**, not an execution barrier: three bounded re-drains can miss an admitted hit completing afterward. `close_delayed_hit_after_drain_is_uncounted_countermodel` at `P/tests/count_deadline.rs:1273-1284` explicitly demonstrates invisible late counts and explains the controller's death+reap barrier for owned exits; living-target closes carry other PARTIAL evidence. A shared API must expose this closure limitation, never return an unexplained “exact final count”. Cookie/generation uniqueness is within one session; cross-restart persistence is not implemented.

### O10. Evidence uncertainty algebra and nonduplicating shared-callback claims

**Source:** `P/src/evidence.rs:25-133,159-228,303-386,733-944`: `SiteKey`, `CandidateIdentity`, `CandidateCoverage`, `SiteExecution`, `match_bounds`, typed counters, finalization. `P/src/policy.rs` supplies OpenSSL-specific predicates.

A shared physical callback's count is conserved once, rather than replicated for every possible algorithm. Complete candidate sets support definite/possible bounds; unknown sets cannot prove a positive lower bound or absence; `AmbiguousComplete` deliberately cannot turn a retained minimum algorithm class into a definite claim. Loss and activity counters remain separate and carry units/source. This pure Rust uncertainty model can serve PKCS#11 aliases, kernel algorithm aliases, or memory attribution if their domains fit the same evidence semantics.

**Preserve:** `00b135d` mixed-class withholding and R01 identity work; `P/tests/evidence_model.rs:108` shared-site conservation, `:135` ambiguous require, `:176` fence candidates, `:233` unknown coverage, `:471` within-alias ambiguity, `:522` loss versus activity, `:590` zero-call unknown candidates. Keep schema/semantic validation fixtures with the model; late schema repair `9f04a31` shows code and artifact shape can drift independently.

**Boundary / recommendation:** medium difficulty. Extract parameterized bounds/counter/window concepts, not the entire CBOM/schema/policy vocabulary. OpenSSL provider class, operation/function IDs, FIPS state, and algorithm taxonomy stay product-specific. A generic finalizer must accept an explicit closure/coverage proof; it cannot infer absence from a quiet ring or zero counter. `AmbiguousComplete` is specific to information deliberately discarded by the producer and should not become a vague catch-all enum.

### O11. Pure supervision and observed thread-incarnation registry

**Source:** `P/src/scan/governor.rs:14-103,126-181` (`DutyThrottle`, `StormDetector`); `P/src/scan/registry.rs:29-123` (`BirthState`, `TidSource`, `ProcTaskSource`, `program_births`); producer use at `P/crates/ebpf/src/bin/members.rs:139-154,502-568`.

The throttle uses injected time and hysteresis; the storm detector computes rate from actual sample spacing, including sparse 250 ms polls. The registry increments a birth when a TID disappears and later reappears, retains orphan rows, freezes at u16 exhaustion, and samples `/proc/<target>/task`, not the observer's threads. Producer sequences combine birth:16 and counter:48; map-capacity failure refuses admission.

**Preserve:** `204b8c8` admission plane and `90fa77e` supervisory integration; tests in `governor.rs:189-271` (hysteresis, sustained quiet) and `registry.rs:151-227` (birth minting, absence/reappearance, saturation, duplicate input, target source).

**Boundary / recommendation:** extract the pure rate/hysteresis algorithm with injected cost thresholds, low/medium difficulty. The constants (15 us fixed + 12.7 us/slot) estimate this traversal's cost and are not portable measured latency. Arithmetic and bounded queue/input contracts need auditing before accepting arbitrary consumer values. Treat birth polling as an observed-incarnation heuristic: a complete death/reuse between polls is not identified by this state machine. Do not market it as a universal task lifetime solution. Keep its BPF map programming adapter separate.

### O12. Causal event joining, late corrections, and shutdown salvage

**Source:** `P/src/scan/oracle.rs:1-79,655-725,994-1024,1123,1619,1763,1925`; `P/src/scan/backend.rs:598-660`: `Oracle`, `ScanBatch`, `Correction`, `finish`, `join_settle`.

An invocation joins explicit CALL/RET/GUARD/ALG/ROW evidence by `(tid,seq)`. Silence is not completion: slot coverage, a verified terminator, retirement, absence of relevant loss, and generation consistency all matter. Loss/truncation persists across drains. Per-TID retained closes prevent unrelated traffic evicting a nesting partner; late contradictory evidence emits corrections that every downstream holder must apply. Shutdown freezes control first, settles/drains, samples the clock after settling, runs the terminal backstop even on errors, and salvages prior evidence before propagating failure.

**Preserve:** `90fa77e` causal joins; `18ee661` soundness fixes; `43885c1` stale-snapshot race; `310d230` post-settle clock; latest unverified `8d4154b` preserves settle delta on CTRL failure and `f8ba5d2` treats unavailable fault views as uncertainty. Tests: `fix3_consumed_taint_corrects` (`P/tests/scan_oracle.rs:1195`), `fix4_recent_survives_foreign_flood:1244`, `r35_successor_holds_predecessor_for_next_poll_fault:2336`, `r36_every_walking_prefix_status_vetoes:2581`, `r3_backstop_marks_unavailable_fault_view_uncertain:2734`. Commit `7d6d64c` adds producer-admissible fixtures; a synthetic test that emits wire-impossible data is not evidence of producer correctness.

**Boundary / recommendation:** preserve as reference architecture and reusable protocol-test corpus first; high extraction difficulty. The oracle is tightly coupled to OSSL_ALGORITHM arrays, 512 member programs, operation loss maps, and traversal cache healing. Extracting a generic join engine prematurely risks losing the proof obligations. Pure data structures and correction propagation are more reusable than the whole protocol. The latest fixes are present in source but not yet requalified, per the handoff.

## LLVM, kernel, and architecture compatibility

The inspected host manifests pin Rust 1.88.0 / edition 2024 and Aya 0.14.0; the detached BPF workspace pins nightly-2026-05-20 with rust-src, Aya eBPF 0.2.1, and GPL-2.0-only program sources. `P/Cargo.toml:29-35` intentionally excludes the BPF workspace so host `cargo test` does not compile no_std BPF targets. `P/docs/build.md:19-24,61-69` and `.github/workflows/check.yml:26,80` identify bpf-linker 0.10.4 and two lockfiles. A shared host library should not force this BPF toolchain on every consumer.

The LLVM warning is a **documented linker dlopen fallback**, not proof that arbitrary LLVM mismatches are harmless: `P/scripts/build-dev.sh:319-326` recognizes the warning and records it after a successful build/artifact path extraction; `P/docs/build.md:99-105` says not to upgrade toolchains just for it. This research ran no linker and establishes no current host LLVM health. Extracted loader compatibility must bind compiler/linker version, accepted ELF shape, relocated instruction image, synthesized BTF, kernel verifier acceptance, and actual callback firing. The `d_btf_load` corpus supplies separate tests for these layers.

`P/docs/usage.md:204-209` describes x86-64 Linux, functional capability admission, 6.9+ support floor, and 6.12-LTS oldest tested. Older `P/docs/overhead-matrix.md:30-62` includes historical 6.9/6.12/6.18/6.19/7.x platform cells and a 6.9 CET/nested-virtualization overhead outlier; these are historical product claims, not evidence for the latest candidate or for extracted code. The newer wording and older matrix do not justify a universal compatibility claim. `P/docs/what-it-proves.md:80-92` excludes pre-6.9 and non-x86-64; no architecture expansion is implemented here. Feature availability, verifier acceptance, callback semantics, and performance must be tested separately; feature backports or a kernel release string alone establish none of the others.

## Product-specific pieces and apparent crates that are not reusable implementations

- Keep provider dispatch traversal, OSSL algorithm/function taxonomy, alias classifier, built-in build-ID enrollment, legacy ENGINE/low-level tripwires, FIPS policy, privacy allowlists, and CBOM formatting in OSSLscope adapters. Sharing transport does not establish identical privacy permission across products.
- `P/crates/manifest/src/lib.rs:1-3` is a placeholder, not a working manifest library. `P/crates/ossl-discover/src/lib.rs:1-6` exports only a fixture directory constant. Crate names and plans must not be mistaken for extracted functionality.
- `P/build.rs:1-8` is also a placeholder; the real pinned build workflow is `scripts/build-dev.sh`. `P/docs/build.md:78-87` still describes the harvest/count pair, while later candidate installer work includes the members object (`43900fe`). Preserve and reconcile build/install documentation with behavior before promoting it as a shared artifact workflow.
- Existing non-goals include multi-target/cgroup attach, daemon posture, always-on production, and non-x86-64 (`P/docs/what-it-proves.md:49-57,89-92`). Restart continuation is therefore a new design requirement, not an existing guarantee ready to extract.

## License metadata and provenance

Observed metadata only, no legal conclusion: `P/Cargo.toml:6`, the four host/shared crate manifests, their source SPDX tags, public docs/scripts, and `LICENSE` identify **GPL-3.0-or-later**. `P/crates/ebpf/Cargo.toml:5` and BPF program headers identify **GPL-2.0-only**; `P/README.md:137-142` states this split. `crates/ebpf-common` is tagged GPL-3.0-or-later even though BPF programs depend on it; any extraction must preserve and deliberately review this metadata boundary. Relicensing history is commit **`ddff57fd180cc8c596e4bef4cd82bff6ef38de14`**. All current crate manifests use `publish = false`; there is no published shared-library release implied here.

A reusable unit should carry the origin SHA, relevant fix chain, SPDX headers, accepted behavioral contract, negative tests/countermodels, architecture/kernel/toolchain envelope, and qualification state. Private W documents should be rewritten into public explanations if needed; workspace instructions prohibit copying private material verbatim into the product. Product comments reference W design files that are absent inside P (for example the H4 design); extraction must preserve an appropriate public rationale, not leave a broken relative link.

## Recommended sequencing

1. Finish the candidate's existing verification/re-review/live obligations before freezing its semantics as a library baseline. Do not restart from the older root checkout or claim old CI validates `4bcb24c`.
2. First prove two real consumers for O1/O4/O5; extract process authority types, descriptor identity, bounded reads, and their fault-injected tests with minimal product vocabulary. These have the clearest general Linux value.
3. Factor small attach-oriented ELF helpers and pure supervisor logic (O6/O11) over existing dependencies; avoid a new universal ELF parser or hard-coded OSSL cost model.
4. For O7/O8, investigate current upstream Aya support separately and prefer upstream fixes/tests where it can remove maintained custom loader code. If retained, make the restricted object/UAPI support contract explicit and keep exact malformed-object regressions.
5. Prototype transport-independent lifecycle and count interfaces (O3/O9) in a second observer before extracting. Require explicit process/image/session identity, tail-closure strength, loss units, and ownership disposition.
6. Retain O10's uncertainty algebra and O12's causal/protocol corpus; generalize only after the second product demonstrates matching semantics. The test suite must include incorrect plausible implementations and countermodels, not just happy-path replay.

Suggested acceptance obligations for any extraction: no change in count conservation or ambiguous-callback verdicts; A->B->A, deletion, alias and in-place-change coverage; owned/foreign target authority tests; fork/exec/short-child and CPU-topology loss cases; restart/session isolation; wire ABI and malformed ELF tests; callback execution plus kernel-image checks; and exact extraction-tip host/BPF/live evidence on each claimed compatibility cell. These are proposed future gates, not work executed in this research.

## Research memory usage

Historical memory was used only to locate the two-repository split, continuation history, and evidence-boundary hazards; live remote refs and current handoff superseded the October 9 snapshot. References: `MEMORY.md:434-470`; `rollout_summaries/2026-10-09T16-16-23-DUUd-osslscope_continuation_audit_plan_and_remote_transfer.md:15-39`; rollout `01a12173-8d19-7761-9ca6-90c2cf8a60f5`. No historical test result was presented as a fresh execution.

## All-branch/worktree extension and uncommitted material

The expanded census ran `git worktree list --porcelain`, `git for-each-ref refs/heads refs/remotes`, `git status --porcelain=v1 --untracked-files=all` in **every registered worktree**, ancestry checks against the selected candidate/main, unique-commit logs, and `git cherry` comparisons for divergent refs. It inspected the workspace-only divergent files named below, newest ignored reports, and untracked source/configuration. This census does not fetch or establish what a hosting provider currently publishes.

**Observed disagreement with the handoff:** `refs/remotes/origin/task/integration-preview-r21` exists at `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a`; workspace `refs/remotes/origin/main` exists at `40369e5f6b93aa7925cda28c21e17ff57afc67d4`. These conflict with handoff wording “LOCAL-ONLY” and “no remote by design.” They are local remote-tracking records only; this research neither inferred actual publication nor changed the intended never-push boundary.

### Product branch/worktree candidate map

All 18 registered product worktrees are clean, with no nonignored untracked files. Every `task/rem-*` row below has its corresponding `.worktrees/rem-rNN` worktree and matching `origin/task/rem-*` ref. The root and preview paths are listed above. Product `main` is not checked out.

| Local branch / full SHA | Relationship and useful material |
|---|---|
| `main` `f0f843ff8cf950112bba58dfa302ba35139e675c` | Ancestor of preview; `origin/main` and `origin/dev/continuation-20261009` alias this SHA |
| `task/p7-traversal` `1a481831a85375ecb2d69ca65618d37c846de8b3` | Ancestor; root worktree; matching origin ref |
| `task/integration-preview-r21` `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a` | Current selected candidate; matching origin ref, publication unresolved |
| `task/rem-r01-alg-identity` `b99bf2618f29fd99329c01d55d1fcde94a17400b` | All eight branch patches have equivalents in preview; finite alias equivalence, conservative duplicate-site merge, structural privacy address checks |
| `task/rem-r02-fatal-usability` `8c4ea6a73c4fb31c53717178656b1e1f2d0e17c6` | Both patches equivalent; salvaged runtime-fatal evidence remains useful through policy/CBOM; shared check assembly seam |
| `task/rem-r03-binding-state` `dbdf7844d70b8cbb8865a5d49c2d8cf7df0dbebc` | All three equivalent; mapping history belongs to each installed binding, including install-poll replacement state |
| `task/rem-r04-firsthit-count` `1644f34856ad5129b25e0d7ae68b06e089a3226a` | Equivalent patch; concurrent first hits use zero-seed plus bounded relookup |
| `task/rem-r05-engine-replay` `f728b8305f8562087a47bab0e2fed552fa986e0f` | Later three patches equivalent; initial patch is conflict-adjusted as `b755717`; independently pinned ENGINE streams, retained replay identities |
| `task/rem-r06-child-custody` `956d789079a1e79b7538b9d52e33fe6b7136382e` | All seven equivalent; latest preview adds lexical/root-parent setup fencing fixes |
| `task/rem-r07-inspect-admission` `d9c136576bd7f19b5fe084b489796c17d428fc4d` | All four equivalent; admission-before-read proof tied to real syscalls, not only helper-spy ordering |
| `task/rem-r08-install-verify` `0cb3eb8b99e547a2fbc924e7bb43b3768bf4ef48` | All three equivalent; manifest snapshotted once, staged hashes/identity before prefix replacement, per-run temporary paths |
| `task/rem-r09-op-compose` `79f4340696dfca20b34e2322f54e97a7bfe58154` | All three equivalent; one candidate must satisfy the whole operation predicate; missing coverage fails closed |
| `task/rem-r10-live-channels` `71758b07719905889031d9ea706e6e8b2e0b3a14` | All three equivalent; doctor/report/ledger channel and exit consistency |
| `task/rem-r11-members-gate` `7de71bee9107bcd100453ccfa98d283bcb1c2c79` | Five patches including R10 equivalents; required freshly built members object and specific negative failure assertions |
| `task/rem-r12-report-context` `91467e7cb2759659b3329310b61e4272347d1c98` | R05 base plus display/context fixes; conflict-adjusted `ee9d8b3`/`8f8dd0f`, latest independent Unicode/old-reader test equivalent. Generic human-display neutralization is another small non-BPF seam; keep schema/context policy product-owned |
| `task/rem-r13-journeys` `4a97ed8af66dd862da7b98b9062b5b5d81601352` | Documentation-only branch; most patches equivalent, privacy/exit wording conflict-adjusted and further corrected by preview `f3be5ca`/`dde4bd6`; do not revive its older behavioral claims |
| `task/rem-r14-read-budget` `9aa0156454e0111c15d56b5f3ef2c6363f598a99` | Both patches differ in patch-id after integration (`2643dae`/`00d1a95`); `src/plan.rs` is byte-identical between branch tip and preview, capture gained subsequent integration fixes |
| `task/rem-r19-p7-execute` `70308a9122a770f3a77011af222ee0738632492a` | Forty task commits; 33 patch-equivalent, seven conflict-adjusted integrations. Corresponding preview subjects include `204b8c8`, `a72207b`, `07b5ede`, `bc2a735`, `90fa77e`, `d885a24`, `520fd52`; preview adds later closure/salvage/schema fixes. The branch's committed WIP-preservation commit is evidence custody, not a newer uncommitted implementation |
| `task/rem-r20-lifecycle` `7db343b4ba1dcad7b9b0350df51fcec8f442aec6` | Twelve commits including R06 base; four lifecycle patches conflict-adjusted as `131012a`, `2700949`, `3a3f382`, `5d8f49b`; other patches equivalent. The terminal WIP-preservation patch is equivalent in preview |

Additional remote-tracking branches without local worktrees are all ancestors of preview: `origin/task/p5-c-probe` `b3eedf420c1d42f058389aa05d0b0d57ae4a8c08`; `origin/task/p5-d-loader` `af22817e03b50df77a3008a01bbd87906672960d`; `origin/task/p5c-b-probe` `d2e9fa401cbb3412db6be94592374d91de06dfa5`; `origin/task/p5d-cold-gap` `d99f95ee93bc527d75df08c029db4d4140931638`; `origin/task/p6-identity-lifecycle` `96a08a908518e37e2f169e453a2d5ed9fc86eccc`. Their loader/callback, cold-gap, and identity lessons are retained through ancestry and the O4/O8/O9 histories. A `git cherry +` means no identical patch-id, not proof that behavior was omitted; matching integrated commits and current source were used to interpret the conflict-adjusted branches. This is a reuse inventory, not a complete semantic proof that every integration conflict preserved every branch behavior.

### Workspace-only committed candidates absent from root main

All seven additional workspace worktrees are clean; all seven branch tips are divergent from workspace main and contain non-equivalent private harness/docs work. They must not be dropped merely because the product preview is the main source baseline.

| Branch, worktree under W, full SHA | Novel source/docs and reusable lesson |
|---|---|
| `task/rem-r09-op-compose`, `.worktrees/rem-r09-ws`, `d242a781ee76556c586ac8c51bcfee7c56983a00` | Three commits: `spike/dev/cells/run-core-root.sh` + `test_cell_oracles.py`; whole-predicate matching on one candidate, definite agreement, missing-coverage rejection. Harness counterpart to product R09 |
| `task/rem-r15-pass-seal`, `.worktrees/rem-r15`, `5122c2098d94389556c708e852bce9f75acefe2d` | Four commits: `spike/dev/evidence_manifest.py` and `run.py` plus cell/test changes; reusable evidence sealing/expected inventory and durable terminal publication |
| `task/rem-r16-argv-lanes`, `.worktrees/rem-r16`, `c1824dccad707aced3bccf8325d0546f2650aee1` | Inherits R15 plus two commits: preserves argv boundaries through SSH and refuses occupied lanes before work; `run.py` and `test_run.py` |
| `task/rem-r17-rate-privacy`, `.worktrees/rem-r17`, `49c6439ebcbb254c9dc716c973ed85d04e0d2f90` | Inherits R09 plus four commits: rate/privacy nonvacuity, observer-family ownership, immutable scan inputs, matching receipt digests; `run-{privacy,rate}.sh`, `test_cell_oracles.py` |
| `task/rem-r18-p7-design`, `.worktrees/rem-r18`, `542d009a971bc2c9097eb97f2e27025cc264abf5` | Three **documentation-only** commits; `docs/2026-10-13-p7-item3-entry-scan-design.md` corrects retained-PENDING from unconditional absence to conditional bounded outcomes after model counterexamples; no independent product implementation claim |
| `task/rem-r21-live-qual`, `.worktrees/rem-r21`, `e9fa2f7231d2ca9b30eb70fc47274a921081cb1c` | Forty-four committed harness/docs changes; strict vs possible attribution, real family/custody judging, preserved receipts, and five rounds of parser hardening; qualification plan/receipts and `spike/dev/cells/common.sh` |
| `task/rem-r23-req-index`, `.worktrees/rem-r23`, `c973dc4fd3fd3c05116c6067a0c96adc0f263290` | Two **documentation-only** commits; `docs/2026-10-13-requirement-status.md:1-30` separates implemented/host-verified/live-qualified, pins older source revisions, and maps residual obligations. Valuable reporting structure, not current final qualification |

Three additional **harness reuse families** deserve first-class consideration alongside O1-O12:

- **Evidence inventory/sealing/publication:** R15 `spike/dev/evidence_manifest.py:271-365,573-608` defines confined paths, expected required roles, exact run/profile/product/harness bindings, and input sealing. The cell manifest is a claim validated against a coordinator-owned expected set, not authority over its own requirements. R15 `spike/dev/run.py:1336-1395` fsyncs content and directories, atomically replaces metadata, and retracts a prematurely visible PASS when post-rename durability fails. Preserve `test_evidence_manifest.py` and the failure-injection cases in `test_run.py`, including single recovery faults (`5122c20`). General Python/Linux test infrastructure; medium extraction difficulty, separate from product capture libraries. Filesystem race/trust assumptions still require a dedicated review before reusing as a hostile-input custody system.
- **Lane lease and SSH argv:** R16 `spike/dev/run.py:283-327,366-369` uses an exclusive nonblocking flock for ownership, an informational lease record, and `shlex.join(remote_argv)` as one remote shell argument. This prevents OpenSSH's remote argument joining from corrupting `sh -c` and paths containing spaces. Keep occupied-lane full-run refusal control (`c1824dc`) and argv regression battery (`bdb2ca2`). General Linux orchestration utility, low/medium extraction difficulty; VM path/port/provisioning policy stays adapter-owned.
- **Nonvacuous privacy receipts and strict log judges:** R17 `run-privacy.sh:161-174` records the live sudo-parent/observer-child family before reap; `:220-250` copies scan input before scanning; `scan_inventory_ok:663-679` compares exact scanner-time membership/digests with receipt-time bytes. R21 `common.sh:433-485` uses one newline parsing path for both broad malformed-marker detection and canonical test-summary classification, checks exit/content agreement, and keeps unknown exit status explicit. Commits `f7a0e8e`/`e9fa2f7` close a splitlines-vs-multiline-regex separator counterexample after four earlier repairs. These are reference corpus/protocol candidates, not universal attestation APIs; do not transfer “no secrets found” without owned/nonempty observation and byte custody.

### Ignored reports, untracked source, and remaining limits

Newest relevant ignored documents inspected under `W/.superpowers/sdd/2026-10-13-remediation-and-improvement-plan/` are `task-final-fix-report.md` and `progress.md`; `git check-ignore` confirms they are outside Git. Worker-reported round-3 gate transcripts at `task-final-fix-report.md:951-980` claim two 1158/0 suites, script checks, BPF builds, and required members-shape 12/0/0. These are **uncommitted/ignored worker receipts**, not independently rerun evidence. `progress.md:316` and committed `docs/HANDOFF.md:17-19` still state coordinator verification and re-review are pending. The distinction is “worker reports tests passed; coordinator gate not closed,” not “no testing ever happened.” The newest handoff is the root one, not copied earlier worktree handoffs.

Additional unresolved protocol limits from the ignored report: `task-final-fix-report.md:989-993` retains same-operation cross-query TRUNC contamination and describes terminal-only uncertainty handling; a wire change is future work. This further argues against extracting O12 as a finished generic invocation protocol.

Root workspace has exactly 21 nonignored untracked files. Eight are source scripts, all read: six SecureBoot QEMU boot variants under `vm-operational/2026-09-18-sb-smoke/` and `lane-b.sh`/`lane-hold.py` under `2026-10-10-continuation-b/`. The six extensionless `meta-data`/`user-data` cloud-init files across all three directories were also inspected with key/credential lines redacted. They contain isolated lane identities, users, package/setup configuration, and fixed-host launch details. The remaining seven entries are three firmware variable images, two lane lock files, one seed ISO, and one generated KVM error log; binary/generated contents were excluded. No dirty product source was found.

The untracked Python lease holder independently uses flock plus a run-ID record and signal cleanup, but the committed R16 harness is the better extraction source because it has refusal/argv regression coverage. The ad hoc launch scripts use fixed paths/ports and PID files; they are historical operational specimens, not reusable process-identity or SecureBoot qualification libraries. No boot script was executed, no keys copied, and no VM activity inferred from file existence.
