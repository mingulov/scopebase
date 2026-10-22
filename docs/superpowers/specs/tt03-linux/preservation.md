# TT03 source mechanisms and preservation limits

All observations are static; all destination tests/controls are **NOT_RUN**.
Exact source paths, standalone histories, commits, hashes and narrow ranges are
in [source-observations.json](source-observations.json). No broad donor intake,
history sweep, live donor refresh, source copying or admission was performed.

P is frozen p11scope w003, commit
`2c2713e66292b0d2688508a25f79e813ae823d81`,
`p11scope-ws/tree/.worktrees/v040-integration`, standalone
`p11scope-ws/history/r001.git`. O is frozen OSSLscope checkout-018, commit
`4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a`,
`osslscope-ws/checkout/osslscope/.worktrees/preview-r21`, standalone
`osslscope-ws/histories/repo-001/history.git`. Those names are relative to the
2026-10-18 private snapshot. Gitless checkouts must never discover the parent
ScopeBase Git repository. Selected-file blob comparisons use only the named local
histories with lazy fetch, replacement objects, hooks, transport and fsmonitor
disabled. A missing object is incomplete evidence.

The earlier LX08 static crossreview checked four files/86 fragments and marked
MATCH, but `packet_ready=false`, source admission unadopted and runtime false.
It is useful source custody evidence only. This packet reuses its exact mappings
and inspects selected fixture ranges; it does not repeat its intake/history audit
or promote its result to product qualification. During this preparation root
separately adopted the combined host admission e29cc889d99b73d3790a48fe555f4f74c60c4f718f7e184bd000f142a01e7bc1.
Fourteen inspected scopes are contained in its ready ranges; the stopped-child
reference is outside them and remains ungranted. This packet consumes that
admission rather than asking for another grant.

| Source mechanism / original | Disposition and destination | Preserved invariant / independent oracle / sensitive wrong control |
|---|---|---|
| P process.rs pidfd_denial filter, thread_status_field and fresh-exec helper, 1929-2427 | ADAPT only named denial/phase pieces into confined observer fixture; original permissive fallback assertions are not transplanted into strict LX08 | Real x86_64 native filter, original filter-count delta+1, raw syscall canary, readable same-birth stat, exact token/phase binding, unconfined owner across live/zombie/reaped. Raw denial and WNOWAIT/pidfd are independent of production. False errno, no filter, fake ack and strict stat-fallback success must fail. ENOSYS remains simulation, not old-kernel coverage. |
| P process.rs exited_unreaped helper and run_pidfd_denial_case | ADAPT exact-owned-child WNOWAIT and independent original pidfd truth; prefer admitted rustix PidFd wait where supported, retain raw syscall/errno | Exited-unreaped differs from reap. Preserve non-reaping witness, successful exact reap disposition and separately observed ECHILD after that recorded reap. Poll/transport error cannot mean alive/exit/reaped. Any PID/wait-any substitution or ECHILD-as-success fails with B still active. |
| P process.rs ReapOnDrop, unbounded BufRead/mpsc reader, stdout substring/summary parsing, repeated per-phase deadlines | REFERENCE_ONLY defects/limits; do not copy these as ScopeBase guarantees | Existing destructor ignores kill/wait errors, thread is not joined, data/diagnostics can grow and deadlines refresh. NEW bounded framed provider is necessary to implement accepted TT02 custody/bounds; no shorter replacement of a complete donor mechanism is being claimed. All partial owners/threads must be explicitly accounted; no quiet-output/exit0 shortcut. |
| P process.rs stat_fields_survive_a_comm_with_parens_spaces_and_a_fake_state | ADAPT original real tricky-comm live/zombie/reaped regression to owned worker and independent byte parser | Last ')' and correct state/starttime fields. Keep the same literal tricky name and raw bytes; a first-')'/wrong-field parser fails after actual naming. Worker uses its own explicit name operation instead of external /bin/sleep/symlink timing loops. Cleanup is inspected before assertions. |
| P process.rs original_generation_state_distinguishes_exit_from_pid_reuse, only_a_missing_process_is_proof_of_exit | ADAPT deterministic oracle counterexamples in LX08; TT03 supplies real matching zombie plus live unrelated target | Exited original pidfd plus matching zombie birth is exited; denied/malformed/unobserved proc state is not exit proof; replacement is not terminal authority. Actual PID reuse is optional stress only. Required native phases and deterministic schedules do not depend on racing reuse. |
| P pidns.rs only_this_namespaces_own_proc_classifies_own and the_numbering_composes_the_mounted_procs_view | ADAPT pure raw view fixtures plus new real namespace recipes with TT04; no application initial-only/cgroup/OnceLock policy | proc self text, NSpid and actual observer numbering must agree. Existing fake directory fixture is a pure tier; it cannot certify a namespace. Root requires matched-nested positive. Fake own label, ignore-NSpid, global cached view and host-PID relabel fail their actual-cell assertions. |
| O target_lifecycle.rs external_pid_target_is_never_signaled | ADAPT observation/control separation and live external population; do not port application OwnedTarget policy or its unguarded cleanup | Actual production pin/read/verify/Drop must leave independent live A/B phase sentinels responsive; type UI forbids control/adoption. Independently sensitive syscall audit must also see invisible signal0/wait-WNOHANG canaries. Sentinel alone does not close no-control. |
| O target_lifecycle.rs stopped_child_maps_readable_for_setup_baseline | REFERENCE_ONLY until LX09's exact stopped-child helper exists | This source requires application pre-exec dumpability/stopped-control semantics. TT03 ordinary live-worker maps do not re-run this original. LX09/LX11 must retain the original stopped-phase case; no fake live replacement closes it. |
| Accepted LX02/LX03/LX04/LX05 library/tests/selected-port receipts | CONSUME accepted packages unchanged; no new donor-copy receipt for calling them | Held descriptor survives replacement/unlink, positional cursor independence, structured charges/zero-payload refusal, cooperative cancellation, strict raw parsers/table-instance provenance and exact A3 whole-input refusal remain intact. Existing testkit fixture truth supplements, never replaces, their independent original controls. |
| Accepted TT02 fixture.rs/observation.rs/result.rs/runner.rs | CONSUME actual APIs, add feature-gated Linux provider only | Owned independent cancellation probe, typed prepare/collect failures, exactly-once new registrations, sticky uncertainty, fixed cumulative adapter-then-fixture retirement and imported descriptive reports. No duplicate engine/trait/report-to-owner API. |

The whole donor denial regression originally accepts a permissive ProcView/PidPin
fallback without signal authority after denied pidfd_open. LX08 requires strict
pidfd acquisition. This is an explicit **contract difference**, not a claim that
the original expected output was copied unchanged. Preserve its mechanism and
all applicable denial/lifetime/no-authority facets; record the nonapplicable
permissive-success facet separately in source admission/port review. Do not
delete the historical source or claim strict refusal re-runs a permissive API.

New mechanisms justified by concrete absences: none of these donor tests has an
accepted TT02 FixtureSession, run/op-bound binary framing/FD cardinality,
bounded private truth ledger, distinct immutable effect registrations, cumulative
retirement reporting, packaged actual-consumer route or matched-nested native
qualification. They are narrow NEW composition with the exact design in this
packet, not a new production syscall framework or universal runtime.

Historical P/O source terms are GPL-3.0-or-later. The existing
OWNER-2026-10-18 authorization permits user-owned selected host contributions
under provisional Apache-2.0 destination terms. The adopted host admission has
classified the selected ranges as owned host contributions, with no attributed
third-party implementation found; TT03 still binds its exact actual subset and
destination/preservation receipt. Do not demand a new author grant merely because
the old header is GPL. Preserve actual upstream
notices/options. No BPF payload/compiler target code or target-license choice is
part of this packet. Native seccomp fixture use is a host syscall-test mechanism,
not a BPF program-license qualification.

Required future port receipt maps every actually copied/adapted slice and original
disposition to actual destination hash/symbol/test, independent oracle/positive/
bad control and support boundary. An intake draft or this JSON source inventory
is not that candidate-bound selected-port receipt. Root validates it independently
and keeps earlier lineages/evidence immutable. Duplicate retirement/migration is
later: after the delivered fixture and actual independent users cover the same
contracts, each donor owner decides its own migration; no donor mutation follows
from this preparation.
