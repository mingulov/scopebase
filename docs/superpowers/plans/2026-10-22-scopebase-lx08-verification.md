# LX08 Strict Observation Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: after root binds the actual base,
> dependencies and fixtures, use superpowers:subagent-driven-development or
> superpowers:executing-plans as selected by the controller. Design ratification
> does not start product execution. Steps below are all NOT_RUN.

**Goal:** deliver and independently check the complete strict LX08 observation
core and explicit downstream developer routes without claiming full profile readiness.

**Architecture:** production scopebase-linux owns original pidfd/proc/namespace
custody, pure LX05 parsers remain unchanged, accepted TT02 runs actual subject
adapters against separately owned TT03/TT04 fixtures, and independent raw truth
decides assertions. Clients never certify the runner's separately resolved copy.

**Tech stack:** Rust2021, Rust1.88.0/1.98.1, Linux x86_64 GNU, rustix=1.1.5
std/fs/pipe plus feature-gated process/event, existing unsafe ioctl machinery
inside one private adapter; test-only libc=0.2.191 pending exact admission;
Python3.11+ delivered driver, externally supplied prebuilt fixture/audit assets.

**Spec:** [LX08 strict process observation contract](../specs/2026-10-22-scopebase-lx08-process.md),
root-selected design from the independently reviewed exact r2. Its
[reviewed input custody](../specs/2026-10-22-scopebase-lx08-process.md#reviewed-input-custody)
records immutable amendment/bindings inputs and the later TT03 protocol change.
**Execution status: INPUTS_UNBOUND; PACKET_READY=false.** The actual future
product base, C7, independently accepted TT02 borrowing maintenance, TT03/TT04
assets, closed EOF orchestration, capable auditor and joint compatibility are
unbound. Every implementation/test/helper/provisioner step below remains NOT_RUN.
No task count, task acceptance or profile qualification changes.

## Global constraints

- Source admission is the actual common next-host-scopes snapshot, not the old
  proposed ledger. Frozen donor files and historical receipts remain immutable.
- BP02 is accepted in the current handoff; its accepted subject is historical
  prerequisite evidence, not an automatic future execution-base binding. No product dispatch until exact post-BP02 base, accepted
  predecessor hashes, new dependencies/feature union and TT fixture interfaces
  are frozen and independently reviewed. No stub export or fake authority.
- Host library never spawns/signals/waits/mounts/joins/unshares/changes credentials,
  limits or handlers. Namespace/filter/control effects belong to explicit owned
  provisioner/fixture resources only, with exclusive leases and retained cleanup.
- Current/MSRV and source/archive checks use the absolute common build wrapper,
  private targets/results outside the worktree, and the supported feature-check CLI.
- Choose required cells before discovery. Setup failure, missing positive,
  missing native trigger, wrong-copy binding or SKIP remains incomplete. Expected
  refusal can pass while a capability is denied; it cannot qualify support.

## Review focus

1. Retained-only Changed cannot observe a replacement at the same numeric PID;
   terminal original pidfd, sampled leader state, birth and namespace are distinct.
2. Own/NSpid agreement is relative numbering, not global initial membership; actual
   nested adapter execution cannot relabel a host PID or fabricate namespace type.
3. Metadata and body budgets are cumulative per call; every EINTR/EOF/link/probe
   and successful effect before refusal is charged, including post-read cancellation.
4. Concurrent reads require fresh descriptions; borrowed/serialized provenance or
   one shared seq_file cursor cannot replace original owners and separate outputs.
5. Still-running sentinels do not detect ignored-error signal0/wait-WNOHANG calls;
   no-control needs a capable operation audit from fallible epoch creation through
   last actual epoch Drop, with parent oracle/cleanup outside that subject window.
6. Numeric creator PID equality can collide in a nested PID1 child. Require both
   retained original creator pidfd and authenticated active-PID namespace; use
   dynamic retained-root self/Own proof before any read/verify target operation.
7. The actual read/death original needs a native EOF -> owned exit witness ->
   postread poll barrier. Between-operation phases and timing stress do not reach
   it. cfg(test) common-native-reader source evidence and external production
   object evidence are separate required tiers.

## File and writer map

| Writer | New/changed paths and purpose |
|---|---|
| LX08 one product writer | `crates/scopebase-linux/src/process/{mod,epoch,observation,reader,native}.rs`: public values, owner, bounded data fetches, narrow native adapter; `tests/process_observation.rs`; `tests/fixtures/process/`; `tests/support/process_reference.rs`; `tests/support/process_fixture_adapter.rs`; `tests/support/run_process_observation_checks.py`; private `cfg(test)` actual-native-reader EOF hook and closed barrier endpoint; two delivered client source templates under `tests/support/process-clients/{proc-inspector,owned-observer}/` |
| Root shared writer | `src/lib.rs`, `src/identity.rs`, `src/error.rs`, all Cargo manifests/lock/policy/notices, public design/plan amendments, README/TODO/source-port receipts, UI harness registration; keep accepted parser/control/read constructors consistent |
| TT03 writer | Actual `scopebase-testkit::fixture::linux` provider, worker images/protocol/raw ledger and oracle, separately chosen bounded no-control audit; separately owned measured-test-binary parent/EOF orchestration; no production LX08 implementation or copied expected-result oracle |
| TT04/provisioner owner | Explicit user/PID/mount realm and child-overmount/symlink/view-change recipes, manifests, original-resource retention/cleanup; no implicit setup in library/operator |

Ordinary helper templates are Rust source included under `tests/**` by the actual
package include list. Root declares explicit examples/tests only with implemented
behavior. Two clients have separate manifests/locks and independent expectation
flow; the driver creates only fresh external client/target/evidence directories.

## Task 1: values, public boundary and dependency closure

**Consumes:** accepted OperationControl, ParseLimits/maps/mount snapshots,
LinuxError/ResourceCharges; adopted source snapshot and exact donor slice map.
**Produces:** every exact type/trait/getter in the [LX08 contract](../specs/2026-10-22-scopebase-lx08-process.md), process feature
configuration, no authority conversion. This task is not accepted as the full core.

- [ ] Root binds the candidate base and concrete predecessor/source admission hashes;
  admit rustix process/event only under process and test-only libc closure.
  Required namespace-kind adapter uses rustix's existing ioctl machinery, not a
  new production libc dependency. Freeze notices/source/policy/union changes.
- [ ] Add `pid_validation_is_release_safe`: new(0), new(-1), new(i32::MIN) are
  None; new(1), new(i32::MAX) have exact round trips in debug and release. Mutant
  directly forwarding negative rustix Pid must fail the negative assertion in
  release after the valid positive setup, not merely hit a debug panic.
- [ ] Add `epoch_and_view_provenance_is_retained`: two simultaneously live new
  strict fallible epochs differ; clone shares their two authority FDs and creation
  receipts without dup; two independent acquisitions in one epoch remain separate; equal raw PID/ticks in distinct owners do not compare equal. No
  counter reset/raw-inode substitute. An actual post-fork use of an inherited
  owner/epoch refuses the first reached creator-context WrongContext before target
  I/O; a fresh child strict epoch/owner works in authenticated Own. Retain every
  descriptive result after dropping all real authority; no creator/target FD may
  remain by identity. ProcView must not retain the authority Arc.
- [ ] Add UI cases at `tests/ui/process_{signal,wait,adopt,raw_pidfd,report_upgrade}.rs`.
  They attempt missing control/raw/report constructors, expect exact E0599/E0451
  at the intended expression, and pair each with a valid public observation
  client that actually acquires/reads. Root reviews no Serialize/Deserialize or
  foreign raw constructor impl was added. A missing import/compiler setup error
  is not the intended RED.
- [ ] Implement public values and private Arc/creator provenance only from the
  selected donor definitions plus the adopted NEW strict creator composition;
  no placeholder behavior method. Implement the
  behavior methods with Task2 before exposing the combined process module.
- [ ] Run focused values/UI/current/MSRV checks, then admitted process dependency
  feature/source policy checks. Record actual commands/hashes and intended RED/
  restored GREEN twins. Do not add a full unrelated all-package rerun.

## Task 2: exact acquisition, readers, statuses and resource closure

**Consumes:** Task1 values/controls, unchanged LX05 parsers, selected original
mechanisms, admitted rustix and the contract's private namespace-kind ABI.
`tests/process_observation.rs` exercises public/core behavior without depending
on an unpublished workspace sibling. Advanced TT03 subject adapters are external
client sources compiled by the explicit developer driver in Task4; no testkit
runtime dependency is added to scopebase-linux.

**Produces:** real acquire/read/verify implementation and all exact error/charge
semantics, with call-local cfg(test) schedules (no production fake owner seam).

Required local test names and semantic populations:

| Test | Exact independent population/assertion | Bad control / expected RED |
|---|---|---|
| `strict_proc_acquisition_brackets` | Each of five original proc_custody bodies; schedule no pidfd/no birth, death before open/after open/after birth, changed retained ticks, stable original dir with all three checks; independent operation ledger | Omit each bracket/replace source directory separately; wrong owner or missing refusal fails intended assertion after valid stable twin |
| `birth_table_preserves_errors_and_terminal_truth` | Enumerate every contract C5 row independently: poll syscall errno, ERR/NVAL+IN, HUP-only, zero+events/count mismatch, preterminal, stat denial/missing/UTF8/overflow, postterminal with same-zombie or changed ticks, live ticks mismatch, leader Z/X and unknown alphabetic state, each supported live-state letter | Error-as-alive, stat-only-exit, zombie-as-live, changed-as-reuse/terminal, erase flags/errno; intended exact status/stage/reason/source/evidence/charges assertion fails |
| `retained_changed_is_not_current_name_reuse` | Two independent owner domains with same raw PID/ticks; a retained-source contradiction schedule; terminal original pidfd while replacement remains live | Fresh global name probe or replacement-as-original mutant fails original-FD/domain assertion; no forced native reuse luck |
| `stat_reader_preserves_all_original_bytes` | Byte-at-a-time + alternating EINTR, two EINTR then data, hard error, EOF, exactly4095/4096/4097/9000 bytes; invalid UTF8 at10/5000; restore valid UTF8 twins; reader and parser judgments separate | First-short-read success, dropped tail, ignored hard error, infinite retry, invalid UTF8 acceptance; compare exact bytes/charged calls and typed refusal |
| `stat_fields_use_last_delimiter_and_field22` | Hand-counted literal comm `a) Z 1 (b`, state decoy, ticks777/field23 different, literal O tricky-comm vector and its malformed/short rows; PID prefix/Tgid boundary cases | First-')'/off-by-one/unchecked decimal/foreign PID mutant fails independently literal expected field, not a shared production parser |
| `own_view_is_not_initial_or_caller_truth` | All14 pidns originals accounted; selected ten adapted; exact valid/malformed link corpus; self42 and NSpid42 versus3026492+42/43/empty/042; real source type required before owner | Unknown-as-own, observer-only, ignored NSpid, caller-labelled agreeing or fake ordinary-root acceptance fails correct domain/refusal assertion |
| `namespace_kind_is_kernel_confirmed` | Real PID FD -> CLONE_NEWPID and mount FD -> CLONE_NEWNS via the private wrapper; swap each into opposite expected slot; deterministic ioctl EPERM/ENOTTY/ENOSYS and unknown return; retained handle survives link retirement | Wrong NoArg-return extraction, expected-kind constant, swapped-kind acceptance, errno erasure or fallback fails exact kind/error/counter assertion; no Getter uninitialized-output implementation |
| `metadata_body_and_eof_share_call_budget` | One aggregate R across all reads/links, exact M/B and one-byte oversize witness, cap overflow preflight, final EOF and complete-LF prefix+more-data, EINTR/EOF probes, readlink truncation, parser failure after complete transport | Per-member reset, uncharged EINTR/EOF/link, prefix success, silent limit clamp, discarded earlier charges fails exact charge/refusal assertion |
| `capacity_and_fd_inventory_are_explicit` | Checked M+1/B+1/parser worst capacities plus R<=(u64MAX-76)/3; constructor6 acquired/peak4/retained2, acquire21/peak8/retained6 borrowing2, read15/peak3 borrowing8, full verify5/peak3; fixed20/76/64/19 and target-terminal16 plus real data; peak reachable4/10/11/11 | Allocate-then-check, overflow/clamp, old no-cost terminal shortcut, lost creator/ioctl/flag attempt, leaked FD or numeric-count substitution fails chronological charges and exact owned-FD identities |
| `controls_preserve_first_error_and_spent_effects` | Cancel/deadline at entry, pre/post every effect, each init chunk, parser boundary and publish; failed syscall+post-cancel keeps errno, successful syscall+post-cancel keeps spent bytes/FDs and returns stop, no later action | Refund/retry-fresh-budget/post-stop-publication mutants fail exact chronological call ledger and no-snapshot assertion |
| `fresh_description_per_concurrent_read` | Same owner two simultaneous reads through distinct newly opened file descriptions; fixed separately known complete inputs, independent barriers and budgets | dup/shared cursor or shared mutable budget causes one incomplete/wrong output and fails semantic output/charge assertion |
| `admission_time_follows_identity_validation` | Selected monotonic-admission originals plus clock seam for constructor/acquire; creation receipts/validated finish occur only after successful real authority checks; stable start<=finish | Pre-validation admission, missing creation charges/effects, timestamp-as-epoch or SameImage helper fails ordering/domain assertion |
| `strict_epoch_creation_preserves_failures` | Every creation getpid/open/flag/fs/self/status/ns/ioctl/pidfd/poll/alloc/control refusal; process=Some, body0,parseNone, no escaping epoch/FD; immutable creation receipts and limits validation | Infallible/cached epoch, uncharged constructor work or partial authority escape fails intended exact stage/errno/resource assertion after stable positive |
| `creator_guard_precedes_every_target_action` | Outer Acquire/ReadMaps/ReadMountinfo/VerifyBirth context; getpid mismatch; creator poll errno/invalid flags/valid terminal; current self/Own malformed/foreign/denied; current PID namespace wrongkind/changed key; first-error and zero target ledger | PID-only check, namespace-only check, creator-terminal-as-target-Exited, cached observer-dir, global root reopen or reset creator budget fails exact refusal/zero-target assertion |
| `creator_terminal_same_pid_same_ns_refuses_model` | Independently scheduled same numeric PID/same namespace key but original creator pidfd valid terminal; inherited target owner still live | Remove creator pidfd guard or substitute fresh pidfd: WrongContext/CreatorPidfd/raw poll and zero-target assertion must fail; no invented forced native PID reuse |
| `readlink_request_bound_precedes_grammar` | Initialized raw readlink subslice exactly min(64,remaining_M+1), remaining0/1/linklen-1 and large-M positive for self/pid/mnt; exact returned byte charge and oversize first, plus EINTR/full-length truncation separate | Always64 request, allocating hidden-growth helper, grammar-before-byte-limit or uncharged link witness fails exact request-length/charge/stage/reason/no-next-action assertion |
| `reports_keep_no_authority_fds` | Clone descriptive epoch/view/birth/result markers, drop all actual epochs/observations, identify original creator and target FDs absent; one real epoch clone retains exactly creator2 | Authority Arc in ProcView, hidden target owner or report-to-epoch conversion fails identified-FD lifetime/UI assertion, not a fragile total FD count |
| `brackets_stop_before_next_action` | Independent chronological ledger for every target acquire/read bracket, including successful EOF and final target guard, creator context checked first | Omit one bracket: chronology/no-next-action RED after valid setup. Do not claim every single omission publishes a snapshot; the exact EOF semantic mutant below removes BOTH postread and final target guard |

- [ ] Port/adapt every selected original per the [frozen preservation map](#frozen-original-test-preservation-map) before the new
  mechanism, retaining its trigger and explicit assertion differences. Do not
  replace all originals with one representative test or relabel donor fallback
  success as a strict-product original expected result.
- [ ] Establish each control's valid setup and intended semantic RED, then restore
  the valid twin before focused verification. A helper panic/compile error at the
  wrong location does not count. Donors themselves remain unchanged.
- [ ] Implement the exact ordered acquisition/guard/read algorithm, original
  descriptor retention, proc metadata grammar and call-local accounting. The
  private namespace adapter is the only new unsafe audit boundary. Root reviews
  safety of opcode/null operand/direct return extraction/borrowed acquired FD.
- [ ] Run the focused test binary on both admitted compilers; include release
  Pid validation and meaningful controls. Current/MSRV/full archive gates happen
  after converged changed bytes; no full reruns without changed inputs/failure/gap.

## Task 3: actual TT03/TT04 subject adapter and real required cells

**Accepted seam, unchanged:** `FixtureSession::{contract,cancellation_probe,
prepare,collect,retire}`, `FixtureAccess::{input,resource,effects}`, and
`ConformanceAdapter::{subject,execute,retire}` from accepted TT02. Exact trait
source is bound in the immutable private bindings record under [reviewed input custody](../specs/2026-10-22-scopebase-lx08-process.md#reviewed-input-custody). No `ConformanceFixture` trait is invented.

**TT03 proposed native interface, not an accepted predecessor yet:**

```text
fixture::linux::LinuxFixtureSession::new(
  RunContract, LinuxFixtureFiles, &[u8], Instant, Arc<AtomicBool>)
  -> Result<LinuxFixtureSession,LinuxFixtureAdmissionFailure>
LinuxFixtureFiles { image_a: File, image_a_path: PathBuf,
                    image_b: File, image_b_path: PathBuf, root: File }
LinuxFixtureAdmissionFailure { contract, files, error: FixtureError }
LinuxFixtureSession::raw_ledger(&self,&InvocationKey)->Option<&[u8]>
LinuxProcessFixture::pid(&self)->u32
LinuxProcessFixture::nonleader_tid(&self)->Option<u32>
LinuxProcessFixture::advance(&self,&Label)->Result<(),LinuxPhaseError>
LinuxPhaseError::{category,errno,step_id,diagnostic_bytes}(&self)
```

Consume the individually observed TT03 r2 primary proposals identified under
[reviewed input custody](../specs/2026-10-22-scopebase-lx08-process.md#tt03-observed-primary-and-final-protocol-boundary), retaining
their original source-tree context. These are the frozen LX08 input copies; the
subsequent final TT03 protocol has a different digest. Root must separately bind
and review final-index/per-case compatibility; this plan does not silently
substitute that final protocol for the earlier observed bytes. Their API/protocol/numeric choices remain
proposed/UNBOUND until root ratifies and actual artifacts exist. No final TT03 r2
index is embedded here; root creates a separate joint compatibility record
binding both final indexes after independent review, without a hash cycle.
The manifest is external FixtureManifest input built before the contract; do not
add a contract/manifest self-hash cycle. The constructor consumes three original
opened assets plus exact paths, creates no child/root, and returns exact inputs
on admission failure. `prepare` creates/retains real owners. Labels
`linux.process`/`linux.excluded-process` downcast to borrowed LinuxProcessFixture;
file labels downcast to actual borrowed std::fs::File. The endpoint exposes phase
advance/ack, no expected-truth/control/raw-owner getter.

`pid()` means the actual Child.id in the *executing adapter/session's active PID
namespace*. Namespace cells execute the actual bound adapter inside the admitted
realm and create a NEW session/children there. Do not forward/relabel a host PID
resource. The adapter uses checked `i32::try_from(pid)` then Pid::new, refusing a
bad fixture input as harness/protocol error rather than a product semantic result.

The r1 TT03 independent review exposed a missing value channel: its old
pid()/advance() proposal could not supply sibling TID before collect. The observed
TT03 r2 primary proposal now includes the root-selected getter below.
**Root-selected interface refinement, implementation UNBOUND:**
`LinuxProcessFixture::nonleader_tid(&self) -> Option<u32>`, populated only after
actual GETTID-ready/start-sibling acknowledgement in the executing observer
namespace, validated in1..=i32::MAX, and cleared on sibling retirement/exec. The phase barrier keeps it live
through the intended nonleader acquisition. This is descriptive numeric input,
not control or identity authority. An exact pre-execute FixtureInput schema is
an alternative, but must bind timing and not substitute a self-reported forged
TID. None/missing raw trigger is fixture Incomplete, never a successful library
refusal. This root-selected getter is not an existing implemented interface; its exact
closed protocol/worker binding remains pending TT03 review.

The actual local adapter is proposed as `ProcessFixtureAdapter::new(subject:
SubjectBinding, limits: ProcLimits, control: OperationControl) -> Self` in the
external-client `process_fixture_adapter.rs` source. Construction only stores
these descriptive configuration values; execute calls the actual linked library
against FixtureAccess resources, and subject() returns that fixed compile-bound
binding. It owns/retire-reports only its acquired observation descriptors; fixture
child control stays in the session. No new trait/runtime is introduced. The exact
closed adapter script/case-to-step binding remains UNBOUND until the same TT03
manifest sequences are frozen; do not make a generic arbitrary-command dispatcher.

The observed TT03 r2 primary proposals address the earlier sequence/fault/chunk
gaps with closed scenario arrays, a tricky-comm prepare prefix, closed control
selectors and binary raw chunk/reassembly framing. These exact numeric/wire
choices are TT03 proposals requiring its review, not adopted runtime protocol
merely because LX08 records them. Repeated capture_raw actions have distinct
unique Label IDs. The adapter consumes only the first unconsumed Label: for
thread-lifecycle, advance s02-start-sibling before reading nonleader_tid; require
Some at its held sibling barrier. For tricky-comm, Prepare has already consumed
s01-ready and s02-comm; for file scenarios it has offered BOTH actual files. Never
repeat consumed steps or substitute post-collect truth as pre-execute input.
Final per-case adapter/manifest/resource compatibility remains UNBOUND in the
separate root joint record; no generic dispatcher or hidden provider trait is added.

On LinuxPhaseError the adapter stops later steps and returns bounded CaseError
with Unknown cause. Session latches the first native phase error; collect returns
actual typed FixtureError at Collect with partial effects and Advance detail.
Expected-dependent assertions remain NotJudged. raw_ledger exports bounded raw
evidence after collect/failure, not a 4MiB payload hidden in64KiB diagnostics.
Fixture truth uses original child/pidfd/WNOWAIT plus measured image/namespace
owners and independently authored Python/literal expectations, not LX08 itself.

The strict fallible constructor changes denial setup: retain a strict pre-filter
epoch and owner BEFORE installing the pidfd_open filter. A new target acquire reusing that
epoch can reach OpenPidfd/Pidfd Denied or Unavailable while the target is live.
Fresh ObserverEpoch::new after the filter instead reaches OpenPidfd/CreatorPidfd
under ProcOperation::CreateEpoch. These are separate exact rows; do not assume a
new constructor can pass denial or erase an earlier fresh-proc failure.

**Mandatory real rows for this strict process slice:**

| Row | Setup and separate positive/negative truth | Product result / key sensitivity |
|---|---|---|
| `real_original_live_zombie_reaped` | Original Child, original pidfd, exact WNOWAIT while unrelated B keeps acknowledged activity; parent alone exits/reaps A | Live correct birth; unreaped terminal pidfd Exited despite matching zombie; reaped original remains Exited; observer never consumes child wait custody |
| `real_tricky_comm` | Actual worker applies `a) Z 1 (b`, acknowledges and raw stat shows it; independently known live/state/birth before original exit/reap | Correct last-')'/field22/live state; no fake-Z zombie inference |
| `real_exec_aba_and_failed_exec` | Distinct measured image A/B original FDs plus before/after executable observations and successful acknowledgements A->B->A; actual failed exec errno/image A continuation | Birth result may remain AliveSameBirth; no image/current-mm statement. Skip-B and about-to-exec-only controls fail raw setup |
| `real_nonleader_and_group_lifetime` | Actual getpid/gettid, leader+sibling barrier; nonleader input; leader exit while sibling responds; independently measured successful nonleader exec | Actual TID cannot become process owner; zombie leader+nonterminal pidfd Inconclusive; terminal readiness Exited; valid changed retained birth Changed. Freeze exact reached raw row per kernel, no guessed errno |
| `real_seccomp_eperm` / `real_seccomp_enosys` | Fresh native x86_64 actual observer helper, strict epoch AND owner before filter, filter-count+1, raw pidfd_open canary selected errno, live stat readable; parent retains original exit/wait truth | Acquire using retained epoch reaches OpenPidfd/Pidfd Denied/Unavailable+errno while live; fresh epoch reaches CreateEpoch/OpenPidfd/CreatorPidfd actual errno; retained owner follows live/zombie/reaped phases. Earlier reached errors stay first; no fallback and no cause inference from errno alone |
| `real_matched_initial_own` / `real_matched_nested_own` | Actual observer+NEW session/children in each admitted realm with matched own proc; direct getpid/self/NSpid, original proc/ns handles and kernel kind; independent provisioner binds realm, no initial claim from own proc/inode/NS_GET_PARENT denial | Both strict epoch/acquire/read/verify positives required; initial-only policy or host-PID relabel fails real nested semantic assertion after setup |
| `real_foreign_unserved_proc` | Initial observer/foreign proc, nested observer/host proc, unserved proc and matched own positives, actual mount/context witnesses | WrongContext/actual source error with no owner; ignore-NSpid/observer-only/fake-label controls fail distinct view assertions |
| `real_proc_root_replacement_and_child_overmount` | Retain root then replace global proc pathname according to TT04 recipe; ordinary member/target child mount and symlink separately inserted in owned realm | Old owner keeps captured root; new acquire authenticates current root. openat2 child-overmount/symlink refuses at actual stage; no fallback/global reopen |
| `real_target_mount_view_changes` | Synchronized target setns/table churn under owned TT04 provisioner; raw original/current mount handles and birth observations | Namespace mismatch ChangedSource, never birth reuse/current-image; unchanged sampled A->B->A cannot be advertised as continuity |
| `real_independent_read_descriptions` | Known acknowledged mappings/records plus separately read raw proc files; concurrent same-owner calls; fixture does not mutate during comparison barrier | Every result reaches real EOF independently; shared cursor fails content completeness, not just FD count |
| `real_cloexec_identity` | Actual exec inventories inherited subject-owned FDs by identity; intentional inherited canary proves sensitivity; cover constructor, acquire and creator/read temporaries | All creator2+owner6+temporary FDs absent after exec; clear-CLOEXEC mutant fails exact identity assertion, no total-count substitute |
| `real_no_control_audit` | Actual bound external production subject executable and exact scoped window starts before fallible epoch construction and includes acquire/read/verify, owner Drop and final real epoch Drop; A/B sentinels active; capable signal0 and wait-WNOHANG canaries in separate marked windows | Zero subject control/wait/spawn attempts in library window; complete audit required. Sentinel success alone is insufficient. Tool/parser/window/ABI/thread limits remain TT03-C8 UNBOUND |
| `real_creator_pid1_nested_collision` | Actual PID1 parent constructs strict epoch/owner; actual nested PID1 child inherits, native getpid equality witnessed; child actual own fresh proc/session/children | Inherited read/verify/new acquire with inherited epoch refuses first reached WrongContext before any target access; child's fresh strict matched-Own epoch/owner succeeds. PID-only mutant fails wrong-authority/zero-target assertion after valid setup |
| `real_creator_active_not_children_namespace` | Original observer changes only future-child PID namespace using owned setns/unshare recipe; raw active pid and pid_for_children handles distinguish; then actual child enters nested namespace | Original observer fresh operations still authenticate active pid; new child's inherited epoch refuses; use-pid_for_children mutant rejects positive or admits wrong inherited context |
| `real_actual_maps_eof_death_barrier_cfg_test` | Measured cfg(test) object from supplied actual Linux source; common native reader reaches real maps read EOF, owned parent then exits A/witnesses original pidfd+exact WNOWAIT while B remains active, then releases reader | Postread poll refuses/no snapshot. Combined omit-postread-poll+final-target-guard mutant publishes parsed snapshot and must fail the intended no-snapshot assertion. Distinct evidence tier from external production clients |

The same-PID/same-namespace creator reuse is a deterministic model row above;
no forced native PID reuse result is asserted. The PID1 collision and ordinary
same-namespace fork are actual required negative populations, paired with fresh
child strict-epoch positives. Current process setns/unshare affects future child
PID namespace, not its active PID namespace; test that distinction explicitly.
Retained-root replacement remains a required positive with the new creator guard.

The no-control audit must detect at least kill/tkill/tgkill/pidfd_send_signal,
queued-signal operations, wait4/waitid and unexpected spawn/control, including
ignored-error signal0/WNOHANG. Separate parent oracle/cleanup windows. Missing,
truncated or unrecognized trace, wrong subject copy or unseen canary is incomplete,
not zero-call PASS. Root must choose/bind one actual audited tracer/strace route
before dispatch, including creation-to-last-drop windows and both external clients.
Alternative ptrace helper costs a private native audit boundary;
external pinned tracer costs delivery/policy/tool availability. Neither exists
merely because named here. Credential denial beyond these required syscall/view
cells is TT03's additional full-exit work; do not drop it from TT03.

- [ ] Root freezes the proposed TT03 seam/closed script and all TT04 recipes,
  manifest identities/leases, no-control auditor and pinned5.15/6.12/current kernel
  artifacts/configs before discovery/dispatch. Missing resources stay NOT_RUN.
- [ ] Build the actual downstream adapter with the subject binding and execute
  every selected real row, each positive/control pair, owned cleanup and raw
  oracle, with changed helper/candidate hashes. Fixture failure never counts as
  the intended product denial. Keep semantic Failed versus setup Incomplete distinct.
- [ ] Run independent preservation/concurrency/oracle review, including every
  reached wrong control and partial-effect teardown. Validate the candidate-bound
  selected-port receipt against exact admitted ranges and destination hashes.

## Actual native read/death original: exact evidence and custody binding

The selected original `original_pin_death_during_actual_maps_read_refuses`
(P process1003-1033; source hash unchanged in the [frozen preservation map](#frozen-original-test-preservation-map)) used a real
body read and after-read death hook. A phase between adapter calls does not
preserve it. This root-adopted route is mandatory and remains implementation/
artifact/orchestration UNBOUND, not a claimed passing source or product test.

- [ ] Add ONE private CALL-LOCAL cfg(test) hook in the COMMON ACTUAL reader, after
  successful native body read returns0 and its normal effect charge/post-control,
  before postread target poll OR EOF interpretation. Public read uses the same
  common native proc path; production has no enabled callback, raw-FD export,
  fake owner constructor or report seam. Source/common-reader hashes and cfg
  differences are recorded; do not call the objects identical.
- [ ] A separately owned fixture parent in the actual observer realm prepares A
  and acknowledged active unrelated B, retains original Child/pidfd/proc/namespace
  owners and launches the MEASURED Linux unit-test executable. The test acquires
  its own real strict epoch and ProcessObservation via PUBLIC constructors; only
  the common-reader hook is private. Parent supplies descriptive PID and closed
  run/invocation/case-bound barrier channel, never an authority report.
- [ ] At actual native EOF the hook emits the exact bound phase event and blocks.
  Parent alone invokes A's declared exit, requires original pidfd terminal plus
  exact WNOWAIT WITHOUT reaping A, requires B's post-exit active acknowledgement,
  appends independent raw evidence, THEN releases the barrier. Next library
  target poll must refuse; no parsed snapshot escapes. Event alone is not truth.
- [ ] Run the SAME actual EOF/exit-witness path with a combined mutant omitting
  BOTH postread poll and final target guard. It must reach parsed snapshot
  publication and fail the no-snapshot assertion. A crash, missing EOF, failed
  witness or timeout is not intended RED. Single-bracket omission cases assert
  chronological/no-next-action behavior separately; a later remaining guard may
  still refuse, so no unsupported semantic sensitivity claim is made for them.
- [ ] Bind the closed orchestration recipe before dispatch: exact EOF/exit/
  original-pidfd/WNOWAIT/B-ack/release order; bounded message grammar/count/bytes;
  unique run, InvocationKey and case/step IDs; exact test binary/common-reader/
  worker/helper hashes and source/features/compiler/cfg; allowed passed FD roles;
  actual observer realm/lease; raw ledger/oracle/expected-row binding; cancellation,
  channel EOF, parent/child failure/deadline paths; partial effects and complete
  child/wait/barrier custody. Missing any binding is Incomplete/NOT_RUN. No public
  provider trait or arbitrary callback/command dispatcher is added.
- [ ] Parent retains every worker plus measured test-binary Child/original pidfd
  through collect and explicit cleanup. A blocked hook is never abandoned on
  cancellation or failure: parent owns release/abort and test-binary retirement,
  then A/B cleanup. A's unreaped witness remains owned until its declared later
  parent reap. Keep product observation errors distinct from fixture errors and
  preserve incomplete cleanup/effects. Test harness stdout is not kernel truth.

**Artifact tiers:** this is actual Linux/proc/native-read evidence of the shared
candidate SOURCE compiled in a cfg(test) object, stronger than fake-reader/model
schedules. It is not an external/installed PRODUCTION library object. Record exact
source/package/common-reader/compiler/features/cfg/test-binary hash and relation
to the separately bound production client library. External production positive,
exit-before-read, no-control, namespace, denial and other rows still run separately;
passing cfg(test) does not certify their object. Changed-copy subject control must
fail with good runner/testkit unchanged in BOTH appropriate tiers.

**Root-adopted delivery refinement:** the owned-barrier native
case is resource-gated/ignored by ordinary libtest. The delivered helper MUST find
exactly that named case, build with explicit --no-run, and directly execute the
measured artifact with --ignored --exact --test-threads=1. It records exactly one
reached native case; missing/zero/ignored/unexecuted is Incomplete, never coverage.
This keeps ordinary source unit tests from silently spawning fixture orchestration
or treating lack of an owned channel as a semantic product refusal. Alternative:
a separate explicit native test target/harness; that needs another target/API
layout and package inclusion decision. Neither route counts default cargo test
as reaching the actual read/death original.

**Later production-object boundary:** source-free installed read-boundary delivery
is still UNBOUND and remains owned by LX11/LX12 plus TT07/TT10. A capable production
barrier tracer must identify the actual opened maps FD and native read exit0,
hold all relevant subject threads before usermode/postcheck, allow separate owned
original exit/pidfd/WNOWAIT/B-ack, then resume into postcheck. Bind actual x86 syscall/
FD/thread/window logic, permission denial, stop/resume/retirement custody, tools/
parser/manifest, installed delivery and intended RED/GREEN. A logging-only tracer,
ordinary strace transcript or timing stress is not that boundary. Sharing the
no-control auditor is possible only if the actually bound tool proves all these
capabilities. No tracer/tool pin or installed pass is invented here.

## Task 4: shipped developer helper, two clients and later installed profile

Proposed packaged entry point:
`crates/scopebase-linux/tests/support/run_process_observation_checks.py`.
It follows the accepted parser-helper approach without importing repository
tools. Required absolute flags are:

```text
--package-root PATH --cargo PATH --rustc PATH --rustdoc PATH --cargo-home PATH
--target-dir FRESH_PATH --output-dir FRESH_PATH
--configuration process|union
--fixture-package-root PATH --fixture-manifest PATH
--fixture-image-a PATH --fixture-image-b PATH
--fixture-root PATH --audit-manifest PATH
```

The supplied fixture-package-root is a separately delivered, bound scopebase-testkit
source package with implemented linux-fixtures and its own lock. Its identity is
explicit: these unpublished packages cannot assume a sibling repository path.
The supplied Linux package has its bound Cargo.lock and all source tests/fixtures/client
templates; the supplied Cargo home is already prepared offline. The script
verifies paths/subject inventory/tool identities, creates fresh disjoint output/
target/client roots outside source, refuses repository/Cargo-config ancestors as
the accepted helper does, and never mutates package bytes or installs tools.
This developer route compiles explicit clients AND the separately measured
cfg(test) source object for the original actual-EOF case; the future installed
operator does not compile. After a successful explicit no-run build from the
supplied Linux source/archive, parse the cargo compiler-artifact record, require
the exact expected executable/test target and bind its digest. The separate
fixture parent executes that measured test binary directly. Intentionally passed
barrier channels are attached ONLY to this execution, never inherited through
cargo/rustc/rustdoc. Build, unit-test execution and production-client execution
have distinct windows/resources/identities; no implicit testkit sibling path or
source-byte change is introduced. Audit/fixture manifests select exact prebuilt images/provisioner
assets, not ambient executable discovery. Native namespace recipes run only in
already admitted owned resources; this helper does not implicitly mount/join them.

Client A, `tests/support/process-clients/proc-inspector`, uses only the delivered
process API to acquire explicit fixture PID and print/count complete maps/mount
records, sampled birth and intervals. Independent fixture mapping/record ledger
decides expected values. It remains useful before LX06 proof, and claims none.
Client B, `.../owned-observer`, independently drives the fixture's declared
owned-workload/exec phases, retains application/fixture child custody and calls
the process API. It has distinct expectations/manifest/lock and never calls
Client A or a shared fake oracle. Its control is outside ProcessObservation.

The driver creates two external manifests pinned to the exact supplied package
path/version/features plus the separately supplied testkit package path with
linux-fixtures, and records cargo metadata/dependency identity, compiler
and linked subject binding. Do not resolve a hidden runner copy as the subject.
Run a deliberate changed-copy/wrong-feature control: a known subject change must
fail reached semantic assertions even when the runner/testkit copy stays good.
No donor paths, network, BPF compiler or repository checkout is required.

- [ ] Archive inclusion check proves all process fixtures, helper, original tests,
  negative controls and client templates exist; lock/policy/notices match actual
  closure. Run helper from extracted source and read-only package root on both
  compilers with fresh offline client targets; distinguish source/build cells
  from real native process and namespace outcomes.
- [ ] Root executes affected Linux package feature/source/archive/union cells using
  the supported existing CLI. Exact row IDs/commands are UNBOUND until policy
  updates freeze; record that binding before execution, not a guessed passing list.
- [ ] LX11/LX12 + TT07/TT10 later bind the actual ConformanceAdapter and installed
  source-free/offline/read-only-prefix route:

```text
scopebase-conformance run --profile process-observation-v1
    --fixture-root PATH --output PATH [--fixture-manifest PATH]
```

This is the canonical future operator command, not an existing implementation or
profile result. The cfg(test) EOF route does NOT close the installed source-free
production-object read-boundary row; LX11/LX12+TT07/TT10 must bind its capable
barrier tracer as above. All required native/kernel/delivery cells remain gates.
An accepted bounded core increment records its actual tested slice and every
missing required cell; it does not close installed readiness or mapped-image,
supervision, migrations, publication or BPF producer qualification.

## Future focused command and acceptance receipt

After all root gates, from the assigned candidate checkout using fresh external
targets and full tool identities:

```sh
/home/user/src/m/bpfscope/.scopebase/controller/build-routing-20261018/scopebase-build \
  -- cargo test --locked -p scopebase-linux --features process --lib process::
/home/user/src/m/bpfscope/.scopebase/controller/build-routing-20261018/scopebase-build \
  -- cargo test --locked -p scopebase-linux --features process --test process_observation
```

The observed TT03 proposed packet binds root's private accepted-API lifetime probe
(results SHA2567df4045424060848e4fef346c0a2afd6b6a101fc3473cc7bbc324e92954c8817),
with current fixture source still unchanged. It proposes a lifetime-only
generalization of FixtureAccess::new
outer input/resource slice borrows (the exact lifetime-only root selection), so
prepare can return owner-borrowed access without borrowing local entry arrays.
This is a TT03/root maintenance/input gate after BP02, not an LX08 trait replacement
or an implemented fix. TT03 r2 excludes an alternative private builder; the
root-owned lifetime-only change preserves inner lifetimes. The probe record
remains separate from changed-product qualification.
The adapter consumes the accepted resource() API unchanged.

The resource-gated actual-EOF route first builds (future NOT_RUN):

```text
cargo test --manifest-path <supplied Linux package Cargo.toml> --locked
  --features process --lib --no-run --message-format=json
```

Run it only through the controller-bound build lease/wrapper with exact supplied
compiler/Cargo-home and fresh target. The helper then directly invokes the measured
test executable's exact resource-gated original with `--ignored --exact
--test-threads=1`, using its separately owned barrier parent. Final concrete test
selector/protocol/worker/realm resources remain UNBOUND; no process is started here.
Union mode uses the root-frozen real feature set, never guesses it from discovery.

The job records exact current/MSRV invocations and `cargo test --release` Pid case;
no command here has run. Do not mark existing donor/source checks as results of
this future command. Acceptance binds reviewed candidate SHA, package/source
hashes, immutable source-admission digest, selected-port receipt digest and every
implemented original/control/oracle result. Root verifies all current-copy bytes
and keeps source admission, pure tests, real Linux, kernel and installed evidence
as separate tiers. After focused success, broaden only for changed inputs,
failures or a named coverage gap.


## Frozen original-test preservation map

The following JSON is the complete immutable r2 `original-test-map.json`, copied
verbatim from the input digest recorded in the contract's reviewed-input custody.
It is preserved input data: its private pending-review kind/status labels describe
the frozen draft, while the canonical design status is stated above. Every
selected/deferred field, source range/hash, original test name, destination,
oracle, bad control, adaptation and execution binding remains unchanged. All
selected execution remains PLANNED_NOT_RUN; deferred obligations remain NOT_RUN,
not granted by this task and not closed by LX08. The selected ignored denial
helper remains included; 34 is a source-object count, not 34 runnable tests.

```json
{
  "kind": "LX08_PRIVATE_ORIGINAL_TEST_PRESERVATION_MAP",
  "status": "PRIVATE_R2_AMENDMENT_PENDING_FOCUSED_REREVIEW_NOT_RUN",
  "source_admission": "docs/provenance/admissions/2026-10-22-next-host-scopes.json",
  "selected_count": 34,
  "deferred_count": 12,
  "selected": [
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "pid_reuse_between_pin_and_proc_open_refuses",
        "line_start": 944,
        "line_end": 958,
        "sha256": "36f3ad63f2b4a40b7ee206daddfa27ae69bc8064b165aa544d0908ed3e4dd7de"
      },
      "destination": "src/process/observation/tests.rs",
      "destination_original_test_name": "pid_reuse_between_pin_and_proc_open_refuses",
      "required_cases": [
        "strict_proc_acquisition_brackets"
      ],
      "independent_oracle": "Independent scheduled operation ledger and original retained owner",
      "explicit_adaptation": "Preserve all three liveness checks and birth comparison; adapt Strings to exact typed stage/reason and cumulative charges",
      "known_bad_control": "Omit each bracket, accept missing pidfd/birth or substitute replacement directory",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "changed_admission_birth_during_proc_open_refuses",
        "line_start": 960,
        "line_end": 970,
        "sha256": "8a2990ada6cd8f135b4f8558a214862fa54f52f9f35143af2e0b777ef127358c"
      },
      "destination": "src/process/observation/tests.rs",
      "destination_original_test_name": "changed_admission_birth_during_proc_open_refuses",
      "required_cases": [
        "strict_proc_acquisition_brackets"
      ],
      "independent_oracle": "Independent scheduled operation ledger and original retained owner",
      "explicit_adaptation": "Preserve all three liveness checks and birth comparison; adapt Strings to exact typed stage/reason and cumulative charges",
      "known_bad_control": "Omit each bracket, accept missing pidfd/birth or substitute replacement directory",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "strict_proc_acquisition_requires_birth_and_original_pidfd",
        "line_start": 972,
        "line_end": 984,
        "sha256": "0a034efaef187dd5a243a04a9a6a01aee093e46304def35edd33d55ecf1b86b8"
      },
      "destination": "src/process/observation/tests.rs",
      "destination_original_test_name": "strict_proc_acquisition_requires_birth_and_original_pidfd",
      "required_cases": [
        "strict_proc_acquisition_brackets"
      ],
      "independent_oracle": "Independent scheduled operation ledger and original retained owner",
      "explicit_adaptation": "Preserve all three liveness checks and birth comparison; adapt Strings to exact typed stage/reason and cumulative charges",
      "known_bad_control": "Omit each bracket, accept missing pidfd/birth or substitute replacement directory",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "stable_proc_acquisition_keeps_directory_after_final_liveness_check",
        "line_start": 986,
        "line_end": 1001,
        "sha256": "aa4ce5f706fee3b60f70aa350621cbe3ec5ec6846136ec10ccf1a9eb4b4d884d"
      },
      "destination": "src/process/observation/tests.rs",
      "destination_original_test_name": "stable_proc_acquisition_keeps_directory_after_final_liveness_check",
      "required_cases": [
        "strict_proc_acquisition_brackets"
      ],
      "independent_oracle": "Independent scheduled operation ledger and original retained owner",
      "explicit_adaptation": "Preserve all three liveness checks and birth comparison; adapt Strings to exact typed stage/reason and cumulative charges",
      "known_bad_control": "Omit each bracket, accept missing pidfd/birth or substitute replacement directory",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "original_pin_death_during_actual_maps_read_refuses",
        "line_start": 1003,
        "line_end": 1033,
        "sha256": "f55f319992b9266abc3b46b930dbaa1eb01a4ea4a6302c3d11bc7d321128c7bb"
      },
      "destination": "src/process/reader/tests.rs (resource-gated cfg(test), direct measured-binary launch; external production rows remain independent)",
      "destination_original_test_name": "original_pin_death_during_actual_maps_read_refuses",
      "required_cases": [
        "real_actual_maps_eof_death_barrier_cfg_test",
        "real_original_live_zombie_reaped",
        "brackets_stop_before_next_action"
      ],
      "independent_oracle": "Actual common native reader read returns0 -> private call-local hook/barrier -> separately owned parent exits original A -> original pidfd terminal + exact WNOWAIT unreaped + B active acknowledgement -> release -> next library poll refuses. Bind exact common source/cfg/test object, raw truth and parent custody; hook event alone is not authority.",
      "explicit_adaptation": "Preserve actual native maps-read/death trigger and original named assertion; parent owns exit/WNOWAIT/cleanup instead of ad hoc kill/reap in reader. Build source unit object with --no-run, execute measured artifact --ignored --exact with exactly1 active test; no production callback or fake FD/report owner seam. This source-object tier does not qualify external or installed production object.",
      "known_bad_control": "Combined omission of postread target poll AND final target guard at the SAME actual EOF/owned exit witness must publish parsed snapshot and fail intended no-snapshot assertion; isolated bracket controls assert chronology/no-next-action rather than unsupported guaranteed publication.",
      "status": "PLANNED_NOT_RUN",
      "execution_bindings": "UNBOUND: closed barrier messages/IDs/FD allowlist, native parent/testbinary/helper/worker artifacts, realm lease, cancellation/failure cleanup, capable installed production-object tracer (later LX11/LX12+TT07/TT10)."
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "a_generation_change_stops_before_the_next_target_action",
        "line_start": 1478,
        "line_end": 1506,
        "sha256": "4b94514cfe43a0a685964a2a6c3b85c2c0b149027557bf239a50b79f278c5489"
      },
      "destination": "src/process/observation/tests.rs",
      "destination_original_test_name": "a_generation_change_stops_before_the_next_target_action",
      "required_cases": [
        "strict_proc_acquisition_brackets"
      ],
      "independent_oracle": "Independent chronological action ledger",
      "explicit_adaptation": "Preserve guarded action and zero subsequent action after post-check mismatch",
      "known_bad_control": "Omit pre or post generation check",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "a_pidfd_poll_error_is_never_generation_evidence",
        "line_start": 1508,
        "line_end": 1517,
        "sha256": "14d0cc3020fa3e95784984e628bb2a5df5003a188e2f872a135fb52eb1b9e8a4"
      },
      "destination": "src/process/observation/tests.rs",
      "destination_original_test_name": "a_pidfd_poll_error_is_never_generation_evidence",
      "required_cases": [
        "birth_table_preserves_errors_and_terminal_truth"
      ],
      "independent_oracle": "Independently literal original/current/exit/error table and real poll-error canary",
      "explicit_adaptation": "Keep all source populations; permissive fallback/path-Reused remains donor/model counterexample. Strict retained verification reads its original stat and Changed means retained-source contradiction. Missing stat alone is typed error; original pidfd terminal dominates matching zombie",
      "known_bad_control": "Error-as-alive, permission/malformed-as-exit, zombie-as-live, replacement-as-terminal, path probe disguised as retained Changed",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "root_fence_owned_poll_error_is_not_a_timeout",
        "line_start": 1519,
        "line_end": 1526,
        "sha256": "99e7cf0ba855951e94768287640fa66d69a0dd682e5286ab99d3c26ac75db53c"
      },
      "destination": "src/process/observation/tests.rs",
      "destination_original_test_name": "root_fence_owned_poll_error_is_not_a_timeout",
      "required_cases": [
        "birth_table_preserves_errors_and_terminal_truth"
      ],
      "independent_oracle": "Independently literal original/current/exit/error table and real poll-error canary",
      "explicit_adaptation": "Keep all source populations; permissive fallback/path-Reused remains donor/model counterexample. Strict retained verification reads its original stat and Changed means retained-source contradiction. Missing stat alone is typed error; original pidfd terminal dominates matching zombie",
      "known_bad_control": "Error-as-alive, permission/malformed-as-exit, zombie-as-live, replacement-as-terminal, path probe disguised as retained Changed",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "original_exit_probe_distinguishes_exit_from_transport_failure",
        "line_start": 1528,
        "line_end": 1550,
        "sha256": "7c05f0e367e24c268f64d904f2930c8d8e5dc1384655ef41972dbfa8e2a6ee42"
      },
      "destination": "src/process/observation/tests.rs",
      "destination_original_test_name": "original_exit_probe_distinguishes_exit_from_transport_failure",
      "required_cases": [
        "birth_table_preserves_errors_and_terminal_truth"
      ],
      "independent_oracle": "Independently literal original/current/exit/error table and real poll-error canary",
      "explicit_adaptation": "Keep all source populations; permissive fallback/path-Reused remains donor/model counterexample. Strict retained verification reads its original stat and Changed means retained-source contradiction. Missing stat alone is typed error; original pidfd terminal dominates matching zombie",
      "known_bad_control": "Error-as-alive, permission/malformed-as-exit, zombie-as-live, replacement-as-terminal, path probe disguised as retained Changed",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "original_generation_state_distinguishes_exit_from_pid_reuse",
        "line_start": 1552,
        "line_end": 1617,
        "sha256": "aea30d5fa329840167a40450ce22dc1391b8ed34e480b7c7b02b05ef681d4ca7"
      },
      "destination": "src/process/observation/tests.rs",
      "destination_original_test_name": "original_generation_state_distinguishes_exit_from_pid_reuse",
      "required_cases": [
        "birth_table_preserves_errors_and_terminal_truth"
      ],
      "independent_oracle": "Independently literal original/current/exit/error table and real poll-error canary",
      "explicit_adaptation": "Keep all source populations; permissive fallback/path-Reused remains donor/model counterexample. Strict retained verification reads its original stat and Changed means retained-source contradiction. Missing stat alone is typed error; original pidfd terminal dominates matching zombie",
      "known_bad_control": "Error-as-alive, permission/malformed-as-exit, zombie-as-live, replacement-as-terminal, path probe disguised as retained Changed",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "process_view_records_its_monotonic_admission_boundary",
        "line_start": 1701,
        "line_end": 1708,
        "sha256": "c6538354ed72d9f061ed3681fa82ad0715db7fa735c2aef289a08b762a14649a"
      },
      "destination": "src/process/epoch/tests.rs",
      "destination_original_test_name": "process_view_records_its_monotonic_admission_boundary",
      "required_cases": [
        "admission_time_follows_identity_validation"
      ],
      "independent_oracle": "Independent Instant seam and validation/admission operation ledger",
      "explicit_adaptation": "Preserve post-validation admission time and interval ordering; no lifecycle-event timestamp API",
      "known_bad_control": "Read admission time before identity validation or use timestamp as epoch identity",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "admission_clock_is_read_only_after_identity_validation",
        "line_start": 1719,
        "line_end": 1737,
        "sha256": "e3ff7ee1d2d185d32bf1010b74f3d80e459cac3b839d56d5b247a2b3509bcbb4"
      },
      "destination": "src/process/epoch/tests.rs",
      "destination_original_test_name": "admission_clock_is_read_only_after_identity_validation",
      "required_cases": [
        "admission_time_follows_identity_validation"
      ],
      "independent_oracle": "Independent Instant seam and validation/admission operation ledger",
      "explicit_adaptation": "Preserve post-validation admission time and interval ordering; no lifecycle-event timestamp API",
      "known_bad_control": "Read admission time before identity validation or use timestamp as epoch identity",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "only_a_missing_process_is_proof_of_exit",
        "line_start": 1739,
        "line_end": 1760,
        "sha256": "34b540ab747ff6983f1bc7552232fe03e7c8a4492e2f88ddffb3e0c2c61912f4"
      },
      "destination": "src/process/observation/tests.rs",
      "destination_original_test_name": "only_a_missing_process_is_proof_of_exit",
      "required_cases": [
        "birth_table_preserves_errors_and_terminal_truth"
      ],
      "independent_oracle": "Independently literal original/current/exit/error table and real poll-error canary",
      "explicit_adaptation": "Keep all source populations; permissive fallback/path-Reused remains donor/model counterexample. Strict retained verification reads its original stat and Changed means retained-source contradiction. Missing stat alone is typed error; original pidfd terminal dominates matching zombie",
      "known_bad_control": "Error-as-alive, permission/malformed-as-exit, zombie-as-live, replacement-as-terminal, path probe disguised as retained Changed",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "single_read_stat_matches_read_to_string",
        "line_start": 1762,
        "line_end": 1786,
        "sha256": "374209913e71c74387472761af01292db674a9f966e564a26e41150a09270e55"
      },
      "destination": "src/process/reader/tests.rs",
      "destination_original_test_name": "single_read_stat_matches_read_to_string",
      "required_cases": [
        "stat_reader_preserves_all_original_bytes"
      ],
      "independent_oracle": "Literal bytes, separate raw reader and exact attempted-call accounting",
      "explicit_adaptation": "Preserve short reads/EINTR/hard error/4095-4096-4097-9000/UTF8 refusals; replace unbounded read_to_end with explicit M/R. Adapt impossible u32 PID literals to validated positive absence without constructor-only failure",
      "known_bad_control": "Return first short read, discard overflow, ignore hard error, uncharged interrupt storm or unbounded tail",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "stat_read_retries_interrupted_reads",
        "line_start": 1788,
        "line_end": 1827,
        "sha256": "24aa1fd0d9f0950caf4a3469e2bbf50bbd412b53a0b8ba2973b1ec725a7a9be6"
      },
      "destination": "src/process/reader/tests.rs",
      "destination_original_test_name": "stat_read_retries_interrupted_reads",
      "required_cases": [
        "stat_reader_preserves_all_original_bytes"
      ],
      "independent_oracle": "Literal bytes, separate raw reader and exact attempted-call accounting",
      "explicit_adaptation": "Preserve short reads/EINTR/hard error/4095-4096-4097-9000/UTF8 refusals; replace unbounded read_to_end with explicit M/R. Adapt impossible u32 PID literals to validated positive absence without constructor-only failure",
      "known_bad_control": "Return first short read, discard overflow, ignore hard error, uncharged interrupt storm or unbounded tail",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "stat_read_accumulates_short_reads_and_the_buffer_overflow",
        "line_start": 1829,
        "line_end": 1875,
        "sha256": "9929e5bd12bd0e390d7a1a0466aa0450c4cafb980f8ef64d642d5e9c6eff161b"
      },
      "destination": "src/process/reader/tests.rs",
      "destination_original_test_name": "stat_read_accumulates_short_reads_and_the_buffer_overflow",
      "required_cases": [
        "stat_reader_preserves_all_original_bytes"
      ],
      "independent_oracle": "Literal bytes, separate raw reader and exact attempted-call accounting",
      "explicit_adaptation": "Preserve short reads/EINTR/hard error/4095-4096-4097-9000/UTF8 refusals; replace unbounded read_to_end with explicit M/R. Adapt impossible u32 PID literals to validated positive absence without constructor-only failure",
      "known_bad_control": "Return first short read, discard overflow, ignore hard error, uncharged interrupt storm or unbounded tail",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "stat_fields_survive_a_comm_with_parens_spaces_and_a_fake_state",
        "line_start": 1877,
        "line_end": 1917,
        "sha256": "2641fa785982cd48767a06b56a87ddbc16277794a9fc46339ceb2faf67dc32f4"
      },
      "destination": "tests/process_observation.rs",
      "destination_original_test_name": "stat_fields_survive_a_comm_with_parens_spaces_and_a_fake_state",
      "required_cases": [
        "real_tricky_comm"
      ],
      "independent_oracle": "Worker acknowledged exact comm and parent original child lifecycle/raw stat",
      "explicit_adaptation": "Keep literal tricky comm and actual live-zombie-reaped phases; use owned guarded fixture and direct field truth",
      "known_bad_control": "First closing delimiter, decoy Z, field23, or cleanup failure mistaken for semantic refusal",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "pidfd_denial_helper",
        "line_start": 2049,
        "line_end": 2180,
        "sha256": "0de6455edb49b0c30eb831d247f236766a11eeefd20c23127a2723acf364b19a"
      },
      "destination": "tests/support/process_fixture_adapter.rs + TT03 fixture worker (separate owner/routing gate)",
      "destination_original_test_name": "pidfd_denial_helper",
      "required_cases": [
        "real_seccomp_eperm",
        "real_seccomp_enosys"
      ],
      "independent_oracle": "Actual fresh-exec filter count+1, raw selected errno, readable same-birth stat, parent original pidfd/WNOWAIT and token+phase",
      "explicit_adaptation": "Preserve entire helper protocol populations and parent custody; strict new acquire refuses; genuine prefilter owner follows phases. Original stat-fallback success remains explicit model/counterexample. TT03 destination routing/admission and actual helper artifacts remain separate unbound gates",
      "known_bad_control": "No filter/canned errno/fallback-success/phase replay/erase errno; intended refusal assertion only after native canary and positive",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/process.rs",
        "symbol": "real_pidfd_denial_preserves_proc_identity_without_signal_authority",
        "line_start": 2416,
        "line_end": 2426,
        "sha256": "390c43846d6fb15b62f87f7d643e8dd9324633f77ba3abb6b69c1b0f11514385"
      },
      "destination": "tests/support/process_fixture_adapter.rs + TT03 fixture worker (separate owner/routing gate)",
      "destination_original_test_name": "real_pidfd_denial_preserves_proc_identity_without_signal_authority",
      "required_cases": [
        "real_seccomp_eperm",
        "real_seccomp_enosys"
      ],
      "independent_oracle": "Actual fresh-exec filter count+1, raw selected errno, readable same-birth stat, parent original pidfd/WNOWAIT and token+phase",
      "explicit_adaptation": "Preserve entire helper protocol populations and parent custody; strict new acquire refuses; genuine prefilter owner follows phases. Original stat-fallback success remains explicit model/counterexample. TT03 destination routing/admission and actual helper artifacts remain separate unbound gates",
      "known_bad_control": "No filter/canned errno/fallback-success/phase replay/erase errno; intended refusal assertion only after native canary and positive",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/pidns.rs",
        "symbol": "the_initial_inode_is_the_kernel_abi_constant",
        "line_start": 445,
        "line_end": 449,
        "sha256": "e7cba2784eac18eac42935aa94115ed687421125adb8a1c73dc439b058eae27d"
      },
      "destination": "src/process/observation/tests.rs + tests/process_observation.rs",
      "destination_original_test_name": "the_initial_inode_is_the_kernel_abi_constant",
      "required_cases": [
        "own_view_is_not_initial_or_caller_truth"
      ],
      "independent_oracle": "Literal link/status corpus and independent raw native realm self/NSpid/type witnesses",
      "explicit_adaptation": "Preserve classification and all malformed rows. Initial-only BPF predicate, product CLI/JSON/cgroup/system text, OnceLock source-shape and global injection are explicit excluded assertions. Host admits matched Own nested/initial; kernel-confirmed namespace kind and retained root replace label authority",
      "known_bad_control": "Unknown-as-own, observer-only, ignored NSpid, fake root/agreeing label, stale cache, host PID relabel or thread-leaked seam",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/pidns.rs",
        "symbol": "only_the_initial_inode_classifies_initial",
        "line_start": 455,
        "line_end": 468,
        "sha256": "0e7d9d5284201234bda253cf073ca5a64145726044004384dee44f97f196f454"
      },
      "destination": "src/process/observation/tests.rs + tests/process_observation.rs",
      "destination_original_test_name": "only_the_initial_inode_classifies_initial",
      "required_cases": [
        "own_view_is_not_initial_or_caller_truth"
      ],
      "independent_oracle": "Literal link/status corpus and independent raw native realm self/NSpid/type witnesses",
      "explicit_adaptation": "Preserve classification and all malformed rows. Initial-only BPF predicate, product CLI/JSON/cgroup/system text, OnceLock source-shape and global injection are explicit excluded assertions. Host admits matched Own nested/initial; kernel-confirmed namespace kind and retained root replace label authority",
      "known_bad_control": "Unknown-as-own, observer-only, ignored NSpid, fake root/agreeing label, stale cache, host PID relabel or thread-leaked seam",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/pidns.rs",
        "symbol": "an_unreadable_namespace_is_unknown_never_initial",
        "line_start": 470,
        "line_end": 479,
        "sha256": "f360535e41b44f5be66d847c2537d3c05127a34c9a54ee9a0601bc453cab5d97"
      },
      "destination": "src/process/observation/tests.rs + tests/process_observation.rs",
      "destination_original_test_name": "an_unreadable_namespace_is_unknown_never_initial",
      "required_cases": [
        "own_view_is_not_initial_or_caller_truth"
      ],
      "independent_oracle": "Literal link/status corpus and independent raw native realm self/NSpid/type witnesses",
      "explicit_adaptation": "Preserve classification and all malformed rows. Initial-only BPF predicate, product CLI/JSON/cgroup/system text, OnceLock source-shape and global injection are explicit excluded assertions. Host admits matched Own nested/initial; kernel-confirmed namespace kind and retained root replace label authority",
      "known_bad_control": "Unknown-as-own, observer-only, ignored NSpid, fake root/agreeing label, stale cache, host PID relabel or thread-leaked seam",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/pidns.rs",
        "symbol": "a_link_that_is_not_a_pid_namespace_is_unknown",
        "line_start": 481,
        "line_end": 507,
        "sha256": "6560dea4d5617b59a5d6075fc2c9044106d43267d14f18a7611998523d001de7"
      },
      "destination": "src/process/observation/tests.rs + tests/process_observation.rs",
      "destination_original_test_name": "a_link_that_is_not_a_pid_namespace_is_unknown",
      "required_cases": [
        "own_view_is_not_initial_or_caller_truth"
      ],
      "independent_oracle": "Literal link/status corpus and independent raw native realm self/NSpid/type witnesses",
      "explicit_adaptation": "Preserve classification and all malformed rows. Initial-only BPF predicate, product CLI/JSON/cgroup/system text, OnceLock source-shape and global injection are explicit excluded assertions. Host admits matched Own nested/initial; kernel-confirmed namespace kind and retained root replace label authority",
      "known_bad_control": "Unknown-as-own, observer-only, ignored NSpid, fake root/agreeing label, stale cache, host PID relabel or thread-leaked seam",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/pidns.rs",
        "symbol": "only_this_namespaces_own_proc_classifies_own",
        "line_start": 592,
        "line_end": 635,
        "sha256": "6da31d17f2e30a1b21fb30387ecb046848a2be9a1d9ad7ad70370f7035574806"
      },
      "destination": "src/process/observation/tests.rs + tests/process_observation.rs",
      "destination_original_test_name": "only_this_namespaces_own_proc_classifies_own",
      "required_cases": [
        "own_view_is_not_initial_or_caller_truth"
      ],
      "independent_oracle": "Literal link/status corpus and independent raw native realm self/NSpid/type witnesses",
      "explicit_adaptation": "Preserve classification and all malformed rows. Initial-only BPF predicate, product CLI/JSON/cgroup/system text, OnceLock source-shape and global injection are explicit excluded assertions. Host admits matched Own nested/initial; kernel-confirmed namespace kind and retained root replace label authority",
      "known_bad_control": "Unknown-as-own, observer-only, ignored NSpid, fake root/agreeing label, stale cache, host PID relabel or thread-leaked seam",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/pidns.rs",
        "symbol": "a_foreign_proc_under_an_initial_observer_is_a_mismatch",
        "line_start": 637,
        "line_end": 688,
        "sha256": "48dd405cf2e27f24dce05f22c432dcbb17c5d9459540de62f32da576808acfb2"
      },
      "destination": "src/process/observation/tests.rs + tests/process_observation.rs",
      "destination_original_test_name": "a_foreign_proc_under_an_initial_observer_is_a_mismatch",
      "required_cases": [
        "own_view_is_not_initial_or_caller_truth"
      ],
      "independent_oracle": "Literal link/status corpus and independent raw native realm self/NSpid/type witnesses",
      "explicit_adaptation": "Preserve classification and all malformed rows. Initial-only BPF predicate, product CLI/JSON/cgroup/system text, OnceLock source-shape and global injection are explicit excluded assertions. Host admits matched Own nested/initial; kernel-confirmed namespace kind and retained root replace label authority",
      "known_bad_control": "Unknown-as-own, observer-only, ignored NSpid, fake root/agreeing label, stale cache, host PID relabel or thread-leaked seam",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/pidns.rs",
        "symbol": "an_unserved_proc_refuses_every_capture_by_name",
        "line_start": 690,
        "line_end": 723,
        "sha256": "44037f51323de831da77f829d073e27ec42e55824533e925cbe8f0b9043572dd"
      },
      "destination": "src/process/observation/tests.rs + tests/process_observation.rs",
      "destination_original_test_name": "an_unserved_proc_refuses_every_capture_by_name",
      "required_cases": [
        "own_view_is_not_initial_or_caller_truth"
      ],
      "independent_oracle": "Literal link/status corpus and independent raw native realm self/NSpid/type witnesses",
      "explicit_adaptation": "Preserve classification and all malformed rows. Initial-only BPF predicate, product CLI/JSON/cgroup/system text, OnceLock source-shape and global injection are explicit excluded assertions. Host admits matched Own nested/initial; kernel-confirmed namespace kind and retained root replace label authority",
      "known_bad_control": "Unknown-as-own, observer-only, ignored NSpid, fake root/agreeing label, stale cache, host PID relabel or thread-leaked seam",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/pidns.rs",
        "symbol": "the_numbering_composes_the_mounted_procs_view",
        "line_start": 725,
        "line_end": 772,
        "sha256": "4bebbb21dc6c2dd835a581c12b14ddff66258d0c39d1bbfd2dc2fa4b09a4ae40"
      },
      "destination": "src/process/observation/tests.rs + tests/process_observation.rs",
      "destination_original_test_name": "the_numbering_composes_the_mounted_procs_view",
      "required_cases": [
        "own_view_is_not_initial_or_caller_truth"
      ],
      "independent_oracle": "Literal link/status corpus and independent raw native realm self/NSpid/type witnesses",
      "explicit_adaptation": "Preserve classification and all malformed rows. Initial-only BPF predicate, product CLI/JSON/cgroup/system text, OnceLock source-shape and global injection are explicit excluded assertions. Host admits matched Own nested/initial; kernel-confirmed namespace kind and retained root replace label authority",
      "known_bad_control": "Unknown-as-own, observer-only, ignored NSpid, fake root/agreeing label, stale cache, host PID relabel or thread-leaked seam",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/pidns.rs",
        "symbol": "the_test_seam_injects_on_this_thread_only",
        "line_start": 774,
        "line_end": 786,
        "sha256": "30cf08489a3543a310b3580503ed79d4eb074e2bf6d1e5f2f56b4636e7b6df2b"
      },
      "destination": "src/process/observation/tests.rs + tests/process_observation.rs",
      "destination_original_test_name": "the_test_seam_injects_on_this_thread_only",
      "required_cases": [
        "own_view_is_not_initial_or_caller_truth"
      ],
      "independent_oracle": "Literal link/status corpus and independent raw native realm self/NSpid/type witnesses",
      "explicit_adaptation": "Preserve classification and all malformed rows. Initial-only BPF predicate, product CLI/JSON/cgroup/system text, OnceLock source-shape and global injection are explicit excluded assertions. Host admits matched Own nested/initial; kernel-confirmed namespace kind and retained root replace label authority",
      "known_bad_control": "Unknown-as-own, observer-only, ignored NSpid, fake root/agreeing label, stale cache, host PID relabel or thread-leaked seam",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "P:src/pidns.rs",
        "symbol": "the_live_read_is_a_pid_namespace_link",
        "line_start": 788,
        "line_end": 811,
        "sha256": "3e55ac8a80ec9e852922bbc3ceb5a502dfe5940836fe1dae1004d40d27a4484e"
      },
      "destination": "src/process/observation/tests.rs + tests/process_observation.rs",
      "destination_original_test_name": "the_live_read_is_a_pid_namespace_link",
      "required_cases": [
        "own_view_is_not_initial_or_caller_truth"
      ],
      "independent_oracle": "Literal link/status corpus and independent raw native realm self/NSpid/type witnesses",
      "explicit_adaptation": "Preserve classification and all malformed rows. Initial-only BPF predicate, product CLI/JSON/cgroup/system text, OnceLock source-shape and global injection are explicit excluded assertions. Host admits matched Own nested/initial; kernel-confirmed namespace kind and retained root replace label authority",
      "known_bad_control": "Unknown-as-own, observer-only, ignored NSpid, fake root/agreeing label, stale cache, host PID relabel or thread-leaked seam",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "O:src/pin.rs",
        "symbol": "pin_self_verifies",
        "line_start": 144,
        "line_end": 150,
        "sha256": "b5f8ff0aab39dac8fb647a7cfe2d5c2c62ae0dec5314dd116e3912ecbc835636"
      },
      "destination": "tests/process_observation.rs + tests/ui/process_*.rs",
      "destination_original_test_name": "pin_self_verifies",
      "required_cases": [
        "real_no_control_audit"
      ],
      "independent_oracle": "Independent active A/B acknowledgements, original wait custody and capable subject-window syscall audit",
      "explicit_adaptation": "Preserve observation/control type split and active target; original survival/kill0 oracle is insufficient alone, add audit. Oracle kill0/wait occurs outside monitored library window",
      "known_bad_control": "Hidden signal0/wait-WNOHANG/Drop-control or raw-pidfd export; capable canaries mandatory",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "O:src/pin.rs",
        "symbol": "external_target_adopts_without_signaling",
        "line_start": 153,
        "line_end": 160,
        "sha256": "764148acfafdbd74dcba77285e5bb50af283fa9d4368c04e1cc624b694a0ac09"
      },
      "destination": "tests/process_observation.rs + tests/ui/process_*.rs",
      "destination_original_test_name": "external_target_adopts_without_signaling",
      "required_cases": [
        "real_no_control_audit"
      ],
      "independent_oracle": "Independent active A/B acknowledgements, original wait custody and capable subject-window syscall audit",
      "explicit_adaptation": "Preserve observation/control type split and active target; original survival/kill0 oracle is insufficient alone, add audit. Oracle kill0/wait occurs outside monitored library window",
      "known_bad_control": "Hidden signal0/wait-WNOHANG/Drop-control or raw-pidfd export; capable canaries mandatory",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "O:src/pin.rs",
        "symbol": "dead_pid_fails_to_pin",
        "line_start": 162,
        "line_end": 167,
        "sha256": "15c56775e54cdd86e833f49a57d0debc550fece897289730d5cd654fefb4131b"
      },
      "destination": "tests/process_observation.rs",
      "destination_original_test_name": "dead_pid_fails_to_pin",
      "required_cases": [
        "strict_proc_acquisition_brackets"
      ],
      "independent_oracle": "Independently established absent supported positive PID, or original exited owned target",
      "explicit_adaptation": "Replace u32::MAX-7 constructor overflow with actual missing/dead positive Pid input; preserve reached no-owner refusal",
      "known_bad_control": "Reject merely at checked-Pid constructor while pretending dead-target acquisition was tested",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "O:src/pin.rs",
        "symbol": "stat_parse_tolerates_tricky_comm",
        "line_start": 169,
        "line_end": 177,
        "sha256": "5821333c961b1a227868a373b9a13fcf26e265c562c222c1ade315ac4b01e3ae"
      },
      "destination": "src/process/reader/tests.rs",
      "destination_original_test_name": "stat_parse_tolerates_tricky_comm",
      "required_cases": [
        "stat_fields_use_last_delimiter_and_field22"
      ],
      "independent_oracle": "Original literal expected777 and separate malformed/short vectors",
      "explicit_adaptation": "Preserve last delimiter/field22 expected values and both negative rows; reject historical unique-per-boot ticks claim",
      "known_bad_control": "First delimiter/off-by-one or shared production parser as oracle",
      "status": "PLANNED_NOT_RUN"
    },
    {
      "source": {
        "file_id": "O:tests/target_lifecycle.rs",
        "symbol": "external_pid_target_is_never_signaled",
        "line_start": 358,
        "line_end": 375,
        "sha256": "b152556306d29199f3d5367b2ffe9b2625549d716f2cc720fe4a3491684994f3"
      },
      "destination": "tests/process_observation.rs + tests/ui/process_*.rs",
      "destination_original_test_name": "external_pid_target_is_never_signaled",
      "required_cases": [
        "real_no_control_audit"
      ],
      "independent_oracle": "Independent active A/B acknowledgements, original wait custody and capable subject-window syscall audit",
      "explicit_adaptation": "Preserve observation/control type split and active target; original survival/kill0 oracle is insufficient alone, add audit. Oracle kill0/wait occurs outside monitored library window",
      "known_bad_control": "Hidden signal0/wait-WNOHANG/Drop-control or raw-pidfd export; capable canaries mandatory",
      "status": "PLANNED_NOT_RUN"
    }
  ],
  "deferred": [
    {
      "file_id": "P:src/process.rs",
      "symbol": "mountinfo_is_read_only_after_the_fd_is_open_with_retained_rechecks",
      "line_start": 1416,
      "line_end": 1441,
      "sha256": "6df768d2780b6c53a6bb4493fc70a3c9c6ef6973824eb78a5914d2d9de974e77",
      "recommendation": "ADAPT_VIEW_BRACKET_PRESERVE_LX06_ASSOCIATION_OBLIGATION",
      "proposed_destination": "LX08 process view brackets; LX06 held-file-open-before-mount-table association test",
      "reason": "Preserve original semantics explicitly: LX08 may test member-open/view/read bracketing; only LX06 can close the original held-file association order. No dependency cycle or premature association claim.",
      "execution_status": "NOT_RUN",
      "source_grant": "NOT_GRANTED",
      "later_owner": "LX06",
      "closure_by_lx08": false
    },
    {
      "file_id": "P:src/process.rs",
      "symbol": "a_changed_mount_namespace_after_open_is_rejected_before_table_use",
      "line_start": 1444,
      "line_end": 1476,
      "sha256": "57a4299fe4f0563a6c37eafa27ff42a7151253b2b9cb084aaf2b0b74ce396566",
      "recommendation": "ADAPT_VIEW_BRACKET_PRESERVE_LX06_ASSOCIATION_OBLIGATION",
      "proposed_destination": "LX08 process view brackets; LX06 held-file-open-before-mount-table association test",
      "reason": "Preserve original semantics explicitly: LX08 may test member-open/view/read bracketing; only LX06 can close the original held-file association order. No dependency cycle or premature association claim.",
      "execution_status": "NOT_RUN",
      "source_grant": "NOT_GRANTED",
      "later_owner": "LX06",
      "closure_by_lx08": false
    },
    {
      "file_id": "P:src/process.rs",
      "symbol": "original_pidfd_is_the_only_signal_authority",
      "line_start": 1620,
      "line_end": 1640,
      "sha256": "7e335338abd6594c10fd293298f951e687a02b155247f59b8ac2d658ab8c7c99",
      "recommendation": "REFERENCE_ORIGINAL_APP_ASSERTIONS",
      "later_owner": "LX09",
      "reason": "Signal operations stay outside ProcessObservation; retain LX08 UI/no-control and denial negative facts.",
      "core_equivalent_obligation_retained": true,
      "execution_status": "NOT_RUN",
      "source_grant": "NOT_GRANTED",
      "closure_by_lx08": false
    },
    {
      "file_id": "P:src/process.rs",
      "symbol": "nofile_raise_is_monotonic_and_reports_a_usable_budget",
      "line_start": 1643,
      "line_end": 1666,
      "sha256": "58333f913a817c71375e359ae016cd5e46830583f98086773cea15af5a089220",
      "recommendation": "REFERENCE_ORIGINAL_APP_ASSERTIONS",
      "later_owner": "MG01 (original p11scope application policy; no LX08 closure)",
      "reason": "Do not raise limits in library.",
      "core_equivalent_obligation_retained": true,
      "execution_status": "NOT_RUN",
      "source_grant": "NOT_GRANTED",
      "closure_by_lx08": false
    },
    {
      "file_id": "P:src/process.rs",
      "symbol": "low_pidfd_budget_demotes_without_global_failure",
      "line_start": 1669,
      "line_end": 1678,
      "sha256": "b6d315fd553141ac152aa719f962ed4cbd9b507d50579549afb2044d66aeae29",
      "recommendation": "REFERENCE_ORIGINAL_APP_ASSERTIONS",
      "later_owner": "MG01 (original p11scope application policy; no LX08 closure)",
      "reason": "Tracker fallback/LRU does not define strict observation acquire.",
      "core_equivalent_obligation_retained": true,
      "execution_status": "NOT_RUN",
      "source_grant": "NOT_GRANTED",
      "closure_by_lx08": false
    },
    {
      "file_id": "P:src/process.rs",
      "symbol": "whole_process_exit_becomes_a_retirement",
      "line_start": 1681,
      "line_end": 1699,
      "sha256": "b4b9c3b8e1bb9b3534d0faea298f6f37032591a0af034ce68e1f9700c5524dd1",
      "recommendation": "REFERENCE_ORIGINAL_APP_ASSERTIONS",
      "later_owner": "MG01 (original p11scope application policy; no LX08 closure)",
      "reason": "Tracker registry retirement is separate; real exit oracle still required in LX08.",
      "core_equivalent_obligation_retained": true,
      "execution_status": "NOT_RUN",
      "source_grant": "NOT_GRANTED",
      "closure_by_lx08": false
    },
    {
      "file_id": "P:src/process.rs",
      "symbol": "lifecycle_event_must_follow_this_exact_view_admission",
      "line_start": 1711,
      "line_end": 1717,
      "sha256": "96e9fdeb08ca2447d8befb1e14799587142909d9997c6a1173f8604bb81e7b15",
      "recommendation": "REFERENCE_ORIGINAL_APP_ASSERTIONS",
      "later_owner": "MG01 (original p11scope application policy; no LX08 closure)",
      "reason": "Hook timestamp matching is not userspace process observation authority.",
      "core_equivalent_obligation_retained": true,
      "execution_status": "NOT_RUN",
      "source_grant": "NOT_GRANTED",
      "closure_by_lx08": false
    },
    {
      "file_id": "P:src/process.rs",
      "symbol": "overall_budget_evicts_lru_only",
      "line_start": 1920,
      "line_end": 1927,
      "sha256": "8f1353004513f2cbfd4b4e29a262e746543014398642b1ada966af1d7eaa389a",
      "recommendation": "REFERENCE_ORIGINAL_APP_ASSERTIONS",
      "later_owner": "MG01 (original p11scope application policy; no LX08 closure)",
      "reason": "No process-global tracker or eviction policy in LX08.",
      "core_equivalent_obligation_retained": true,
      "execution_status": "NOT_RUN",
      "source_grant": "NOT_GRANTED",
      "closure_by_lx08": false
    },
    {
      "file_id": "P:src/pidns.rs",
      "symbol": "labels_are_the_published_closed_set",
      "line_start": 510,
      "line_end": 516,
      "sha256": "3b308854ca6e7ea48c97ba0da97649db6237d3f153ca27764b5737c9b2dc4cea",
      "recommendation": "REFERENCE_ORIGINAL_APP_ASSERTIONS",
      "later_owner": "MG01 (original p11scope application policy; no LX08 closure)",
      "reason": "Closed internal classifications retained; public app strings are not imported.",
      "core_equivalent_obligation_retained": true,
      "execution_status": "NOT_RUN",
      "source_grant": "NOT_GRANTED",
      "closure_by_lx08": false
    },
    {
      "file_id": "P:src/pidns.rs",
      "symbol": "pid_scope_is_allowed_only_in_the_initial_namespace",
      "line_start": 519,
      "line_end": 541,
      "sha256": "98cef27e26f4b65f898c178639ea9e2d91de0d86543388ea9a3f4e3e856d8c36",
      "recommendation": "REFERENCE_ORIGINAL_APP_ASSERTIONS",
      "later_owner": "MG01 (original p11scope application policy; no LX08 closure)",
      "reason": "Preserve classifier/predicate outcomes under explicit support policy; CLI/cgroup recommendation stays local.",
      "core_equivalent_obligation_retained": true,
      "execution_status": "NOT_RUN",
      "source_grant": "NOT_GRANTED",
      "closure_by_lx08": false
    },
    {
      "file_id": "P:src/pidns.rs",
      "symbol": "evidence_names_both_numberings",
      "line_start": 544,
      "line_end": 556,
      "sha256": "bcd2382d63e823abbb85aee22fae0fda99a923c00e0ff6d3a2ab3b7869d0e9e4",
      "recommendation": "REFERENCE_ORIGINAL_APP_ASSERTIONS",
      "later_owner": "MG01 (original p11scope application policy; no LX08 closure)",
      "reason": "Both domains retained internally; do not import app JSON schema or mint live authority from it.",
      "core_equivalent_obligation_retained": true,
      "execution_status": "NOT_RUN",
      "source_grant": "NOT_GRANTED",
      "closure_by_lx08": false
    },
    {
      "file_id": "P:src/pidns.rs",
      "symbol": "only_a_mismatched_observer_warns",
      "line_start": 559,
      "line_end": 584,
      "sha256": "bdf09d00c89ef6825270ac51bb89444a13da2f2ce32b3d4dadc65ee192dd65d8",
      "recommendation": "REFERENCE_ORIGINAL_APP_ASSERTIONS",
      "later_owner": "MG01 (original p11scope application policy; no LX08 closure)",
      "reason": "Warning/cgroup/visibility policy stays app local; unknown/mismatch refusal remains tested.",
      "core_equivalent_obligation_retained": true,
      "execution_status": "NOT_RUN",
      "source_grant": "NOT_GRANTED",
      "closure_by_lx08": false
    }
  ],
  "prior_map": {
    "path": ".scopebase/controller/resume-20261022/lx08-crossreview-r1/contract-draft-r1/original-test-map.json",
    "sha256": "4829e9410ea7202bf2397589bc4813ddf6c9b61ca799c8f02305fd9a95bd2cb9",
    "preservation": "All34 selected source objects and12 deferred objects exactly preserved; no donor access in r2; source-range hashes inherited from bounded r1 receipt."
  },
  "r2_root_adopted_delta": [
    "Strict creator-authority constructor/current-context guards and revised inventory tests are additive NEW tests, not replacements for selected originals.",
    "Actual-maps-read death original remains native read/death evidence in common-reader cfg(test) object; production-object and installed tiers separately required.",
    "Prefilter epoch target denial and fresh constructor creator denial are separate actual required populations.",
    "Ignored resource-gated EOF test must be explicitly executed exactly once from measured no-run artifact; missing/zero/setup failure is Incomplete."
  ]
}
```
