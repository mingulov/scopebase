# User-run conformance: architecture and release review

2026-10-17. Proposal review following the owner's requirement that filesystem mapping checks remain explicit, ship in a ready package and be runnable by library users. This supplements the earlier architecture review: its small-first conclusion remains an implementation sequence, not an exemption from delivering the requested mapped-image capability. No product edits, builds, mounts, probes or live experiments were performed. No implementation specification is approved here.

## Decision: ship the capability together with its executable contract

A small held-file/read pilot is a useful internal milestone. A package advertised as providing mapped-image identity must additionally ship its supported filesystem-domain checks, explicit calibration API, failure/uncertainty outcomes, runnable tests and user documentation. Calling calibration “optional” must mean the caller controls whether an operation may create a mapping; it must not mean the package can advertise mapping support while deferring its implementation or qualification.

Separate the milestones visibly:

| Milestone | What it can claim | Required evidence/deliverables |
|---|---|---|
| Internal held-file pilot | Selected acquisition and bounded-read mechanisms integrated in p11scope/OSSLscope. | H04/H06 subsets, ownership/resource tests, selected file pins and two migration seams. No mapped-image readiness claim. |
| Independently usable file package | Its documented held-file/read API works within a finite supported contract. | Public API, code, packaged tests/fixtures, user-run path, docs, standalone package verification and applicable supported cells. The library may remain useful without BPF. |
| Ready mapped-image capability | It resolves or explicitly refuses the advertised stat/mount/maps relationships in the named environments. | H05 and relevant H04/H06/H19 cases, explicit active/passive policies, retained-evidence invalidation, maintained real filesystem cells, packaged user tests and two consumer adapters. Actual attachment claims additionally need the adapter's live evidence. |

This preserves independent Rust libraries first, SDK second and C/Mojo later. It does not require every library to implement every feature. It requires every advertised behavior to have implementation, tests and documentation before readiness is claimed. [Current sequence](README.md#proposed-sequence-and-exit-criteria), [H04–H06/H19](testing-strategy.md#hard-regression-matrix-32-scenarios-with-component-specific-gates).

## What the donor code proves, and what extraction must add

The following source observations are pinned to p11scope `fb81ee74b5c185d8abaef1cd93b168d6c241989e`, using `git show`; they do not describe subsequent product changes or fresh runtime results. `P` is the product root identified in [p11scope research](p11scope.md#revision-and-authority).

- `P/crates/manifest/src/identity.rs:111–159` resolves an opened FD's mount ID through a supplied mount table; its documentation requires the process view through which the file was opened. The convenience function reads `/proc/self/mountinfo` using `read_to_string`, without a public total byte cap. The mount-table domain is essential input, not incidental diagnostic text.
- `:177–193` pins with O_PATH, checks regular-file type, then opens through the retained descriptor. `:401–412` provides `SelfMappingProbe`, but exposes overlay classification as `bool` and calibration as `Option<ObjectKey>`. Those are useful donor seams, not sufficient public diagnosis: denial, wrong view, unsupported mapping, exhausted budget and missing evidence collapse into false/None.
- `:460–485` creates one private read-only mapping of the actual held FD and reads its own maps entry; `:497–503` unmaps in Drop. This has observable effects even without PROT_EXEC. `:365–397` allows caller budgeting but also an unbounded adapter; a single-line bound and stop-at-match are not a total scan/time bound.
- `P/src/discovery/kernel_identity.rs:29–73` retains capture-watched exclusions. Collisions may deny acceleration but must never grant identity. The [recorded filesystem fixes](p11scope.md#hard-fixes-worth-carrying-with-their-regressions) explain why retained proof and no-new-mapping behavior matter during attachment/cleanup.
- [OSSLscope O4/O5](osslscope.md#o4-descriptor-bound-attachment-identity-and-stable-physical-cookies) supplies descriptor-bound attachment and bounded reads, with A→B→A replacement tests. It deliberately uses a stat-derived identity domain; FD retention and metadata checks do not establish immutable contents. Extracting one generic integer key would lose a real guarantee boundary.

A ready library must translate these mechanisms into explicit contracts; it should not simply rename the donor types. Keep the underlying parser/syscall dependencies and product policy boundaries from the [external comparison](external-comparison.md#existing-safe-wrappers-still-need-an-application-contract).

## Keep observations, calibration and conformance reports distinct

Three different things must not share one “verified” type:

1. **Observation:** facts read from a particular held file/proc/mount view, with limits and observation context. This can involve I/O but must not silently mmap, attach BPF, enter a namespace, mount a filesystem or spawn a workload. Its method name and documented effects must be precise; “read-only” does not mean “no observable effect.”
2. **Object-bound mapping evidence:** the result of comparing observations and, when explicitly permitted, calibrating the actual held object. It is bound to retained ownership and named context, with conditions for reuse. It says nothing by itself about immutable contents, current target mm, executable offsets, attachment completion or a whole environment.
3. **Conformance report:** historical results of named scenarios against a package/backend/configuration in a recorded environment. It is useful for diagnosis and maintained support decisions. It is neither runtime admission authority nor a transferable proof that an arbitrary file is safe to use.

A plausible API decomposition is observation → pure decision/planning → explicitly requested calibration → comparison/revalidation. These are responsibilities, not approved function signatures. A no-new-mapping request can reuse sufficiently bound retained evidence or return inconclusive; it cannot silently fall back to mmap. Calibration permission should name the operation, target capability, resource budget and allowed effects. This is an explicit API/runner setting, not a mandatory interactive approval prompt.

Active calibration must use the held FD, not reopen a display pathname. Replacing a watched object with an unwatched copy may be an excellent environment test fixture, but cannot prove the original object's mapping identity. Watched-file exclusions and caller scheduling belong in the operational contract. A detached selftest process still can perturb shared tracing or filesystem activity, so process isolation alone is not a noninterference proof. The caller needs an effect plan and a way to select safe fixture roots or defer an operation with a recorded result.

## Result strength and lifetime need more than a capability boolean

Do not model all results as one ordered ladder from “unknown” to “verified.” A stat observation, a maps-domain match, a content digest, a successful attach and an application workload result answer different questions. Preserve separate evidence dimensions and explicit prerequisites for the requested comparison.

Return a successful match/mismatch only for a completed comparison in the stated domains. Keep inconclusive, denied, unsupported, stale context, malformed input and budget exhaustion distinguishable. A mismatch says the compared evidence differs; it does not automatically prove two pathnames identify different immutable images. A denied probe says neither supported nor unsupported. Keep cleanup outcome separate: an observation can succeed while teardown fails and ownership remains unresolved.

A capability snapshot must describe its scope and invalidation rules, not just contain uname/filesystem strings:

| Bound fact | Minimum scope/revalidation requirement |
|---|---|
| Held-file identity | Retain the original capability; descriptor numbers can be reused. State whether a duplicated descriptor shares the same owner/evidence. Recheck relevant metadata without claiming this detects all in-place writes. |
| Mount-domain resolution | Bind the proc/mount namespace view and observation context. Mount IDs are local and reusable; retaining a namespace handle does not freeze its mount table. Churn, missing IDs or changed view cause bounded reacquisition or refusal. |
| Target maps observation | Bind target process incarnation and the observation interval. PID/starttime/pidfd does not freeze exec/mm. A maps snapshot cannot silently become an atomic current-image proof. |
| Calibration result | Bind the retained file, method, observed mapping key and relevant view; define when reuse is invalid. Do not generalize one overlay object to every mount, subvolume, copy-up state or namespace. |
| Environment probe | Bind the backend, relevant permissions/capabilities, kernel/profile and fixture location. A successful probe before privilege changes or namespace transition does not authorize later operations. |
| Serialized report | Bind run/package/case versions and inputs; keep it data. Deserializing a PASS report must not construct a live trusted evidence capability. |

Prefer operation-local evidence initially. Persistent caching is a separate design with tested invalidation, bounded retention and explicit restart behavior; a TTL does not establish coherence. Where races cannot be excluded, describe the observation's interval/strength rather than inventing a timeless boolean. Foreign-view, stale-token, inode/FD reuse, copy-up and exec negatives belong beside happy-path fixture cases.

## Public testability without a parallel implementation

Ship a reusable conformance entry point and fixtures that downstream users can call through their own library integration. The [distribution comparison](test-distribution-options.md) separates source tests, a required installed operator route and a test-only API; a standalone diagnostic binary is optional when an independently distributable application command supplies that route. None runs automatically merely because an application depends on the library.

The critical binding is to the implementation under test. A testkit that depends on its own compatible library version can accidentally qualify that copy while the application uses another version or feature set. Scenarios should take an adapter supplied by the consumer and invoke its actual public boundary; the adapter identifies the selected package/version/source override, features, backend and configuration. Record lock/build identity as appropriate, but do not treat a version string as proof of identical bytes. A standalone doctor qualifies its embedded library, not every application's statically linked copy. Kernel/BPF claims additionally bind the actual object and loader/compiler profile.

Avoid a new general syscall abstraction solely for testing. Keep narrow seams already justified by the donors: held-file acquisition/reader, mount/proc observation, calibration, clock/budget and attachment owner. Expose semantic scenario adapters rather than forcing downstream users to reproduce private caches or state machines. Use compile-time contracts and deterministic fault injection where possible, then exercise the real Linux backend with owned fixtures. The same public production path should be reachable from both, without a test-only branch that bypasses the property being checked.

Custom backends need an explicit trust boundary. Passing a generic trait test proves that backend's declared behavior for those scenarios; it does not qualify its access to the real kernel. A mock must not mint indistinguishable live-kernel authority. Use provenance/context-bearing observations and state which guarantees require the trusted Linux adapter. Test-only constructors/fault hooks should not silently widen normal production authority. This keeps the library usable with custom environments without falsely inheriting the built-in backend's support claim.

## Adaptive user tests must preserve obligations

Adapt fixture execution to what the user can supply, but determine required obligations from the requested capability/profile **before** discovery. Otherwise a machine without Btrfs, overlay mounts, namespace access or BPF permissions can omit every difficult case and report misleading success.

Maintain two independent outputs: each scenario's execution result and whether the selected claim/profile has its required evidence. A required absent fixture remains NOT_RUN/BLOCKED with a concrete prerequisite; it cannot become an optional pass. An intentionally excluded feature is outside the requested profile, not qualified. Unexpected refusal in a declared supported cell is a failure to investigate; do not convert arbitrary runtime errors into “unsupported.” Cleanup and resource-budget outcomes remain visible even after a semantic assertion succeeds.

Users should be able to supply ordinary writable directories on existing filesystems and explicit namespace/fixture contexts. The harness must verify the actual filesystem/view it exercised; defaulting to `/tmp` can silently test a different mount. Provide reproducible disposable setup recipes for maintained Btrfs/overlay/copy-up and cross-namespace cells. Mount creation, namespace changes, probes and workloads are explicit modes; normal library tests do not acquire them invisibly. Refusal paths are runnable without granting privileges.

Use constructed fixture relationships as independent oracles: retain two distinct inodes, preserve one across rename/delete, pass the chosen held FD to an owned mapper, and assert which object remains associated. Do not copy the returned maps/device tuple into the expected result. Test “no-new-mapping” by observing an attempted-effect seam and real fixture behavior, not merely by checking the final enum. Include positive and negative populations; all-zero/no-activity cannot qualify attachment or noninterference.

One local PASS covers that scenario's package/backend and environment at that time. Maintainer qualification still needs a finite declared support matrix, including the historical defect cells and refusal/fallback behavior. State explicitly which combinations were tested and which are unsupported/unknown. Pairwise sampling or a modern-host run cannot be presented as every combination; conversely no reasonable finite campaign proves all future filesystems, races or kernels. “Fully tested” should mean all advertised contracts and required declared cells have satisfied their gates, with limitations visible.

## Deep gaps that affect readiness

| Gap in the current proposal | Required architectural correction |
|---|---|
| File-first pilot can be mistaken for completed mapping work. | Name the ready mapped-image milestone and its mandatory H05 code/tests/docs; defer implementation order, not the promised capability. |
| Public identity outcomes inherit bool/Option donor seams. | Preserve typed reasons and evidence domains, plus independent cleanup outcome. Test consumers' decisions on each refusal class. |
| Retained proof has no common invalidation contract. | Define owner/context binding, exec/mount/permission change behavior, bounded retry and cache expiry-by-invalidation before exposing reusable evidence. |
| Bounded reads are confused with bounded operations. | Bound mountinfo/maps bytes, lines, attempts, retained FDs/mappings and aggregate work. Document that a deadline checked between syscalls does not interrupt a stalled filesystem syscall. Isolate potentially blocking probes where a hard return bound is claimed, and track unresolved worker/resource ownership. |
| User tests may exercise another package/backend or only mocks. | Bind consumer adapters, package/features/backend and actual artifacts; validate the real installed/archive route. Keep model, live and custom-backend verdicts distinct. |
| Adaptive test availability can shrink the claimed contract. | Freeze requested obligations first; expose missing prerequisites and coverage debt independently of passed cases. |
| Test effects can alter the observed target. | Explicit calibration and test effect plans, caller-supplied roots/context, watched-file exclusions and retained-proof/no-new-mapping tests. No silent operational fallback to an active probe. |
| Product-owned attachment may leave a library seam untested. | Library owns reusable retention/negative scenarios; each product supplies its real adapter and workload oracle. Preserve detach/quarantine semantics without embedding product controllers. |
| Published tests may rot independently of the package. | Version case IDs/expectations and compatible adapter protocol; test every advertised version/profile combination from the release archive and minimal consumer. Intentional expectation changes need a declared contract change. |

The fourth gap is directly motivated by p11scope's uncapped mountinfo convenience read and unbounded probe-budget option, rather than a claim that all current application call paths lack budgets. Its current caller adapters and original safety boundaries must be preserved during extraction.

## Minimum release-gating contract

Before calling the mapped-image library ready, require all of the following; these are delivery requirements, not a request for experiments in this research turn:

1. **Named capability contract:** supported observations/comparisons, explicit effects, typed refusal/strength, lifetime/invalidation, limits and supported environments; no implicit immutable-content/current-mm/settlement promise.
2. **One maintained implementation plus independent real reference adapters:** selected donors reconciled with relevant WIP, dependencies and notices; two materially different standalone clients exercise the same public mechanism through packaged artifacts. Existing p11scope/OSSLscope migrations are later MG work with their own policy and live attachment gates. This gate was updated for the user's subsequent migration-later scope; it does not treat mock wrappers as independent clients.
3. **Tests shipped with the behavior:** every advertised branch has a scenario/oracle, including the relevant H04/H05/H06/H19 negatives, resource exhaustion, denied access, stale context and no-new-mapping paths. Supply real fixtures/setup recipes and applicable artifact/compiler cases where the capability actually depends on BPF.
4. **User-run path proven from the distributed package:** a clean downstream consumer invokes the suite against its own adapter/version/features; tests/docs/fixtures survive packaging; any diagnostic states exactly which library/artifact it tested. No private workspace, hidden fixtures or maintainer-only harness dependency.
5. **Maintained declared cells pass:** supported filesystem/view/backend cells have exact-version results, independent positives/negatives, expected refusal and cleanup checks. Required missing cells block that support claim. User diagnostics supplement these results and cannot waive them.
6. **Ownership and interference qualification:** retain original FDs through detach or unresolved quarantine; bound/identify workers and mappings; test cancellation and failed cleanup; verify the advertised coexistence/operational restrictions. A successful local calibration cannot upgrade the product's collection or shutdown guarantee.
7. **Version and change discipline:** package/API/test-protocol/support-profile changes trigger their affected cells; regression expectations cannot silently drift. Preserve small case definitions, minimized fixtures and concise results, not a new permanent evidence archive.

The previous A1–A5 resolutions remain valid for the narrow pilot. The owner's expanded requirement adds a mandatory user-facing conformance and mapped-image readiness layer. Incorporate that layer into README milestones, TODO dependencies and testing delivery gates before treating the proposal as complete.

## Final adversarial integration review, 2026-10-17

Bounded reread of user-conformance, gap-analysis, distribution options and integrated README/TODO/testing strategy. All 23 G entries, 14 UC entries and eight U delivery items are present. The owner's requirement is now operationalized in the proposal: phase 1a is an internal pilot, phase 1b requires production mapping behavior and user delivery, L04 is mandatory for ready mapping support, and S02 cannot postpone the operator route until the SDK. Required claims are selected before environment discovery; custom/installed artifact binding, independent fixture truth, source-free use and real supported filesystem cells have concrete gates. No new broad census, product changes or runtime actions were performed.

Four focused corrections remain before calling the integrated research ready for user review:

1. **Scope G12 dependencies to the evidence domain.** U01 requires G12, while G12 currently names B03/B04/B10, pulling the BPF/compiler support matrix into a host-only mapping design. Use L02 plus the selected file/mount evidence contract for mapping; add B03/B04/B10 only for BPF capabilities. The mapping requirement should not accidentally undo the independent-crate boundary. This affects both gap-analysis's action index/section and TODO G12.
2. **Separate fresh post-detach firing from previously admitted/buffered observations in UC12.** Its current “no further observations” wording can reject legitimate late delivery or imply universal quiescence from detach. Use fresh, independently identified post-detach operations to check absence of new probe admissions; retain pre-detach events and in-flight completions under the selected drain/closure protocol. Link-release, admission closure and complete collection remain different claims. The existing delayed-hit countermodel still applies.
3. **Make G18's backend trust claim achievable.** Safe untrusted trait implementations must not cause memory unsafety; their extents, transitions and metadata structure can be checked. The library cannot detect every internally coherent false identity supplied by a backend. Preserve backend-asserted provenance, reject contradictions, and reserve stronger independent kernel evidence for the trusted/validated path. Replace the blanket “hostile safe backend cannot ... [create] strong fabricated evidence” acceptance with that precise boundary in the G index, G18 prose and TODO. Otherwise an impossible truth-verification test becomes a release gate.
4. **Choose one operator-delivery rule consistently.** User-conformance's second surface mandates a standalone executable; README, U04 and distribution options allow a standalone executable **or** an adopting application's command. Both can meet the request if they provide the installed, compiler-free case/fixture closure and exact implementation binding. State the permitted alternatives in user-conformance; a generic library user must have an independently installable route, without needing a private product checkout. Do not require a duplicate standalone binary when an independently distributable product command satisfies those same obligations.

One proportionality adjustment is advisable: the user-conformance cleanup section mandates a durable per-run ledger before every worker handoff. Ordinary process-local held-file tests can use owned in-memory custody plus a bounded run marker/result; durable reconciliation records belong to profiles creating resources that outlive the runner or explicitly promising crash recovery. Preserve identity-checked cleanup and unresolved outcomes, but do not turn every basic file test into a transactional recovery system or permanent archive. A text ledger never recreates a lost live pidfd/FD capability.

The G/UC scope is otherwise substantive and appropriately conditional: G04 does not promise interruptible syscalls, G05 does not promise recoverable universal OOM, async/fork/coexistence gates apply only to advertised features, and UC refusal success is separate from operational support. No additional missing scope requiring a new inventory was found in this bounded review. With the four corrections, the research is ready for user review as a proposal; none of these documents establishes implementation readiness or a passing support cell.

### Resolved integration verdict

Rechecked the revised G11/G12 prerequisites, G18 trust boundary, UC12 detach evidence, installed operator alternatives and cleanup ledger scope: all four final findings and the proportionality adjustment are resolved in the proposal. The research is ready for user review, with required user-run delivery preserved and standalone-binary choice kept separate; this verdict establishes neither implementation readiness nor passing runtime qualification. The subsequent actionable testing workflow is separate work and was not reviewed here.
