# S-loop regeneration close-out report — 2026-11-02

## Lineage and scope

External round 9 findings S143–S159 (9 Critical / 6 Important / 2 Minor)
were lost in the 10-30 host transfer (both copies gone; loss verified
twice). The owner answered the S-call 2026-11-02 with **(c) scoped
regeneration**: a fresh review of non-fixture surfaces with new IDs from
S160 — not a reproduction of the lost texts. Decision record:
[2026-11-02-s-loop-call.md](2026-11-02-s-loop-call.md), ledger amendment 49.

Frozen scope (from the S-call record), all over parent commit `c87cdf9`:

- IN: `crates/scopebase-linux`, `scopebase-capture`, `scopebase-bpf`,
  `scopebase-sdk`, `scopebase-conformance` (code + tests);
  `crates/scopebase-testkit` except the R-stream surface;
  `consumers/*` reference clients.
- OUT (already re-reviewed fresh 2026-11-01, external R2 READY): the
  R-stream fixture surface (C7/C8/R-set).

This report closes the regeneration loop. Verdict scale: PASS = fix
landed, its regression fails-before/passes-after, suite green;
REFUTED = evidence-backed counterproof; DEFERRED = owner-called only
(none in this loop).

## Internal review (11/11 surfaces, 405/405 files)

Fresh internal review covered every in-scope file and filed **70
findings, S160–S229: 0 Critical, 20 Important, 50 Minor**. Catalog:
`.scopebase/s-regen-20261102/merged.md` (per-surface texts beside it).
No cross-surface duplicates; within-surface near-twins kept (distinct
file:line each).

| Scope | File | Read | Findings |
|---|---|---|---|
| bpf-src | bpf-src.md | 33/33 | S160–S163 Important, S180–S183 Minor |
| bpf-tests | bpf-tests.md | 60/60 | S164–S168 Important, S184–S188 Minor |
| capture-src | capture-src.md | 18/18 | S169 Important, S189–S193 Minor |
| capture-tests | capture-tests.md | 63/63 | S170–S171 Important, S194–S195 Minor |
| conformance | conformance.md | 11/11 | S196–S201 Minor |
| consumers | consumers.md | 24/24 | S172–S174 Important, S202–S205 Minor |
| linux-src | linux-src.md | 25/25 | S206–S209 Minor |
| linux-tests | linux-tests.md | 63/63 | S175 Important, S210–S211 Minor |
| sdk | sdk.md | 17/17 | S176 Important, S212–S218 Minor |
| testkit-src | testkit-src.md | 41/41 | S177–S178 Important, S219–S224 Minor |
| testkit-tests | testkit-tests.md | 50/50 | S179 Important, S225–S229 Minor |

## Verification lane (minors, pre-fix)

`verify-*.md` adjudicated all 50 minors against the pre-fix tree:
**49 CONFIRMED, 1 REFUTED (S219)**. The 20 Importants went directly
finding → TDD fix → external review (no separate verify file).

- S219 REFUTED: `RawRequest::decode` rejects `record_index == 0`
  (`fixture/linux/wire.rs:479`) before the worker's `as usize - 1`
  (`scopebase-tt03-worker.rs:1098`) is reached — the debug-panic
  trigger is unreachable. Recorded in `verify-testkit.md`;
  **externally confirmed** (batch2 R1: "REFUTATION CONFIRMED").
- S166 REFUTED (rationale re-derived at report time; none was on
  disk): the fork child in `retirement.rs:1416-1438` does call
  `retire()`/`reconcile()`, but `retire()` (`attach/retire.rs:187`)
  takes the `Option` flag and hits `check_process` first, which is
  `getpid` + integer compare returning a struct-only `Changed` error
  (`attach/pool.rs:344-350`, `error.rs:74-80` — no allocation, no
  lock); the child never reaches `retire_entry`. `reconcile()`
  (`attach/pool.rs:265`) likewise returns a zero report on the
  `check_process` gate before the allocating `Vec` at `:274`
  (`usage()` at `:239` is read-only integer accumulation). The
  deadlock trigger cannot materialize; the SAFETY comment's claim
  holds. No code change.

## Per-finding verdicts

Batch 1 = S160–S211 (external R1–R5, READY at R5).
Batch 2 = S212–S229 (external R1–R2, READY at R2).
"Fix" cites the landed change (uncommitted over `c87cdf9`, inventoried
below); "Trail" cites the external confirmation (B1R1..B1R5, B2R1..B2R2
= finals in `.scopebase/external-reviews/sregen-batch{1,2}-20261102/`).

### Important (S160–S179) — 18 PASS, 2 REFUTED

| ID | Finding | Verdict | Fix evidence | Trail |
|---|---|---|---|---|
| S160 | BTF preflight refuses valid FUNC_EXTERN (vlen=2) | PASS | `btf/adapt.rs`: `12 =>` arm allows vlen<=2, `14 =>` requires vlen==0; vectors regen | B1R1 spot-check (linkage 0/1/2 accept, VAR nonzero vlen rejects) |
| S161 | Aya `is_return` hardcoded false | PASS | `adapters/aya.rs`: `uprobe_is_return` via public `ProbeKind` | B1R5 READY, no new findings |
| S162 | AbortAndRollback walks the sibling | PASS | `attach/`: voted-gated fail-fast; assert exactly 2 native attempts + order | B1R1 spot-check |
| S163 | Anonymous-member recursion unbounded | PASS | `btf/query.rs`: depth ceiling 256 | B1R5 READY |
| S164 | who_map_reader panics on wrong-size lane file | PASS | `examples/who_map_reader.rs`: explicit length guard + typed error | B1R5 READY |
| S165 | who-reader consumer slice panic twin | PASS | `tests/consumers/who-reader/src/main.rs`: same guard | B1R5 READY |
| S166 | fork child post-fork retire/reconcile | REFUTED | none — see rationale above | covered by B1R5 READY (no new findings) |
| S167 | ring sweep swallows errors, self-compares | PASS | `tests/ring.rs`: ok/err counts both nonzero + fixed seed-vector | B1R5 READY |
| S168 | TC06 seam leg never calls TC06 | PASS | `tests/aya_adapter.rs`: real TC06 entry on truncated probe + valid control | B1R5 READY |
| S169 | HolderPair::agree value-half has no oracle | PASS | `capture holder.rs` tests: same-revision divergence disagrees | B1R5 READY |
| S170 | nine pre-CP05 UI fixtures never executed | PASS | new `tests/ui_sealed_units.rs` harness (pass builds, fail fails); +R1–R4 follow-ups: subject binding (X2→Y2→Z2), package include (X3), strict fingerprint (CONSIDER→Y5) | B1R1 findings 2,3; B1R2 X2; B1R3 Y2; B1R4 Z2 FIXED; B1R5 READY |
| S171 | tautological test-local scalar asserts | PASS | `cp06_donor_subsets.rs`: donor-echo surgery (vacuous lines removed/threads) | B1R5 READY |
| S172 | heldfile parse_script accepts extra/dup params | PASS | `linux-heldfile-reference/adapter.rs`: exact param-multiset allowlist | B1R5 READY |
| S173 | observe parse_script accepts extra/dup params | PASS | `linux-observe-reference/adapter.rs`: same allowlist | B1R5 READY |
| S174 | kryprobe unknown-identity scenario vacuous | PASS | kryprobe adapter scenario deleted/rewired to real capture API | B1R5 READY |
| S175 | tautological exited-child birth assert | PASS | `process_observation.rs`: contract assert (`sampled_birth().is_none()`) | B1R5 READY |
| S176 | dependency-purity oracle skips build edges | PASS | `sdk tests/dependencies.rs`: scan over normal+build edges + synthetic negative | B1R5 READY |
| S177 | hex decode Value-per-byte amplification | PASS | `testkit artifact.rs` `decode_byte` bypass + scalar pre-check; new `tests/script_scalar_bounds.rs` peak-heap regression | B1R5 READY |
| S178 | atomic decoder LE-only nibbles, wrong on BE | PASS | `object/inspect.rs`: BE nibble normalize | B1R5 READY |
| S179 | call-graph test discards graphs | PASS | `tests/object_graph.rs`: shape asserts (conforms, non-empty fns, names, BE leg) | B1R5 READY |

### Minor (S180–S229) — 49 PASS, 1 REFUTED

| ID | Finding | Verdict | Fix evidence | Trail |
|---|---|---|---|---|
| S180 | terminal attach errors skip classify | PASS | `attach/`: terminal consult-once + stacked-range refusal; `adjudicate_split_verbose` + doc | B1R1 spot-check (one policy call, one native attempt); X6 doc fix at B1R2 |
| S181 | map_types ~4x budget via nested budgets | PASS | `btf/query.rs` + `btf/domain.rs`: shared per-call budget via `*_inner` + doc | B1R1 spot-check (budget-16 parse then LimitExceeded) |
| S182 | copy_into clears slot before bump | PASS | `ring/stage.rs`: bump-before-copy + unit test | B1R5 READY |
| S183 | Aya binding converts held FD to /proc path | PASS | `/proc/self/fd` helper with documented /proc dependency | B1R5 READY |
| S184 | FakeBackend charge assert self-fulfilling | PASS | `Cell`-counted charge inside `custody_charge` | B1R5 READY |
| S185 | aggregate_fixture unchecked arithmetic | PASS | checked multiplies + hoisted walk check; `usize::MAX` typed-error case | B1R5 READY |
| S186 | SimMap NOEXIST re-insert models success | PASS | existing-key branch refuses; twin-insert test | B1R5 READY |
| S187 | predictable temp files, no drop-guard | PASS | `create_new` seams + retirement drop-guard; pre-created-target refusal test | B1R5 READY |
| S188 | native_fixture sysfs unwrap | PASS | pure parser core returning `Result`; `BLOCKED_ENVIRONMENT` call sites; malformed-string units | B1R5 READY |
| S189 | unknown-kind error reports record-0 offset | PASS | `replay.rs`: enumerate, `at(index)`; second-record offset assert | B1R1 spot-check |
| S190 | serde offsets overshoot one column | PASS | `column.saturating_sub(1)`; `b"x"` → offset 0 | B1R5 READY |
| S191 | panicking Drop poisons holder | PASS | `checked_replace`: install value+metadata before displaced payload drops | B1R1 highlighted Sound |
| S192 | scanner recursion exhausts stack | PASS | pre-scan depth clamp 256 | B1R1 highlighted Sound (clamp-vs-serde parity) |
| S193 | two-member policy/magnitude refuse differently | PASS | unified two-member UnknownMember | B1R5 READY |
| S194 | m_s03 proves determinism, not equivalence | PASS | renamed determinism+content test (empty reasons + post-loss twin) | B1R5 READY |
| S195 | closure test drops ClosureGap reasons | PASS | fixture gaps as `[predicate, gap]` pairs; full-pair compare | B1R1 spot-check |
| S196 | staging-plan gaps die post-commit as Engine | PASS | preflight guards: slash-ids, reserved `contract`/`bundle`, untemplated files; BrokenPackage + no run dir | B1R1 highlighted Sound (C mirror) |
| S197 | plan hides manifest-schema failures | PASS | shared `check_manifest_doc` + plan attribution | B1R5 READY |
| S198 | refused cleanup strands manifest-less dir | PASS | manifest restore on post-clear refuse + follow-ups (X1→Y1→Z1 survivor identity pin; ENOENT unlink removal; thread-local hooks at R5) | B1R1 finding 1; B1R2 X1; B1R3 Y1; B1R4 Z1/Z3; B1R5 READY |
| S199 | fresh-dir proof getuid + umask-fragile | PASS | geteuid + repair; follow-ups: O_PATH acquisition (X4), unsafe-chmod removal → safe EACCES rollback (Y3) | B1R1 finding 4; B1R2 X4; B1R3 Y3 FIXED |
| S200 | read_member_at refuses in-root `..` | PASS | gate-level `..` refusal with honest messages | B1R1 highlighted Sound (vs S82) |
| S201 | refusal tests pin receipt-absence, not no-run-dir | PASS | `!run.exists()` asserts in all 5 refusal tests | B1R5 READY |
| S202 | memveil scenarios index snapshot[0] unchecked | PASS | checked `first_row` projection → contract error + unit test | B1R5 READY |
| S203 | kryprobe binary panics on dead stdout | PASS | fallible main (`put_line`/`err_line`, exit 1/2) + /dev/full test | B1R5 READY |
| S204 | memveil binary panics on dead stdout | PASS | same as S203 | B1R5 READY |
| S205 | ossl binary panics on dead stdout | PASS | same as S203 | B1R5 READY |
| S206 | Walk Debug impls emit unbounded paths | PASS | path-omitting bounded `Debug` for walk types + canary test | B1R5 READY |
| S207 | subdir strands dir on post-mkdir open failure | PASS | guard-before-open both sites + thread-local fault hook | B1R1 highlighted Sound + spot-check (EMFILE) |
| S208 | clone_error invents errno 0 | PASS | errno-less source clones to no errno + test | B1R5 READY |
| S209 | test-only BorrowedFd on invalid fd | PASS | raw-fd probe replacing invalid `BorrowedFd` | B1R5 READY |
| S210 | loud-skip claim hidden by capture | PASS | docstring corrected + `EXAMPLE_BOUNDARY_STRICT` + CI export (`ci_local.sh`) | B1R5 READY |
| S211 | unwrap() in Drop impls | PASS | `let _ = ...` both guards + regression test (+R2–R4 follow-ups: root-capability dual path → scratch probes, Z4) | B1R1 finding 5; B1R2 X5; B1R3 Y4; B1R4 Z4 FIXED |
| S212 | wait_for_exit overflow timeout returns Timeout | PASS | saturating never-expiring deadline + still-blocked test | B2R1 fix-verdicts Sound |
| S213 | shutdown kill-race misreports Killed | PASS | `Killed` requires delivered signal AND signal death; ESRCH→Exited | B2R1 fix-verdicts Sound |
| S214 | capture cost ignores loss/signal lanes | PASS | cost lanes 16/8/4/4 charged, checked arithmetic; N/N+1 maxima fixture | B2R1 spot-check |
| S215 | FileObservation redacting Debug unpinned | PASS | `bytes_len`-present/pattern-absent pin | B2R1 fix-verdicts Sound |
| S216 | error-rendering omits CaptureAlreadyPresent | PASS | table row + exact-sentence assert (self-review follow-up) | B2R1 spot-check |
| S217 | diagnostic u64::MAX budget panics on 32-bit | PASS | `usize::MAX as u64` + width-parameterized limits test | B2R1 fix-verdicts Sound |
| S218 | Spawn/ReapFailed/read-zero paths untested | PASS | nonexistent-binary Spawn test; zero-shape InvalidLimits incl. 2 self-review shapes; read-zero regression (+R1→R2: unscoped worker ownership fix) | B2R1 finding 1; B2R2 FIXED |
| S219 | record_index 0 underflow | REFUTED | none — decode rejects 0 first (see above) | B2R1 "REFUTATION CONFIRMED" |
| S220 | blob assembly grows past total | PASS | `apply_chunk_data` pre-append overrun refusal (self-review: was extend-then-check); no-growth + recovery tests | B2R1 Sound + spot-check |
| S221 | driver flag lookup scans subject argv | PASS | dash-first flag scan both drivers + exit-2 tests | B2R1 Sound + spot-check |
| S222 | oracle cap counts duplicates | PASS | distinct-key guard both oracle loops + shared-cell test | B2R1 Sound + spot-check |
| S223 | peak_bytes consistency unenforced | PASS | bytes-peak independent-channel exclusion documented + pinned | B2R1 "acceptable explicit contract choice" |
| S224 | hash-before-use TOCTOU on tool binary | PASS | tool-dir-immutable trust assumption documented + corrupt-after-pin refusal test (+R1→R2: pre_exec wording fix) | B2R1 residual + note 3; B2R2 FIXED |
| S225 | fork child can panic after fork | PASS | bool-returning EINTR-retried child helpers; EOF-exits-13 regression | B2R1 Sound + spot-check |
| S226 | f_seccomp_unit_shapes cannot fail | PASS | exact `Debug` rendering assert | B2R1 Sound |
| S227 | contains_slice panics on empty needle | PASS | non-empty guard + should_panic | B2R1 Sound + spot-check |
| S228 | object/dir helpers index untrusted bytes | PASS | `elf_field`/`object_names` context accessors, all four suites (+R1→R2: checked narrowing of 5 conversions) | B2R1 Sound + CONSIDER 4; B2R2 FIXED |
| S229 | temp-dir helpers weaker than R32 pattern | PASS | exclusive `create_dir` + nonce + symlink canary in all three files | B2R1 "complete" + spot-check |

## Fix discipline and gates

- Per-finding TDD: every fix observed RED first, most with a
  caught-mutant proof (recorded in the batch prompts; external
  spot-checked 7 RED/mutant mechanisms in B1R1, 6 more in B1R2, 5 in
  B1R3, 5 in B1R4, 9 in B2R1 — all discriminating for the right
  reason).
- Self-review gates: batch 1 full-production-diff self-review — zero
  findings. Batch 2 self-review found 3 (S220 refusal-must-not-append
  pre-check, S218 two missing zero shapes, S216 exact sentence) —
  all fixed, targeted re-review zero findings.
- Tool gates after the change (recorded pre-report; re-verified at
  close — see Close verification): planning checker PASS, ledger
  AGREE (51/86), traceability VALID, orchestration 129/129, planning
  tools 132/132, package-policy 65/65, clippy zero on regen lines,
  `git diff --check` clean. Batches ran green per-crate
  (bpf/capture/conformance/linux/sdk/testkit suites + all six
  consumers).

## External review trail (Codex `gpt-6.1-sol` medium, resumed lane)

Batch 1 (S160–S211), five rounds to READY:

- R1 NOT READY: 5 SHOULD-FIX (X1 S198 restore soundness, X2 S170
  subject binding, X3 S170 package include, X4 S199 umask repair,
  X5 S211 unchanged) + 1 NOTE (X6 terminal-error doc).
- R2 NOT READY: X3/X5-cleanup/X6 fixed; X1/X2/X4 partial (→Y1/Y2,
  Y3 fixed); new: root-capability test defects (Y4), fingerprint
  strictness (Y5 CONSIDER→fixed).
- R3 NOT READY: Y3/Y5 fixed; Y1/Y2 partial (→Z1 inode-pin lifetime,
  Z2 relative dep-info origin, Z3 ENOENT unlink); Y4 fixed for
  ordinary root; Z4/Z5 fixed.
- R4 NOT READY: Z1/Z2/Z4/Z5 fixed; Z3 production fixed but new
  process-global hook test-isolation finding.
- R5 READY: thread-local hooks; zero new findings.

Batch 2 (S212–S229), two rounds to READY:

- R1 NOT READY: 2 SHOULD-FIX (S218 timeout-join hang, non-UTF8
  fixture leaks) + 1 NOTE (S224 `pre_exec` wording) + 1 CONSIDER
  (S228 narrowing conversions); per-fix verdicts Sound/complete,
  S219 refutation confirmed.
- R2 READY: all four fixed; zero new findings.

Standing external caveat (every final): inspection was read-only;
reported suite runs and historical RED/mutant executions were not
independently rerun. `git diff --check` passed at every round.

## Change inventory (uncommitted over `c87cdf9`)

92 modified files + 3 new files (`tests/ui_sealed_units.rs`,
`tests/script_scalar_bounds.rs`, `tests/fixtures/tc06-live.o`),
~+4964/−619 lines, spanning all six crates plus five reference
consumers and `tools/qualification/ci_local.sh` (S210 CI export).
Full stat: `git diff --stat` at report time. No requirement, task, or
obligation count changes (120/86/179).

## Disclosed residuals (accepted by external review)

- Z2 subject binding is a conservative embedded-string heuristic
  (default-profile, accidental-cache-reuse boundary) — not general
  binary provenance validation.
- S198 non-regular eviction window: possible loss of replacement
  evidence during name-based deletion; no follow/chmod/truncate of
  external targets.
- S224: pathname-execution trust boundary documented (tool-dir
  immutable); fd-bound exec not implemented.
- S223: bytes-peak independent-channel exclusion is an explicit
  documented contract choice, not a proven sampling model.
- S192/S163 clamps (256) are hard ceilings independent of caller
  limits by design.

## Close verification (2026-11-02, this session)

Fresh full runs over the uncommitted close-out tree (lease-wrapped,
`--locked --offline`, target dir outside the worktree):

- `cargo test --workspace -- --test-threads=4`: 85 targets,
  **1222 passed / 0 failed / 15 ignored** (log
  `/tmp/sregen-closeout/workspace-test.log`, scratch — rerun to
  reproduce).
- Default-parallelism run flaked once on
  `template_override_admits_bounded_inputs` (15s budget vs ~15–19s
  runtime under load). Root-caused per systematic debugging: the
  same flake is documented in the batch-1 R2 prompt (fails
  identically with regen tests skipped; passes solo and 83/83 at 4
  threads) — pre-existing load sensitivity, not the diff. No code
  change.
- Clippy `--all-targets`: zero hits on regen lines (machine
  cross-check of all 170 warning locations against the diff hunks).
  Two close-out lint fixes on regen-added lines, both
  behavior-neutral, suites re-green: `mut budget` → `budget`
  (`btf/query.rs` S181 helper); nibble-swap expression →
  `rotate_left(4)` (`object/inspect.rs` S178; S178 BE tests pin
  equivalence). Remaining workspace hits pre-exist, including the
  deny-by-default `3..2` test input (`attach.rs:264`, since
  BP04/BP06) and the `view.rs` helper arity.
- Python/doc gates: planning checker PASS, ledger AGREE (51/86),
  traceability VALID, orchestration 129/129, planning tools
  132/132, package-policy 65/65, `git diff --check` clean.

## Loop verdict

**S-regen CLOSED 2026-11-02: 68 PASS, 2 REFUTED (S166, S219),
0 DEFERRED, 0 open.** Both batches externally READY with zero new
findings at the terminal rounds. The lost S143–S159 range is
superseded by this fresh S160+ review per the owner's scoped-
regeneration call. Next: integration evidence audit verdicts
(full-tier vs alpha-tier per accepted task); no aggregate-green
claim until that audit closes.
