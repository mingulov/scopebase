# S-loop owner call — decision record

Date: 2026-11-02. Author: session controller, owner decision in-session.

## What was lost

External review round 9 produced findings S143–S159 (17 findings:
9 Critical / 6 Important / 2 Minor) against the pre-merge integration tree.
The finding texts lived only in `/tmp/sdd-round7/codex-r9-final.md` plus a
home-directory backup; both were lost in the 10-30 host transfer. Loss
verified twice: 2026-11-01 (gap audit cites the ID range and counts only;
r10 lane holds passing mentions; donor snapshots cannot contain the file)
and 2026-11-02 (`/tmp/sdd-round7` absent, no `codex-r9*` in `/tmp`, no
home backup). The S143–S159 texts are unrecoverable; regeneration means a
fresh review of the current tree, not a reproduction of the lost texts.

## Options put to the owner (2026-11-02)

- (a) Defer with a record entry (R-stream re-reviewed the fixture surface
  fresh; external R2 READY, zero findings).
- (b) Full regeneration via a fresh review of the entire merged tree.
- (c) Scoped regeneration of non-fixture surfaces only.

## Answer

**(c) Scoped regeneration.** The owner selected scoped regeneration
(in-session structured answer, 2026-11-02).

## Frozen scope for the regeneration review

IN SCOPE (fresh review; internal rounds first, then external
`gpt-6.1-sol medium`, per-finding TDD fixes, new finding IDs from S160):

- `crates/scopebase-linux`, `crates/scopebase-capture`,
  `crates/scopebase-bpf`, `crates/scopebase-sdk`,
  `crates/scopebase-conformance` (product code and their tests).
- `crates/scopebase-testkit` EXCEPT the R-stream surface below.
- `consumers/*` reference clients.

OUT OF SCOPE (already re-reviewed fresh 2026-11-01, external R2 READY,
zero findings — not re-done):

- `crates/scopebase-testkit/src/fixture/linux/` (+ `fixture.rs`,
  `fixture/tests.rs` legs owned by R-stream).
- `crates/scopebase-testkit/src/bin/scopebase-pair-publisher.rs`.
- `crates/scopebase-testkit/tests/toolchain_invoke.rs`.
- Dev tooling and planning docs (`tools/`, `tests/`, `docs/`,
  `orchestration/`) — not product surfaces.

## Gate effect

Gap-audit S2 is re-decided: the lost S143–S159 range is superseded by
this regeneration (new S160+ findings adjudicated PASS/REFUTED/DEFERRED
each). No aggregate-green claim until the regeneration review closes at
zero findings AND the integration evidence audit closes.
