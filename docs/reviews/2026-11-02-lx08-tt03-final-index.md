# LX08 × TT03 final-index joint compatibility record — 2026-11-02

Root-owned record binding the independently finalized TT03 and LX08
design indexes and resolving per-case adapter/protocol compatibility
before execution. Required by the LX08 contract §"TT03 observed-primary
and final-protocol boundary" and TT03 packet §10 ("root owns the
future joint record"); gates LX08 dispatch.

## Bound indexes (hashes re-verified 2026-11-02)

| Index | Path (repo-relative, private custody) | SHA256 |
|---|---|---|
| TT03 final r2 | `.scopebase/controller/resume-20261022/next-tt03-packet/r2/artifact-index.json` | `1105d700199c7ec4a512f2d122495728eaa042ef0006ca3a8e0752534b5bf194` |
| LX08 exact reviewed r2 | `.scopebase/controller/resume-20261022/lx08-crossreview-r1/contract-draft-r2/artifact-index.json` | `b2947891d9750c4b522cec8302875467b3a657eb137528161f1ad62a02f0e839` |

LX08 r2 observed only three frozen TT03 *proposal* documents (all
hashes re-verified 2026-11-02):

| Observed primary | SHA256 (observed) | Final SHA256 | Changed |
|---|---|---|---|
| `inputs/tt03-primary-r2/packet.md` | `0daf15f0…22bf` | (packet, +21 lines) | yes |
| `inputs/tt03-primary-r2/protocol.md` | `e70e2e1a…53712` | `475f603d…c9cbe6` | yes |
| `inputs/tt03-primary-r2/contract-data.json` | `fdc3bd9d…b0dd` | (3 deep-diff items) | yes |

(Full hashes: packet `0daf15f0794e2bd6c52d0e66391d5d84cb4a2755e636fae773766f7cd2f422bf`,
protocol `e70e2e1ae655665074bc636e1958d76f75ddd508fe46bb77df9e3378a3253712`,
contract-data `fdc3bd9df3f9e31289887c30d5c6e7d4f20a84ec6b7c5f8c949d63800350b0dd`;
final protocol `475f603d98cc8595153d10df4e61eef8a9a0a8805e7626b3378a271c7dc9cbe6`.)

## Observed → final deltas (complete enumeration)

D1. **packet.md +21 lines** — new §"Admission assets and the
no-Prepare boundary": constructor-supplied root/image Files are
owned admission assets (not per-invocation effects); run
retirement may omit BOTH fixture calls if Prepare never entered
(export must record the omission); the no-Prepare outer
finalization route is **C4 NEEDS_DECISION / UNBOUND**.
D2. **protocol.md Advance mapping** — fixed heartbeat/exec rules:
blob_mask 3/4/0 per request kind; B heartbeat `capture_raw`s;
parent-only steps carry no A request; exec replies carry
epoch+1/new pid/tid (failed exec keeps epoch + bit2); exact phase-
flag mapping; contiguous per-producer record index with exec
handover.
D3. **inventory canary literal** — `…4552452d43414e…`
("FIXTURE-CANARY1") → `…45524543414e…` ("FIXTURECANARY1"); one
byte (`0x2d`) removed, in protocol.md and
`contract-data.json:/inventory_canary_hex`.
D4. **partial_file_write premise strengthened** — bytes 0 AND 1
must each differ (`differing_byte_offsets: [0, 1]` added);
parent readback must equal `mutation[0] + originalA[1..]`;
short/zero/error native writes stay incomplete.

## Per-case compatibility rulings

LX08 r2's TT03-facing assumptions (per the TT03 fixture spec §R3
and the LX08 contract): original creator pidfd + authenticated
active-PID namespace, PID1/nested-PID1 inherited-epoch refusal,
fresh-child Own success, and a private actual-reader cfg(test)
EOF barrier. LX08 consumes TT03 *populations* (scenarios/rows via
prepared sessions); no provider trait exists on either side, and
LX08 speaks no TT03 wire directly. Verified 2026-11-02: the LX08
contract pins no canary literal, no Advance/blob/epoch wire
detail, and no death-premise internals.

- **D1 → COMPATIBLE.** LX08's consumption path uses prepared
  sessions; the no-Prepare omission route is outside it. Carried
  (not blocking): if any future LX08 consumer path omits Prepare,
  the C4 outer-finalization route must be bound first.
- **D2 → COMPATIBLE.** Wire tightening is implemented inside the
  TT03 worker/driver pair, which ship together (F-row closure
  increment, in-tree). No population semantics LX08 observes
  changed (exec A→B→A images/PID/birth, sibling phases,
  descriptor-inventory shapes).
- **D3 → COMPATIBLE.** The canary is internal to TT03's
  descriptor-inventory oracle (digest-compared inside TT03);
  LX08 observes inventory outcomes, never the literal.
- **D4 → COMPATIBLE.** Premise strictness is inside TT03's
  worker-death control; the observable LX08 could consume (typed
  `WorkerDeath` + retained evidence kinds) is unchanged.

## No-cycle statement

The TT03 final index pre-allocates
`joint_compatibility_record: "UNBOUND; root binds independently
finalized TT03/LX08 indexes separately"` with
`counterpart_final_index_consumed: false`; the LX08 r2 index
carries no joint/counterpart keys. Neither index references this
record or the other index (0 cross-references verified
2026-11-02). This record references both indexes by hash only.

## Dispatch gate resolution

Final-index joint compatibility is **BOUND** by this record. LX08
dispatch is unblocked on this gate. Explicitly NOT bound here
(owned by their tasks): the C4 no-Prepare outer-finalization
route; any admitted adapter realm; LX08 adapter/epoch/view-tracker
semantics (needed by the open seccomp/nested F-rows); the
operation-audit consumer; TT03's 152 NOT_RUN DAG delivery rows.
This record binds designs; TT03's implemented increment state is
recorded separately in the [TT03 packet](../provenance/tt03-packet-20261023.md).
