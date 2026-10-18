# Insertion identity and loss despite full tables

CP04 delivers a host fold, bounded test-only producer models, a strict literal
corpus/control route and two finite API consumers. Its [exact contract](../../superpowers/specs/2026-10-18-scopebase-cp04-insertion.md)
and [selected-port map](../../provenance/ports/CP04-preservation-20261018.md)
retain the original defect populations. Candidate implementation is separate
from independent review/acceptance and from live support.

A per-CPU hash insertion can initialize the winning lane while secondary lanes
start at zero. Later hits may migrate and change thread/display metadata without
observing fresh identity. Inferring an owner from nonzero uid/stack, selecting
the latest lane or allowing a losing insertion to mark its lane fabricates
identity. Numeric uid0 and stack0 are genuine values. The generic host contract
counts markers first, refusing missing or multiple owners even with identical
payloads, before inspecting counts. It then checked-adds every lane in original
order. An earlier exact overflow takes precedence over a later explicit
saturation. Only successful validation invokes the owner's Clone, exactly once;
no Eq calls or refusal-path Clone calls occur. Generic exact MAX remains valid;
a raw donor MAX is explicitly nonexact and must be adapted to `saturated`.

The original full-map defect stored a diagnostic lazily in the identity gate.
When all256 slots were occupied, marker insertion also failed, and absent-as-zero
hid attribution loss despite exact aggregate activity. The delivered model
preallocates independent CPU/slot diagnostics before filling its bounded gate
and attribution table. Small capacity1/five-attempt tests independently expect
failed IDs2–5, exact aggregate5 and signal4; capacity5 is the healthy-zero twin.
Historical tests retain gate256, attribution2048, one additional refused key,
exact aggregate2049 and signal1, plus below-capacity128. Existing-key hits at
capacity, rejected-insert atomicity, preexisting254→255 and independent CPU/slot
routing have separate assertions. The signal remains a capped diagnostic, with
no conversion into exact omitted events or public completeness policy.

The semantic lazy-loss control actually attempts marker insertion into the full
gate and reads an absent marker as zero, while leaving aggregate totals intact.
Both small and historical tests must fail their loss-presence assertions; their
restored independent-storage twins and below-capacity populations must pass.
Other mutations cover marker selection, equal-owner deduplication, zero identity,
losing marks, hit refresh, dropped secondary counts, arithmetic/saturation order,
eager Clone and output redaction. The redaction mutant deliberately emits the
fixed secret carried by an independent test identity: it establishes output
redaction sensitivity, not arbitrary generic payload extraction. The unwanted
I:Debug bound has separate compile-refusal evidence, never a semantic-kill label.

All mechanisms here are T0/T1 host/scripted evidence. No real kernel insertion,
NOEXIST race, migration, final-object writer partition/reentry, raw numeric marker2,
88-byte ABI/stride, native attachment or live map is qualified. BP02 owns every
actual decoder/stride consumer and raw-saturation mapping; BP07 owns producer
storage/failure sites, independently active live workloads and writer/reentry
proofs. CP05 owns nonjoinable unknown/generation histories; CP06 persistent and
exactly-once loss; CP10 strict future replay including explicit saturation;
CP11 real application reducers; CP13/TT installed exact-consumer conformance.
MG03 duplicate retirement requires actual version/features adoption and the
original producer/ABI/product regressions. No donor duplicate is removed here.
