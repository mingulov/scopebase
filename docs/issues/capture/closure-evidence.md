# Closure evidence without runtime authority

CP09 is NEW T1 model-only code: a versioned predicate DAG
(`ClosureProfile`), bounded same-context observations with explicit
invalidation (`ClosureRecord`), and a three-set assessment
(`assess_closure`). There is deliberately no `is_complete()`, no live
fence constructor, no sleep/poll/detach, and no universal session
state. Concept references are MemVeil `src/memveil/capture/stop.mojo`
(distinct admission-close, quiescence, bounded-drain and post-drain
sample predicates; late submit invalidates the drain and its sample;
a deadline never settles quiescence), KryProbe every-program/every-CPU
obligations, and the OSSLscope delayed admitted hit. No live
settlement, native receipt path or product shutdown is qualified.

Profiles bind required predicate IDs with `before` edges, refusing
version zero (`IncompatibleVersion`), duplicate IDs (`DuplicateKey`),
foreign/unknown edge endpoints, self-edges and cycles
(`InvalidProfile`), caller-limit excess (`CapacityExceeded`) and more
than 64 predicates (`InvalidProfile`). Records pin one epoch at
construction (a zero budget refuses) and pin binding/origin from the
first observation; foreign epoch/binding/origin observations refuse
(`DomainMismatch`), so synthetic/replayed history cannot be promoted
into an adapter-reported record. Duplicate observations refuse;
renewed drain/sample uses a new record, keeping the old record's
history intact. Invalidations are atomic and share the admission
budget.

Assessment is total over admitted records: named invalidations
propagate transitively to dependents with the caller's gap; a
predicate is satisfied only when observed, uninvalidated, and every
prerequisite is satisfied with a strictly smaller serial and equal
drain generation. Observed-but-blocked predicates report `Missing`
(absent/misordered prerequisite) or `ContextChanged` (drain-generation
mismatch). Non-required observations are ignored, so a weaker
bounded-drain profile reports only its own predicates. No global
aggregate flag exists; callers read satisfied/missing/invalidated in
profile order.

Bad controls: baseline-after-admission serials withhold the chain;
sample-before-drain withholds the sample; dropped quiescence withholds
drain/sample; return-final-on-quiet-poll, detach-as-quiescence and
timeout-as-settled mutants each fail the explicit missing-predicate
assertions while weaker-profile and restored twins pass. The shipped
`fixtures/closure-v1.json` vectors carry the same six-predicate
script the tests drive literally; structural drift fails the package
test rather than passing silently.

All mechanisms here are T0/T1 scripted-model evidence. Live MemVeil
settlement, KryProbe/OSSL product truth, BP drain cursors, native
closure and UC12 remain open with their owners. CP10 owns strict
replay of closure records; CP11 owns real adapters; CP13/TT installed
exact-consumer conformance. No donor duplicate is removed here.
