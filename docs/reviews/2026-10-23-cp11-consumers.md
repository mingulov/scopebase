# CP11 acceptance (alpha mode, 2026-10-23)

**ACCEPTED.** Lane `lane/w24-cp11`: `9552e96`, merged to
`feat/m0-foundations`. No fixup round (review ACCEPT, no blocking findings).

- Three standalone reference consumers (`consumers/capture-{kryprobe,
  memveil,ossl}-reference`), each with own manifest+lockfile, own
  ConformanceAdapter over a materially different capture surface
  (insertion/counter/loss; facts/generations/views; bounds/corrections),
  8/8 tests each incl. negatives+twins and dropped-holder detection.
  Correction-holder types (`holder.rs`) + 5 runnable examples.
- Reference-only NEW: zero donor lines copied. Root re-verified 8/8 ×3
  plus capture suites green post-merge.
- Follow-ups: retire() untested (no public RetireRequest constructor —
  needs API decision); exact subject/archive binding belongs to CP13;
  CP13 packaging + MG migrations later.
