# SDK04 acceptance (alpha mode, 2026-10-23)

**ACCEPTED as in-crate adaptation.** Lane `lane/w25-sdk04`: `c9ff382`,
merged to `feat/m0-foundations`. No fixup round (review ACCEPT-adapted).

- Owned-workload host observer as `scopebase-sdk` module (linux-gated):
  owned-spawn-only custody over LX02 acquire + LX03 read_all + LX04
  control; typed ForeignPid/Capacity/ShutDown negatives; explicit
  kill-vs-exit reporting; one-diagnostic-per-observation SDK tie-in.
- Tests: observer 11/11 (real owned children, /proc reap checks).
  Root re-verified 11/11 post-merge. No donor/third-party lines.
- DEVIATION (recorded, accepted): plan text wants installed binary
  `apps/scopebase-file-observer` + CLI/report contract — NOT built.
  Binary app + mutant-kill probes + TT03/TT06 registry linkage remain
  follow-ups (SDK04-binary) if still wanted.
- Minors carried: kill-race misattribution note, 2 untested accessors,
  doctest /tmp litter path.
