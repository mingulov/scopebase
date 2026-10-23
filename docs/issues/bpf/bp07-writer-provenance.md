# BP07: writer ownership, insertion provenance and full-map diagnostics

TT05 follow-up binding record for the BP07 host increment (`0e055c9`,
Wave 27). The Step-4 deferral was first recorded in that commit message
(immutable); this document restates it and appends the unnamed Step-3
sub-item so both bindings live in one place.

## Delivered (host-only)

- Program/CPU writer slots over `CpuTopology`, guarded same-program
  refusal with an independent exact miss ledger.
- Unique-marker insertion ownership with checked totals; saturating
  cap-255 degradation folds over validated loss grids with epoch reset
  discipline.
- Typed `FullMap` occupancy proof (capacity == admitted, refused >= 1;
  every non-proof shape, including the silent-drop shape, refuses).
- Pure insertion records ship in `src/writer.rs` (host-only);
  `maps/provenance.rs` keeps its native-only gate with no host API.

## TT05 follow-up binding (OUT OF SCOPE, exact binding needed)

Step 4 deferral (from `0e055c9`): TT05 live discrimination — plan
Step 4 (H14 subcases, H15.migration, H17 subcases, H18 every-lane /
stuck-writer / deadline / late-entrant countermodels on x86-64 6.12/7.0
fixture profiles with workload ledger + T0/T1 host mirror). Needs a TT05
live-cells execution binding: selected kernel profile, producer workload
ledger, and final-map linkage (TC05/TC07/BP11) before any live claim.

Step-3 sub-item (plan Step 3, second sentence): package minimal
independently authored BPF writer/full-map producers for conformance;
inspect their actual per-program partitions and independent preallocated
diagnostic array. Deferred to the same TT05 live-cells execution
binding as the Step-4 deferral above; no live producer claim until that
binding exists.
