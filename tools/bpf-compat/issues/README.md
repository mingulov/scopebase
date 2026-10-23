# TC01 issue mapping: H07–H11/H29–H32, B/C, patch expirations

Donor-backed rows have issue files and provenance in this lane.
Research-only rows point at preserved research and state their owning
task; TC01 ships no fixture for them and claims nothing about them.

| Row | Issue file / pointer | Provenance | Patches | Owner |
|---|---|---|---|---|
| H07 | `H07-map-relocation.md` | `fixtures/bpf/object-graph/provenance.json` | `aya-obj-map-relocation` | TC01 register; TC05 checks |
| H08 | Preserved research (`docs/research/2026-10-17-shared-libraries/`); no TC01 fixture | — | — | BP08/TC05/TC06 |
| H09 | Preserved research; no TC01 fixture | — | — | TC06 |
| H10 | Preserved research; no TC01 fixture | — | — | TC05/TC06 |
| H11 | Preserved research; no TC01 fixture | — | — | TC05/BP09 |
| H29 | `H29-used-result-rmw.md` | `fixtures/bpf/atomic-rmw/provenance.json` | `llvm-used-result-rmw` | TC01 register; TC04 oracle |
| H30 | `H30-isa-profiles.md` | `fixtures/bpf/isa/provenance.json` | — (contract, not a workaround) | TC01 register; TC03 admission |
| H31 | `H31-atomic-load-selector.md` | `fixtures/bpf/atomic-load/provenance.json` | — (separate unpatched issue) | TC01 register; TC04 selector |
| H32 | `H32-mixed-debug-metadata.md` | `fixtures/bpf/metadata/provenance.json` | `bpf-linker-debug-records` | TC01 register; TC05 checks |
| B05 | Register itself (`../patches.json`): reader, relocation entries | — | `aya-ring-reader`, `aya-obj-map-relocation` | TC01 |
| B06 | `H07-map-relocation.md` (sentinel-FD rule) | object-graph | `aya-obj-map-relocation` | TC05/BP10 |
| C01 | H29/H31 rows | atomic-rmw, atomic-load | `llvm-used-result-rmw` | TC01/TC04 |
| C02 | H30/H31 rows | isa, atomic-load | — | TC01/TC03 |
| C03 | `H29-used-result-rmw.md` (removal rule) | atomic-rmw | `llvm-used-result-rmw` | TC01/TC08 |
| C04 | H07/H32 rows | object-graph, metadata | `bpf-linker-debug-records`, `aya-obj-map-relocation` | TC01/TC05/TC06 |
| C05 | `../toolchains.json` (pinned closure inputs) | all (toolchain_refs) | — | TC01/TC02 |
| C06 | This mapping plus per-record removal tests | — | all (none expired) | TC01/TC08 |

Notes:

- `aya-ring-reader` is registered (B05 reader entry) but has no TC01
  fixture area; ring fixtures belong to BP06. Its defect family (H12)
  is outside the TC01 H-row scope.
- No record is expired. Expiration needs the replacement binary, final
  mixed objects, independent bad/valid controls, affected kernel cells
  and downstream routes (TC08); a merged upstream source alone never
  expires a record.
- All historical donor results in this lane are `HISTORICAL` or
  `NOT_RUN`, never current PASS verdicts.
