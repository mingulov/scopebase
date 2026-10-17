# Documentation mechanical checks

These are staged historical checks. See [final verification](final-verification.md) for the expanded study, including the later root instructions, gap analysis, user conformance, delivery plan and regression catalog.

Date: 2026-10-17. Read-only mechanical review of the research Markdown and JSON. No builds, tests, installs, or product changes were performed. Scientific correctness and source claims remain unverified by this check.

Commands/checks run from `/home/user/src/m/bpfscope`:

- `rg --files -g 'AGENTS.md' -g 'README*' -g '*.md' -g '*.json' ...`: enumerated the research files; no `AGENTS.md` was present in the returned workspace file set.
- Python Markdown-link scan over all `*.md`: **11 files**, **0 broken local file links or heading anchors**. Root README's advertised research README exists.
- Python `json.loads` over all `*.json`: **2 files**, **0 parse errors**.
- Python trailing-whitespace scan over Markdown and JSON: **0 lines**.
- ID scan: testing strategy contains a contiguous table of **28** scenarios, `H01`–`H28`; it contains **0** `Rnn` IDs. TODO.md says the scenarios are `R01`–`R28`.
- Placeholder/secret pattern scan over research Markdown and JSON: four generic TODO-word matches, all ordinary prose or the TODO filename; **0** private-key headers and **0** credential-assignment matches. Patterns are heuristic and do not establish absence of all secrets.
- README navigation/name spot-check: root README points to the existing study README. The study recommends **Scopebase**, says **scopekit** already exists on crates.io, and proposes six `scopebase-*` packages. This check verifies internal consistency only, not registry availability.
- Evidence-language spot-check: testing-strategy defines source/model/future-port/live tiers and explicitly says source presence and models do not establish runtime passes. The surrounding study also labels the work proposed and unexecuted. No runtime qualification was performed here.

Exact issue for the documentation owner to fix: change the TODO.md sentence naming `R01`–`R28` to `H01`–`H28`, or rename all 28 strategy IDs consistently. The existing matrix and scenario references use `H` IDs, so updating the single TODO reference is the smaller correction.

## Final recheck — 2026-10-17

The initial findings above are historical. The ID mismatch is **resolved** in the current documents: TODO.md names `H01`–`H32`, matching the testing strategy.

- Re-ran a Python local Markdown-link and heading-anchor scan across root README and the research documents, including `architecture-review.md` and `synthesis-review.md`: **14 Markdown files**, **170 local links**, **0 missing files or anchors**. Five links target compiler-investigation anchors in `kernel-toolchain-notes.md`; all resolve.
- Parsed both research JSON files with Python `json.loads`: **0 errors**. `external-sources.json` contains **13** source records, including `retis-org/btf-rs` with a pinned SHA.
- Rechecked trailing whitespace across the checked Markdown and JSON files: **0 lines**.
- Recounted the testing-strategy scenario table: **32 rows**, **32 unique IDs**, contiguous `H01`–`H32`, with no missing, duplicate, or unexpected table IDs. TODO's range is consistent.
- `final-verification.md` was not present at recheck time. `synthesis-review.md` preserves earlier findings as history and explicitly marks the compiler cases, IDs, source pin, and link checks resolved in its follow-up.
- No builds, tests, installs, broad source scans, or product changes were performed. Scientific correctness and source claims remain outside this mechanical recheck.
