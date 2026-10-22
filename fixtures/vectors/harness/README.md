# TT02 model vectors

The authoritative delivered corpus is
[scopebase-testkit/tests/fixtures/harness](../../../crates/scopebase-testkit/tests/fixtures/harness).
It contains separately authored arithmetic inputs/expected vectors, model ledgers,
source registrations, raw malformed controls and independent receipt literals.
Run `python3 tools/qualification/check_harness_vectors.py` from the repository.
These are T0 model operations and real host byte-admission checks, not Linux/BPF
runtime, source-license compatibility or a qualified canonical profile.
