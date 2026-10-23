# BP09 BTF input-boundary fuzz project

Separate Cargo workspace with one libFuzzer target (`btf_parse`). It depends
on the `scopebase-bpf` path crate with the `btf` feature, uses
`libfuzzer-sys =0.4.13`, and exercises base/split admission over fixed
small budgets (4 KiB images, 256 types, 100k work steps). Neither binary is
part of the normal product workspace or package closure.

`corpus/btf_parse/` seeds are byte copies of the `fixtures/btf-v1` corpus
images (see that directory's manifest for hashes); all five must admit
under the target budgets. The target asserts nothing beyond termination
with `Ok` or a typed `Err`: any panic, hang or runaway allocation is a
failure. Build and smoke-run with an installed clang (`clang-18` verified):

```sh
cd fuzz/scopebase-bpf
cargo fetch
CC=clang-18 CXX=clang++-18 cargo run --offline --locked --bin btf_parse -- \
  -runs=10000 corpus/btf_parse
```
