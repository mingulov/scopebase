# BP03 host normative authoring assets

These frozen finite definitions accompany the [ratified host contract](../2026-10-22-scopebase-bp03-host.md)
and [verification plan](../../plans/2026-10-22-scopebase-bp03-verification.md).
They preserve the independently reviewed r2 definitions except the two client
templates amended by the [client JSON feature correction](client-json-amendment.md).
That correction adds only literal json=[] with no client default feature;
dependency substitutions and all original feature graphs remain fixed. Other
assets preserve the exact independently reviewed r2 bytes, including historical
PRIVATE/PROPOSAL/kind labels and PLANNED_NOT_RUN status. They are normative
authoring inputs; no product implementation, package helper, executed result or
runtime support is claimed by their presence. No private directory is needed
to recover their finite cases, raw literals, templates or resource definitions.

| Asset | Definition |
|---|---|
| [filter-cases.json](filter-cases.json) | 38 exact supplied-population/filter truth rows |
| [profile-cases.json](profile-cases.json) | 23 exact receiving-domain bridge rows |
| [observation-fixtures.json](observation-fixtures.json) | Full observation object/wire, context mutations, zero-BTF distinction and same-errno descriptive cases |
| [codec-cases.json](codec-cases.json) | 22 raw literal files with lengths/hashes/expected errors, plus five encoder boundaries |
| [adapter-cases.json](adapter-cases.json) | 16 closed constructor/binding/work/joint-retention recipes |
| [client-json-amendment.md](client-json-amendment.md) | Client-local JSON feature activation, separate graph bindings and exact controls |
| [delivery-recipes.json](delivery-recipes.json) | Full source/archive mappings, commands, templates, tools/cache/config rules and all cell definitions |
| [manifest-additions-bpf.toml](manifest-additions-bpf.toml) | Exact additive target/JSON declarations; preserve inherited manifest |
| [manifest-additions-testkit.toml](manifest-additions-testkit.toml) | Exact optional edge/features and gated target |
| [cache.Cargo.toml.in](client-manifests/cache.Cargo.toml.in) | Finite typed cache-client manifest template |
| [populations.Cargo.toml.in](client-manifests/populations.Cargo.toml.in) | Finite typed population-client manifest template |

Raw .bytes files are literal bytes, including malformed UTF-8/JSON, and must
never be normalized. Each codec path is relative to this directory; all other
paths in delivery recipes are the planned product/package locations. The six
template markers are whole typed TOML values as fixed in the delivery contract;
these unrendered templates are not valid Cargo manifests. The additive TOML
fragments are not standalone package manifests or permission to overwrite one.

The delivery recipe's inspected_predecessor_manifest/CANDIDATE_ONLY record
preserves the original r2 observation. It is historical, not current acceptance
or execution-base authority. The host contract binds BP02's actual accepted
subject/6050/root receipt; actual current accepted manifests/declarations/archives,
dependency/feature/lock/source closure, compiler/cache and output/build resources
still require the future executor binding. No old hash certifies new bytes.

Required future inventory remains exactly 20 testkit cells/80 retained-client
runs, 12 activated cells/24 BP03 runs and 12 corresponding BPF cells/24 runs.
Only identically bound actual executions may satisfy both overlapping inventories.
Full Rust clients/helpers/catalogs, API tests and semantic controls remain planned
outputs at the paths defined by the verification and delivery contracts. No
validator/generator script is normative or needed to recover these definitions.
