# BP03 client JSON feature amendment

Status: root-selected implementation correction, 2026-10-22. The contract below
amends the [verification plan](../../plans/2026-10-22-scopebase-bp03-verification.md#one-shipped-source-for-each-complete-external-client)
and supplements [delivery-recipes.json](delivery-recipes.json). It specifies
future implementation and verification; it records no executed Cargo, client,
semantic-control, archive or conformance result.

## Defect and selected correction

Dependency feature activation does not enable a same-named feature of the
calling package. The original six-substitution templates enable dependency JSON
APIs but declare no client feature, so `cfg(feature="json")` direct-client checks
cannot run. Both complete delivered client templates, cache and populations,
must contain the following literal declaration, with no client default feature:

```toml
[features]
json = []
```

The list deliberately forwards no dependency features. This is a fixed template
literal, never a seventh substitution. Preserve exactly BPF_PACKAGE_PATH,
TESTKIT_PACKAGE_PATH, BPF_DEFAULT_FEATURES, TESTKIT_DEFAULT_FEATURES, BPF_FEATURES
and TESTKIT_FEATURES as the only six typed substitutions. Preserve every other
package, workspace, target, dependency, default-feature and same-BPF-path patch
term. Ship the amended templates at the already specified testkit client paths.

## Activation and graph bindings

For each new client, use the following client Cargo arguments consistently for
offline/locked metadata, build and run. For direct execution of the measured
binary, retain the corresponding measured build/metadata binding; do not pass
Cargo flags to the binary. The same unchanged Rust source bytes serve all modes.

| Mode | Client Cargo feature arguments | Raw client resolve features | Combined BPF raw features | Combined testkit raw features |
|---|---|---|---|---|
| core-default | none | [] | [default] | [bpf-host,default] |
| core-minimal | none | [] | [] | [bpf-host] |
| json-union | --features json | [json] | [json] | [bpf-host,bpf-host-json] |

The existing dependency rendering remains exact: core-default sets both
dependency defaults true, BPF features=[], testkit features=[bpf-host];
core-minimal sets both defaults false with those same explicit lists;
json-union sets both defaults false, BPF features=[json], testkit
features=[bpf-host,bpf-host-json]. No client default marker exists even in
core-default. Baseline default/minimal modes introduce no BP03 clients. Existing
isolated testkit/retained-client BPF graphs and all raw default markers remain
unchanged; client features are a separately measured graph dimension.

Before qualification, record the client package ID, exact manifest/template and
source hashes, requested Cargo feature arguments and actual raw client resolve
features separately from both dependency feature sets in metadata and results.
For each activated consumer require exactly one actual BPF package ID and equal
direct/adapter BPF IDs, still matching SubjectBinding. Reject extra/missing
client features as well as existing dependency graph mismatches. Freeze target,
lock, binary and source/archive bindings as before. Do not use RUSTFLAGS, rustc
`--cfg`, per-mode source rewriting, a mock JSON implementation, fallback checks
or inferred dependency-feature activation. A feature flag or successful build
alone never proves the complete JSON semantic checks executed.

## Required positive and active-negative checks

The ordinary json-union positive executes both complete clients with the
explicit client json feature and all previously required direct JSON checks,
adapter JSON cases, independent literal comparisons and report round trips.
The packaged/root client sources and the population oracle remain byte-identical
according to the existing mappings. Do not replace complete JSON coverage by a
feature assertion or a JSON success banner.

The delivered checker must retain semantic completion evidence produced only
after the relevant assertions pass, with these exact required group IDs:

| Client | Required JSON completion group IDs |
|---|---|
| bp03-cache | cache.json-import-fields-origin, cache.json-reencode-literal |
| bp03-populations | populations.json-direct-api, populations.json-adapter-cases, populations.json-report-roundtrip |

These are completion witnesses for the full pre-existing required checks, not a
smaller case inventory or new public library API. Require exact comparison of
imported fields/origins and independent canonical bytes in cache; direct optional
JSON APIs, the complete JSON case population through the real adapter and the
executed/report-import assertions in populations. Emit each group only after
all its required assertions succeed. The checker obtains its required group set
from the externally selected json-union recipe, never from the client's cfg,
stdout claims, or the set of checks the binary happened to execute. A bounded
completion record may be embedded in the existing result format; an unconstrained
stdout substring is not the oracle.

For `omitted_client_json`, hold source bytes, input/expected fixtures, JSON-enabled
dependency rendering, locks, route and runtime json-union request fixed. Remove
only the client's `--features json` from metadata/build/run for each client in
turn. In a separately labelled control stage, record the expected raw-client
feature mismatch, deliberately bypass only that one normal binding refusal, and
execute the ordinary client's runtime request through the semantic checker.
Never qualify this stage. Both missing-feature paths must report the intended
coverage error, rather than panic at argument parsing, crash during setup or
silently select the core profile. The exact semantic refusal is
`BP03_CLIENT_JSON_COVERAGE_MISSING`, with client ID and the lexicographically
sorted missing required group IDs; with json absent all groups for that client
are missing. The negative passes only when this exact refusal and missing set
are observed, the admitted JSON dependency graph remains intact, and no JSON
completion group is accepted. An early feature-metadata mismatch alone does not
satisfy this semantic control. Restoring only client activation must produce the
exact expected raw client/dependency graphs and all required semantic groups
with passing comparisons. Record RED/restored-GREEN separately; these are planned
checks until observed against the actual delivered bytes.

For `core_with_client_json`, choose a precise pre-Cargo manifest-validation
refusal rather than unstable compiler diagnostic text. Render each core mode's
unchanged dependency manifest and request client features=[json]. Before Cargo,
the delivered checker must reject exactly
`BP03_CLIENT_JSON_MODE_MISMATCH`, recording the actual client ID, the requested
core-default/core-minimal mode, requested_client_features=[json] and
expected_client_features=[]. No Cargo child or payload is entered. The control
passes only for this exact refusal with the original core dependency projection
preserved. Restoring requested_client_features=[] passes this admission check
and permits the original core checks; it does not by itself prove those checks.
This is an explicit binding negative, not a semantic-mutant sensitivity result.

## Scope and history

This correction changes only client feature declaration/activation, corresponding
binding/result fields and discriminating controls. The 20 testkit cells, 80
retained-client executions, 12 activated cells/24 BP03 executions and 12 BPF
cells/24 corresponding executions retain their identities. New control stages
are separately recorded and do not inflate those positive-cell counts.

The original recipe labels, preparation/job snapshots and observed hashes remain
historical inputs. Root must append this amendment and exact hashes to the
executor inputs, retain the older bindings, and bind the actual amended shipped
and canonical template bytes before any passing result is claimed. No old hash
or prior review certifies these changed bytes. All existing model-only evidence
limits, native/runtime exclusions and acceptance gates remain in force.
