# Authoring ScopeBase catalogs

TT01 supplies strict catalog admission, immutable requirement selection and an
independent local Python checker. These are metadata operations. They do not run
cases, discover environments, authorize a subject or establish qualification.
The initial catalog has 86 tasks, 179 source obligations, H01–H33, 19 DRAFT
profiles, one extension and four UNIMPLEMENTED H33 subcases. Other domain
subcases remain work for their named owners. The historical research catalog is
unchanged.

Use `CaseCatalog::load(bytes, CatalogLimits::default())`, parse the exact profile
with `ProfileId::parse`, then call `ProfilePlan::select`. Callers supply catalog
bytes explicitly. The returned plan owns its data and survives dropping the
catalog. Getters expose borrowed slices and immutable values; no unchecked
constructor, mutable plan or environment callback is available. Keep the
original plan when checking transported components with `validate_selection`.
Removing, adding or duplicating a component, extension or required cell fails;
reordering is permitted. Versions, tiers, implementation status and the full
sorted declaring-record attribution remain part of each required cell.

## Identities and revisions

Case IDs accept 1–96 ASCII characters, profile IDs 1–64: an alphanumeric first
character followed by alphanumerics, dot, underscore or hyphen. There is no
trimming, Unicode normalization, slash conversion or case folding. Profile and
extension declarations additionally end in `-vN`, a positive decimal u32 with
no leading zero. `ProfileId::parse` checks the lexical domain; catalog admission
checks the version suffix. These IDs are separate from BPF profile paths.

A case record is the exact `(CaseId, positive u32 version)` pair. Old and new
revisions coexist. `CaseCatalog::case(&id, version)` returns only that pair;
zero, missing and newer versions never choose a replacement. Profile suffixes,
case versions and executable/fixture/oracle/control revisions are separate
version domains. The catalog schema remains major 1; `catalog_revision` names a
reviewed metadata edition and supplies no authenticity. Global artifact-version
slots in `profiles/schema-versions.json` remain separate.

Change required membership, predicates, cells or composition under a new
profile/extension `-vN`, retaining the old declaration. This applies to DRAFT as
well as FROZEN. Changed case semantics require a new case revision; changed
referenced cell definitions require a new cell ID. Retain every historical case
pair, including unselected revisions. A catalog revision bump alone cannot
replace historical semantics. Baseline comparison treats membership as sets and
preserves inactive conditional declarations as well as effective closures.

DRAFT requires nonempty `open_owners`; FROZEN requires none, a nonempty effective
case closure and no DRAFT component. An unchanged-requirement DRAFT to FROZEN
transition clears owners and increments catalog revision. FROZEN to DRAFT is
refused. `ProfilePlan::open_owners` is the sorted union from selected profiles.
Extension `requires_tasks` references known tasks; it does not manufacture open
owners. Definition completeness is independent of implementation or evidence.
A FROZEN profile may still select UNIMPLEMENTED cases.

## Composition and H33

Admission resolves references everywhere, including unselected records and
inactive conditional rows. It rejects cycles over profile, extension-base and
extension-required-profile edges. Each declared profile root is checked for
profile/extension stem conflicts and active case revision conflicts.

Selection first closes profile and extension edges, then evaluates
`when_extensions` as an all-of predicate. A predicate does not select an
extension or create an edge. Repeated requirements merge by exact case revision
and cell; `required_by` lists the declaring profiles/extensions, not their
ancestors. Output is lexical by case ID, numeric version, then cell ID.

`btf-shape-le-v1` conditionally declares H33.license-admission when
`btf-runtime-linkage-v1` is selected. The extension's required_cases is empty.
Bare BTF shape selects no H33 cells. Native composition selects T0 source
closure, T2 final-object declaration, T4 license admission and T5 installed
notices, while all remain UNIMPLEMENTED. These distinct source/build/runtime/
installed obligations must not be presented as executed license checks.

## Registration and local artifact observations

UNIMPLEMENTED requires `registration:null`. REGISTERED_EXECUTABLE requires
executable, fixture, oracle, bad_control, oracle_basis and control_assertion.
Each artifact has id, revision, path, sha256 and entrypoint. Artifact `id()` and
`entrypoint()` return `&str`, with identifier grammar checked at admission;
`path()`/`sha256()` also return `&str`, and `revision()` returns u32. Case and
profile references retain their typed ID getters. The oracle and bad-control
identities must differ from the executable's `(path, sha256, entrypoint)`.
String inequality cannot prove semantic independence. Explain the independent
oracle and intended control assertion; owning domain review and later execution
are still required. Entry points are identifiers, never shell commands.

Paths are nonempty relative slash paths with no empty, dot or parent segments,
backslashes, NUL or absolute prefix. SHA256 is exactly 64 lowercase hex digits.
Rust admission performs no filesystem IO. The Python checker with
`--artifact-root ROOT` opens root and path components through directory file
descriptors with `O_NOFOLLOW`, checks regular file type and hashes each distinct
path once. It reads at most 8 MiB plus one detection byte per file by default.
It refuses missing/nonregular/symlink/escaped/oversize/mismatched files and never
imports or executes them. This observes bytes through opened descriptors; it is
not an atomic snapshot of concurrently modified files or an execution permit.
Runtime consumers must revalidate their own exact bindings in TT02.

Registration/status changes are evidence invalidations, separate from unchanged
case/profile semantics. They require a new metadata edition and invalidate
previous affected artifact evidence, even when baseline structure is accepted.
The checker does not claim that an altered oracle remains semantically valid.

## Strict admission, bounds and diagnostics

Every field is required; only case registration may be null. Duplicate object
members reject before map collapse; unknown/missing fields, wrong types,
noninteger/zero/overflow revisions, invalid UTF-8/BOM, trailing input and
duplicate IDs/list members are refused. Numeric booleans are not integers.
Unselected records consume the same limits as selected records. Cases count
records, including revisions, rather than distinct ID strings.

CatalogLimits permits lowering positive values up to these hard ceilings:

| Limit | Default and ceiling |
|---|---:|
| Input bytes | 8 MiB |
| Case records | 4096 |
| Profiles / extensions | 128 each |
| Obligations / cells | 512 / 256 |
| Reference and ownership edges | 8192 |
| UTF-8 bytes per string | 64 KiB |
| JSON delimiter depth | 32 |
| Selected case/cell pairs | 16384 |

Tasks and families are capped at 128 each. Zero or above-ceiling settings are
InvalidLimits. A quote/escape-aware delimiter preflight bounds nesting; serde
and Python json remain the JSON grammar authorities. Rust bounded visitors
never reserve from size_hint and refuse the next collection element before
pushing it. Python preflights delimiter population counts before json can grow
collections. An invalid document may hit a bound before its grammar error.
Every reference/ownership edge counts, including nested obligation references,
required-case declarations, extension predicates, case family references and extension base profiles.

Error precedence is deterministic for the supplied bytes: limits, raw byte size,
depth/population preflight, bounded JSON decoding, numeric revisions, typed
fields/schema, identities/references, graph cycles, then root closures and
frozen definitions. Within a stage, input record order and lexical object-field
order can determine the first error. Consumers should use typed Rust `kind()`
values; Display is bounded diagnostic text without an input blob. Multiple
invalidities are not promised an order-independent diagnosis. These are byte,
collection and work ceilings; no exact RSS ceiling, syscall deadline or
interruptible filesystem operation is promised. No process policy is changed.

## Independent checks and delivery

Run the checker with Python 3.11 or later:

```sh
python3 tools/qualification/check_catalog.py profiles/cases-v1.json
python3 tools/qualification/check_catalog.py NEW.json --baseline OLD.json
python3 tools/qualification/check_catalog.py profiles/cases-v1.json \
  --traceability docs/superpowers/plans/2026-10-17-scopebase-traceability.json \
  --research-catalog docs/research/2026-10-17-shared-libraries/regression-catalog.json
```

The inventory arguments must be supplied together. Installed independent use
needs only the catalog; it does not resolve donors or repository metadata. The
explicit inventory route checks canonical owners, family meanings, descriptions
and graph plus package-copy equality. Source obligations lacking inline prose
keep an empty description for UC/G; regression families use their exact
short_contract fallback. Supplied descriptions remain verbatim. Stable UC/G
IDs retain the meanings documented by the project inventory.

Output is exactly schema_version, structurally_valid, definition_complete,
qualification (`not_evaluated`), registrations_verified and errors. Valid DRAFT
metadata exits 0 with definition_complete false. Invalid data exits 2; invalid
usage exits 64. Without artifact-root, registered catalogs report
registrations_verified false. No registrations make that field vacuously true;
it is only a local file-binding field. No PASS/runnable/support aggregate exists.

The package contains byte-identical initial catalog/schema copies, literal
revision fixtures, a shared literal accept/reject table and harmless registered
artifact files. Maintainer tests have independent Rust/Python closure oracles,
known-bad controls and two separate archive consumers. Run package tests and
explicit doctests against the unpacked archive; downstream dependency tests do
not run automatically with an application's ordinary cargo test. This slice
supplies no domain runner or installed operator qualification route; TT02 and
TT07 retain those later obligations. Package readiness, domain execution,
profile qualification, migration and publication remain separate boundaries.
