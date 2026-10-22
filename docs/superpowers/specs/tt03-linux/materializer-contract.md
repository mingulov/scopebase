# TT03 verified archive materialization contract, version 1

**PROPOSED R2 NARROW NORMATIVE REPAIR / no implementation or execution admission.**
This document closes C7DEL-01 through C7DEL-04 of the independent C7 delivery
review. The accompanying source selection closes C7DEL-05 at the design level,
subject to its named admission supplement. All product commands and controls are
NOT_RUN. The r4 protocol, creator context, owner/finalizer rules, numerical native
bounds, fourteen P/seven F populations and later installed interface are preserved.

## Selected delivery and trust boundary

The package ships complete literal `worker/Cargo.toml.in` and
`driver/Cargo.toml.in`, their independently generated frozen `Cargo.lock` files,
their actual source, `LICENSE-APACHE` and `THIRD-PARTY-NOTICES.md`, plus
`materialize.py` and `test_materialize.py`. It contains no nested actual
`Cargo.toml`, prebuilt fixture binary or own build script. Every actual corpus
leaf must be enumerated in the actual package inventory before execution; a glob
in a design document is not that inventory.

Developer delivery consists of the actual `.crate`, an external
`scopebase-testkit-0.1.0.tt03-inventory-v1.json` companion, and externally supplied
SHA-256 bindings for both. The companion describes the actual archive; it is not
inserted into that archive and does not describe itself. Its generation is a
packager action after reviewing the exact archive membership and Cargo-normalized
manifests. The materializer never makes an approved inventory by measuring the
directory it is asked to accept.

The supported route is Linux, CPython 3.11 or later with `tomllib` and the named
standard-library descriptor operations available. The actual interpreter/version,
stdlib installation and resource envelope are bound before execution. Unsupported
interpreters refuse without installation or a fallback parser. Only explicit
filesystem reads/copies are performed: no subprocess, Cargo, resolver, compiler,
network, native fixture, copied-code execution, tool search, mount or credential/
namespace/host-limit change. No package import may start materialization.

The CLI is exactly:

```text
python3 ABS/extracted-testkit/tests/fixtures/linux/materialize.py
  --package-root ABS/extracted-testkit
  --inventory ABS/scopebase-testkit-0.1.0.tt03-inventory-v1.json
  --inventory-sha256 LOWERCASE_64_HEX
  --output ABS/previously-absent-output
```

Each option occurs exactly once; extra arguments/options refuse. Each input
absolute path has at most 4096 UTF-8 bytes. All paths are
absolute, with no empty, `.` or `..` components, trailing separator or NUL. The
inventory path is outside both the source tree and requested output. The output
parent already exists. Source, inventory and output traversal follows no symlink
component. The source and output are neither equal nor ancestors/descendants;
held-parent/root identities and ancestry are checked as well as spelling. A
previously existing output, including an empty directory, is refused untouched.

`--inventory-sha256` is an independently supplied caller anchor. The observed
companion bytes must match it before parsing. The inventory's archive SHA-256
and length are **caller/packager assertions**, because this CLI does not read the
archive. The outer route first checks the actual archive against that binding and
extracts only its approved regular files into the exclusively owned source tree.
The materializer establishes observations of those extracted files and their
copies. It does not authenticate a publisher, prove an extraction history from a
directory name, or verify a backend, compiler or binary. Supplying a different
companion and its digest is a different caller assertion, never an automatic
approval of different source.

## Exact expected-inventory version 1

`materializer-contract.json` defines the closed field/type vocabulary and fixed
ceilings. Unknown or duplicate fields at every object level, unknown versions,
UTF-8/BOM/surrogate errors, nonfinite numbers, booleans in integer fields, floats,
negative/out-of-range integers and trailing JSON refuse. Check structural depth
before allocating a parsed graph; its maximum is 12. A decimal integer token has
at most 20 digits. The bounded raw JSON is retained only while needed; do not
retain arbitrarily nested parser errors or arbitrary exception representations.

The root object has exactly `schema_version`, `kind`, `source_archive`,
`subject`, `entries`, `topology`, `totals` and `limits`:

- `schema_version=1`, `kind="scopebase.tt03.expected-inventory.v1"`.
- `source_archive={sha256,bytes,root_directory}` binds the actual `.crate` and
  its single top-level package directory. That prefix is stripped once to form
  entry paths; the prefix is not part of an entry path.
- `subject={name,version,default_features,requested_features,target,
  intended_rustix_backend}` is exactly `scopebase-testkit`, `0.1.0`, `false`,
  `["linux-fixtures"]`, `x86_64-unknown-linux-gnu`, `linux_raw`. The last field is
  an intended C7 input, not an observed compiler/backend result.
- `entries` is a nonempty array of unique regular-file records
  `{path,bytes,sha256}`, strictly ordered by the path's UTF-8 bytes. Paths are
  relative Linux paths with no empty/dot/parent component, backslash, NUL or
  control character; no Unicode normalization is applied. A file cannot also be
  a directory prefix. Empty directories, symlinks, hard links and nonregular
  archive entries are unsupported. Directory membership is the exact prefix
  closure of the file paths, including the source root separately.
- `topology` has exactly `root_manifest`, `root_original_manifest`,
  `archive_root_lock`, `worker`, `driver`. The first three are file records for
  `Cargo.toml`, `Cargo.toml.orig`, `Cargo.lock`. Each workspace record is exactly
  `{template,lock,generated_manifest}`: template and lock are file records;
  generated_manifest is its fixed path. All file records match an `entries`
  record exactly. Worker and driver template/lock paths are fixed below
  `tests/fixtures/linux/{worker,driver}/`; generated paths are respectively
  `tests/fixtures/linux/{worker,driver}/Cargo.toml` and must be absent from input.
- `totals={files,directories,file_bytes,directory_path_bytes,generated_bytes}`
  equals recomputed entry count, non-root prefix-directory count, entry-byte sum,
  UTF-8 prefix-directory path-byte sum and the two template byte lengths' sum.
- `limits` contains exactly the fixed version-1 values in the machine contract.
  It is not permission to raise them. No CLI limit override exists.

Every non-root basename `Cargo.toml` is refused, even when declared in entries.
The normalized root manifest, root original manifest and archive-root lock are
three distinct exact inputs. No archive-root lock can substitute for either
workspace lock. A missing worker/driver lock always refuses. No resolver or
missing-lock exception is available through this CLI.

After byte identity, use bounded `tomllib` parsing for the two root manifests
and two templates. Check actual subject name/version/default features, own
`build=false`, explicit `linux-fixtures` optional-rustix feature and the selected
target/dependency topology. The templates must exactly match the reviewed
manifest bytes and semantics: explicit targets, no automatic target discovery,
no own build script, resolver-2 own `[workspace]`, worker with no testkit edge,
driver testkit path exactly `../../../..`, version `=0.1.0`, defaults off and
only `linux-fixtures` selected. Pinned dependency/feature differences are a C7
refusal; neither a hash match alone nor TOML parsing approves a new graph.
Dependency build inputs and the resolved graph are separate C7 checks. An
unexpected provider dependency returns the named NEEDS_DECISION stop.

## Bytes, logical work, metadata memory and time

These are selected application ceilings, not measurements of a candidate:

| Dimension | Version-1 ceiling |
|---|---|
| Inventory raw UTF-8 | 4 MiB |
| Regular files / non-root prefix directories | 8192 / 8192 |
| Relative path / components | 4096 UTF-8 bytes / 64 |
| Sum of prefix-directory path bytes | 4 MiB |
| One copied file / aggregate copied inputs | 8 MiB / 64 MiB |
| Each parsed TOML manifest / generated manifests together | 256 KiB / 512 KiB |
| One read/write/hash data chunk | 64 KiB |
| All charged file/descriptor data reads, including verification | 512 MiB |
| Copied plus generated data writes, excluding report/diagnostic | 64.5 MiB |
| Charged logical filesystem/iterator/chunk operations | 1,048,576 |
| Simultaneously held descriptors | 32 |
| Terminal filesystem report / terminal diagnostic | 16 MiB / 64 KiB |
| Accounted retained metadata object graph | 64 MiB |
| Caller-owned process memory allowance, separately enforced/observed | 512 MiB |
| Cooperative deadline from one monotonic start | 120 seconds |

Each declared size and total is checked with overflow-safe arithmetic. Enumerate
at most the permitted total directory/file count plus one unexpected entry; stop
there rather than finishing an unbounded tree scan. Directory iterators are
closed explicitly and share the descriptor ceiling. Charge all own open/stat/
directory-entry/read/write/hash/verify/report steps before attempting them;
retries consume the same work/time allowance. The logical operation counter does
not claim to count hidden CPython/kernel retries or bound kernel syscall work.
Enforce total read/write work during every pass, including short reads and
partial writes; the chunk ceiling is not a total-byte ceiling.

Before output creation, compute/reserve complete per-entry, per-directory,
generated-file and failure-report mapping space, using worst-case fixed-width
numeric/error fields and actual escaped path lengths. Refuse if any possible
terminal mapping exceeds 16 MiB. No path/custody map may be truncated to make a
nominal COMPLETE or PARTIAL report fit. Keep only bounded buffers and necessary
metadata; do not read an entire copied file into memory. Manifest parsing has its
separate 256 KiB cap. Iterative graph accounting with `sys.getsizeof`, charging
each retained object identity once and including keys/container overhead and
reserved report state, must remain within 64 MiB. Refuse before output if that
reservation cannot fit. Account subsequent metadata before retaining it.

The metadata ceiling does not include the interpreter, TOML/JSON parsing
temporaries, allocator fragmentation, hashing implementation or OS page cache.
The fixed 512 MiB outer process allowance covers interpreter/temporary overhead
and is a required caller resource binding, not an inferred Python RSS theorem.
The materializer does not configure a host/cgroup/process limit. Qualification
must measure actual retained allocations and Linux peak RSS of the bound
interpreter on maximum accepted inventories and reached refusals. An outer
memory kill is an incomplete attempt with possible partial output, not a passed
bounded-memory refusal. If the supported envelope cannot meet these ceilings,
return NEEDS_DECISION; do not silently increase them.

Check the one deadline between bounded operations/chunks and before output
creation, generation, final verification and report publication. It never
refreshes after a file/error. It cannot interrupt a blocked filesystem syscall,
guarantee process termination or prove output/descriptor/resource retirement.
The outer command collector separately binds its wait, memory, output and owner
custody. Its wait expiry is incomplete and cannot be rewritten as INPUT_REFUSED.

## Original source and exclusive output authority

Supported input is an exclusively owned, stable extracted source tree, a stable
inventory file, and an existing caller-owned output parent, all retained by the
same caller throughout the command. The caller excludes other source/output
writers until the subsequent build gate releases them. Files/directories are
owned by the executing effective UID and source regular files have link count
one. These checks do not prove exclusive ownership against a hostile same-user
writer. No such adversarial filesystem guarantee is advertised.

Open source root, inventory and output-parent components with descriptor-relative
O_DIRECTORY/O_NOFOLLOW/O_CLOEXEC traversal. Reject a nonregular leaf with held-
parent no-follow lstat before source/inventory O_RDONLY/O_NOFOLLOW/O_CLOEXEC/
O_NONBLOCK open and original fstat; output files use O_RDWR/O_CREAT/O_EXCL/
O_NOFOLLOW/O_CLOEXEC. Nonblocking input open avoids an observed FIFO blocking
before type validation. Unsupported concurrent rebinding is not a device/security
guarantee. With those operations, hold root/parent authority, validate `fstat` kind/UID, and
record identities before using children. Inspect the held file actually read,
not merely a preliminary pathname stat. Each source file's `(dev,ino,mode,uid,
nlink,size,mtime_ns,ctime_ns)` is recorded before/after reading and compared with
the same path reopened through the held root at final verification. A descriptor
number or pathname alone is never identity. Device/inode metadata is local
observation, not a universal filesystem/content identity or an atomic snapshot.

First enumerate/hash/validate all inputs and topology, preflight resources and
confirm exact inventory. Until that finishes, create nothing under output. Then
reserve the requested output by exclusive `mkdir` under its held parent; open
that original directory without following links and record its actual identity.
All subsequent output creation is relative to that authority, with directories
mode 0700 and new regular files mode 0600, exclusive/no-follow creation, no
hard-link copy, merge, overwrite, resume, source write or recursive rollback.
For source regular files/inventory, compare all recorded fields plus hashes;
source directory stability also checks its size/nlink/times. For created output
directories, compare dev/ino/mode/uid and exact membership: own child/report
creation legitimately changes size/nlink/times from the initially empty directory.
Record destination regular-file stats only after its completed writes and keep
those facts stable through rechecks. File permissions are output policy; the
byte mapping does not claim metadata identity with the archive. There is no durability/fsync or crash-recovery claim.

Copy every approved entry, in inventory order, to `OUTPUT/subject-testkit/PATH`.
Hash the source bytes actually copied, compare with the expected record, handle
short writes, then re-read/hash the original created destination file. Record
both held identities and exact bytes/digests. Never substitute a path-reopened
different file after a failure. Close each per-file owner once; a consumed close
failure is not retried by descriptor number. Hold only the bounded traversal
working set, not an unbounded set of open input files.

Only after complete copying, exclusively create these two additional files:

```text
subject-testkit/tests/fixtures/linux/worker/Cargo.toml
subject-testkit/tests/fixtures/linux/driver/Cargo.toml
```

Their bytes are identical to the already copied, verified respective templates.
No token substitution, normalization, dependency-path rewrite or lock edit occurs.
Driver's `../../../..` resolves to this very `subject-testkit`; it cannot escape
to a separately resolved testkit. Original templates and all three lock roles
remain. Enumerate/re-hash the complete copied input and the exact two additions,
re-enumerate/re-hash the source, and recheck directory/path/held identities before
sealing completion. Re-read/re-hash the original held inventory file too,
matching its initial/final identity/stat and caller-anchored digest; retain those
observations separately from the caller-asserted archive. Output reports live outside `subject-testkit`. Never
repackage the generated tree as the original source archive.

Changed bytes, extra/missing paths, file/directory rebinding, source/destination
identity changes, short copy, syscall/close error, bounds or deadline failure
after reservation yield PARTIAL. These checks detect observed races; equal
observations cannot rule out an unobserved A→B→A or coherent hostile rewrite.
The source/copy report records sequential observations. It cannot freeze files
for a later build. A subsequent build requires continued exclusive ownership and
an immediate full mapped-tree/manifest/lock recheck against the accepted report.
Cargo-generated `target/` or other build artifacts are outside the copied subject;
any new subject member invalidates that gate. Cargo's ordinary metadata/lock
reads must not mutate the frozen source/lock bytes.

## Terminal result, report and partial custody

The closed terminal states and exit codes are `COMPLETE`/0,
`INPUT_REFUSED`/2 and `PARTIAL`/3. Before reservation, refusal emits the bounded
terminal diagnostic only and leaves a missing output absent or a preexisting
output untouched. There is no filesystem report at an uncreated destination.
A known EEXIST refuses without writing the preexisting tree. An ambiguous mkdir
result, or observed mkdir success followed by failure to obtain original output
authority, is PARTIAL/nonzero: record CREATED_UNOPENED or ATTEMPT_UNCERTAIN,
nullable output identity/exclusive-created truth and retain caller custody of the
parent/possible entry. Do not claim absence, original ownership or a filesystem
report that could not be established. After verified exclusive reservation, every
failure is PARTIAL, even if no file completed. Retain the original owned output and a complete per-entry status map; do not
delete it, continue it, rerun into it or permit downstream/native use. A new
attempt always has a new output root.

The only terminal report path is `OUTPUT/materialize-report.json`, outside the
copied subject, created exclusively. Its version-1 vocabulary/fields are in
`materializer-contract.json`; required fields cannot be omitted on normal
PARTIAL publication. All expected entries and directories have a state,
including unattempted and uncertain paths; generated manifests and three lock
roles are separate. Report/diagnostic bytes use strict UTF-8, sorted JSON keys, compact comma/colon
separators, no nonfinite numbers and one final LF; byte bounds include that LF.
The report binds expected/initial/final observed inventory digests/held stats,
caller-asserted archive binding, subject descriptor, observed original/copy
identities/digests, generated mappings, source revalidation observations,
output identity, work/byte/memory/time charges and original stage/errno/category.
It never includes its own digest; the outer collector hashes the final bytes.

The terminal diagnostic is one bounded JSON object with kind/version/state,
the first original error record (stage/category/errno/path), a separate later
publication-error record or null, output identity if obtained,
report path/publication outcome, counters and inventory digest if known. It does
not substitute a truncated full path map. A report write/close/publication failure
always keeps the command nonzero and is retained by the outer collector. If no
complete report survives, the full mapping is **unknown**, the existing output
remains in caller custody, and no fictional published report or cleanup success
is reported. A report file bearing COMPLETE alone cannot authorize a build:
require normal zero completion, a complete parse, external report digest and
the immediate independent mapping recheck. A later I/O/close failure overrides
an intended COMPLETE with nonzero completion and the outer PARTIAL diagnostic.
No report transfers ownership, proves process/resource retirement, or releases a
caller lease.


### R2 terminal reservation summary (TT03-MAT-R1-02)

Every terminal diagnostic contains the exact bounded `output_reservation` object
`{state,exclusive_created,identity}`, even before reservation. Its identity must
equal the retained top-level output_identity. The five state rules are exactly
NOT_ATTEMPTED/false/null, KNOWN_EXISTING/false/nullable observed existing-entry
identity, CREATED_VERIFIED/true/original held identity, CREATED_UNOPENED/true/null,
and ATTEMPT_UNCERTAIN/null/null. Existing-entry identity describes what was
observed; it does not establish creation authority. Reserve <=1024 bytes for
this object inside the unchanged 64KiB terminal diagnostic budget.

mkdir success followed by an output-open/fstat failure reports CREATED_UNOPENED;
uncertain mkdir reports ATTEMPT_UNCERTAIN. Both remain PARTIAL with no copied
file or promised report. With no original output authority, report_path is null,
report_publication is NOT_CREATED and publication_error stays null when no
publication operation was attempted. Known EEXIST remains INPUT_REFUSED without
touching that tree. Original error now includes its actual closed `operation`
along with stage/category/errno/path. Preserve the first error and a separately
observed secondary publication error; never encode custody in an error category
or pathname. This summary describes caller parent/entry custody and never grants
cleanup/report/absence authority.

## Separate first-lock bootstrap and immutable later locks

Root first selects/adopts the exact source subset and NEW designs, actual clean
TT03 candidate/base and complete manifest templates. Root owns root Cargo/lock/
policy/notices; no executor improvises them or edits moving BP03 work. Bootstrap
is permitted only once actual reviewed worker/provider/driver/consumer source
exists, in fresh root-owned source-only assemblies. This is explicitly **not**
the delivered materializer and cannot claim archive/installed qualification.

Use three independent source-only assemblies with complete initial lock maps
in `materializer-contract.json:first_lock_bootstrap`. Worker and driver each
contain a whole source testkit copy and both literal generated manifests. Their
selected own lock and the unrelated new worker/driver lock are initially absent.
The unrelated absence is intentional and is not a required seed. The source
testkit crate-root lock is absent too; the reviewed actual candidate workspace
lock is a separately recorded external input. Never substitute it for an own
workspace lock. The consumer source bootstrap uses the final sibling-container
path layout below, but is only a source-layout analog: no actual materialization
report or archive qualification is invented for it.

| Independent assembly | Candidate root lock | Source testkit crate-root lock | Worker own lock | Driver own lock | Consumer own lock | Linux archive-root lock |
|---|---|---|---|---|---|---|
| Worker first-lock assembly | Present external, never seed | Absent source-only dependency | Absent selected generator output | Absent unrelated new workspace | Not in assembly | Not in assembly |
| Driver first-lock assembly | Present external, never seed | Absent source-only dependency | Absent unrelated new workspace | Absent selected generator output | Not in assembly | Not in assembly |
| Consumer first-lock assembly | Present external, never seed | Absent source-only dependency | Absent unrelated new workspace | Absent unrelated new workspace | Absent selected generator output | Present actual archive input, never consumer-own seed |

Container-root Cargo.lock files are absent because those containers have no
Cargo.toml. The complete machine maps enumerate those absences and every own,
candidate-root, source-testkit and Linux role/path separately. No prior probe,
policy-projection, library-root or archive lock supplies a new own lock.

Generation/copy order is exactly ROOT-LOCK binding, worker assembly/own MSRV
generation, driver independent assembly/own MSRV generation, consumer independent
assembly/own MSRV generation, then all six locked metadata graph rows and root
review. A lock generated earlier in another assembly remains absent in the
next independent initial assembly; it is not an implicit seed. All three actual
own first locks and actual graphs must exist before `LOCK-REVIEW-AND-COPY`.
That gate freezes the three unique generator origins, copies worker and driver
bytes into their canonical own paths and corresponding source-copy subpaths,
then consumer-own bytes into its independent source bundle. Root/projection/
Linux lock roles stay separate. The future testkit archive-root lock is recorded
from each actual Cargo-normalized archive later, never substituted as an own
lock. Unexpected presence/absence/hash stops binding for a named C7 decision;
do not delete a lock to fit the map.

All resolver commands use pinned MSRV Cargo 1.88.0, explicit offline config/cache
and the common absolute lease; later graph/build rows use the exact frozen locks
with --locked --offline on both compilers. No new lock is generated by the
delivered materializer, which still requires every declared frozen lock.

After packaging on both selected Cargo versions, the strict delivered route
requires the frozen locks. All subsequent metadata, builds and tests use
`--locked --offline` with those same bytes on both compilers. Recheck locks
before/after metadata and builds. An unexpected package/version/feature/patch/
config/backend is a C7 stop; it is not excused by a successful build.

## Policy and complete finite execution route

The selected policy route is a dedicated TT03 product/policy candidate isolated
from the ongoing BP03 candidate. For six affected testkit archive cells, root
stages an explicitly reviewed one-member testkit workspace/policy projection:
complete exact copied testkit source, explicit root manifest/member set, own
lock/config and the reviewed TT03 pair. The existing helper validates actual
workspace membership; it has no invented member filter. TT01 client source and
historical acceptance remain preserved. The first TT03 client cfg-gates optional
vocabulary and actually exercises the existing API in minimal/default `[]`.
Worker, driver and actual independent Linux consumer are separate from that
shared-union policy workspace. Root later owns canonical policy convergence and
any broader checks caused by changed shared inputs.


The projection's exact member is `crates/scopebase-testkit`, `fixture_members=[]`,
minimal/default `[]` and the sole supported union `["linux-fixtures"]`.
The ordered new pair is `tt03-files-admission` from
`tests/package-policy/fixtures/clients/tt03-files-admission.rs`, then
`tt03-process-phase` from
`tests/package-policy/fixtures/clients/tt03-process-phase.rs`, both defaults off
and explicitly selecting `linux-fixtures` in union mode. Their runtime work is
pure public-value/admission vocabulary; they do not construct a live session or
spawn/build/run workers. The first client's optional vocabulary is cfg-gated,
so minimal/default actually runs accepted default API code with no optional
fixture dependency. The original `tt01-inventory` and `tt01-selection` sources
and accepted receipts remain retained separately, not overwritten or represented
as covered by the new pair. Exact client sources/complete policy/graph/notices
are later mechanical bindings; the existing helper's union clients share one
union workspace/lock and cannot prove independent native consumer usability.

The full dependency-ordered future roster is `materializer-command-dag.json`:
source/admission/fresh assembly → first locks and graph review → source/policy
checks → actual two-Cargo packaging/list/extraction/membership → external
inventory sealing → delivered oracle/materializer controls → fresh strict
materialization → immediate report/tree/lock verification → actual locked
worker/driver/independent-client builds → measured runtime closure/binder →
resource-gated native driver and actual Linux client. The roster supplies exact
command grammars but leaves nonexistent path/hash/resource values mechanically
UNBOUND. It is not an executable packet. Packaging membership and `package
--list` are separate observations. Reached semantic negative/restored twins,
partial/report-write controls and before/after source preservation are mandatory.

Two compilers can consume one COMPLETE tree only while that tree remains under
the same exclusive ownership, all relevant bytes remain identical and targets/
results are disjoint. Every failed or interrupted attempt gets a fresh tree.
Driver/binder/raw-oracle/native cleanup semantics remain r4. Actual Linux client
binds accepted held-file/read/control/parser APIs with independent assertions;
it consumes no speculative LX08 or TT02 prepared-response API. No count of
policy clients, toy package probe, copied tree or dead-caller compile proof
qualifies the new C7 union, a P/F population, full TT03 or installed conformance.

## Delivered independent checker and test CLI

`test_materialize.py` is also the independently authored read-only build gate;
neither mode imports materializer validation/hash/membership code as its oracle.
Its two exact explicit modes are:

```text
python3 ABS/test_materialize.py test
  --package-root ABS/extracted-testkit --inventory ABS/companion.json
  --inventory-sha256 HEX --output ABS/previously-absent-control-root
python3 ABS/test_materialize.py verify
  --package-root ABS/extracted-testkit --inventory ABS/companion.json
  --inventory-sha256 HEX --materialized-root ABS/materialized-root
  --report-sha256 HEX
```

The `test` mode validates its actual delivered subject/input binding, reserves
its own absent output root and runs M01–M18 plus M21/M22 from
materializer-controls.json using controlled copies and in-process calls only.
M19/M20 belong to separate outer Cargo rows; M23 is the separate bootstrap-map authoring check. It retains all partial/failed and
restored-twin trees plus `test-materialize-report.json`; it never edits the
original extracted source. Freeze the expanded invocation/fixture/output map
within <=512 materializer invocations and <=8GiB output, <=15-minute outer wait
and <=512MiB process memory before execution. These are capacity ceilings, not
currently provisioned resources; outer termination leaves an incomplete run.

The `verify` mode accepts only an exact externally hashed COMPLETE report and
independently re-enumerates/re-hashes source, copied entries, directory identities,
the exact two generated manifests and all three lock roles. It checks actual
subject/TOML/path topology, caller inventory anchor and source stability premise,
does not write the source/materialized tree, and executes nothing downstream.
Exit zero and its bounded VERIFIED diagnostic are required immediately before
and after metadata/build commands; REFUSED/nonzero blocks downstream work.
The exact bounded diagnostic fields are in materializer-contract.json. Checker
accounted retained metadata is capped separately at 256 MiB, raw report 16 MiB,
read work 512 MiB, logical steps 1,048,576, held descriptors 32, one cooperative
120 s deadline and outer process allowance 512 MiB. This larger metadata allowance is
explicit because input plus independently parsed complete report/maps coexist;
it is not the copying tool's 64 MiB metadata cap. Measure actual object retention
and RSS for both routes. No checker report is process/resource authority.

## R2 separate consumer container and read-only verification (TT03-MAT-R1-01)

The original sealed materialization root has exactly `subject-testkit/` and
`materialize-report.json`. It is never extended, moved, copied/relabelled or
repackaged for the independent consumer. Reserve a separate fresh sibling:

```text
U/materialized-testkit/{subject-testkit/,materialize-report.json}
U/consumer-assembly/{consumer/,subject-linux/,consumer-assembly-report.json}
```

U is an existing owned stable parent. The consumer's testkit dependency path is
exactly `../../materialized-testkit/subject-testkit`; its Linux dependency stays
`../subject-linux`. The original driver `../../../..` stays unchanged. Check
held identities/ancestry, not only path spelling. Both roots have exact closed
membership; neither has an unknown-sibling exception or symlink bridge.

The existing delivered `test_materialize.py` adds exactly this read-only mode:

```text
python3 ABS/test_materialize.py verify-consumer
  --package-root ABS/extracted-testkit --inventory ABS/testkit-inventory.json
  --inventory-sha256 HEX --materialized-root ABS/U/materialized-testkit
  --report-sha256 HEX --consumer-inventory ABS/consumer-inventory.json
  --consumer-inventory-sha256 HEX --assembly-root ABS/U/consumer-assembly
  --assembly-receipt ABS/U/consumer-assembly/consumer-assembly-report.json
  --assembly-receipt-sha256 HEX --consumer-source-root ABS/consumer-source
  --linux-package-root ABS/extracted-linux
```

All twelve options are mandatory, unique and closed. No extra packaged file,
private checker helper, Cargo/compiler/native/network subprocess, setup effect
or output mutation is introduced. The original four-option materializer and
five-option strict `verify` remain. The externally anchored descriptor/receipt
are caller data; their exact fields/types/predicates are in the existing
`materializer-contract.json:delivery_checker_cli.verify-consumer` object.

The expected consumer inventory binds reviewed real consumer source/manifest/
own lock and actual accepted Linux archive source/normalized manifest/original
manifest/archive lock, plus original materialization source, expected-inventory
digest, externally anchored COMPLETE report and original live root/subject
identities. Source bundle/archive digests remain outer caller assertions; the
checker observes extracted source/copy bytes and held identities. Root first
strict-verifies the original sealed materialization, seals this expected
descriptor outside both roots, then exclusively copies the reviewed consumer
and Linux inputs into the separate assembly and emits its bounded descriptive
receipt. The descriptor does not hash its receipt; the receipt binds descriptor
digest and has no self hash. Its final digest is supplied independently.

`verify-consumer` first performs the complete original strict verification,
including the unchanged exact sealed-root membership. It then checks the
approved source roots and every consumer/Linux source/copy entry, own manifest/
lock, exact directory closure, receipt, dependency path and held identity.
Original live materialized subject identities must match the expected descriptor,
original report and actual held objects together. A report cannot stand in for
a newly copied subject or mint source/control authority. Re-read/rehash and
recheck every relevant source, destination, descriptor and receipt at completion;
repeat immediately before/after actual metadata/build commands under the same
exclusive caller custody. No unobserved ABA/hostile same-user atomicity is claimed.

The whole mode shares one 120-second cooperative deadline, <=512MiB read work,
1,048,576 logical operations, 32 held descriptors, 256MiB accounted retained
metadata and separately bound 512MiB process-memory allowance. Each original
and consumer inventory is <=4MiB; each original report/assembly receipt <=16MiB.
Consumer+Linux entries together are <=8192 files/8192 directories, <=64MiB
source bytes, <=8MiB per file, with 4096-byte paths/64 components and 64KiB
chunks. Limits do not reset after the original strict subcheck. Output is one
<=64KiB diagnostic, VERIFIED/zero only after all predicates; otherwise
REFUSED/nonzero. No filesystem report, owner transfer, resource retirement or
compiled-consumer qualification follows from this read-only mode.

M21 requires a legitimate separate assembly positive, reached extra-member
refusals for both exact roots, and wrong consumer/Linux/manifest/own-lock/
original-subject/forged-receipt negatives after valid setup. A forged receipt
with substituted live IDs cannot override the original expected descriptor and
held objects. M22 requires distinct mkdir-success/open-failure versus uncertain-
mkdir diagnostics when no report exists. M23 preserves the noncircular bootstrap
map/origin boundary; its static traces do not execute a resolver.
