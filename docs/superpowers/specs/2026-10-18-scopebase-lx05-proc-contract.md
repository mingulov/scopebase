# ScopeBase LX05 strict bounded proc parser contract

Status: **Normative controller-adopted LX05 contract, 2026-10-18; implementation and qualification are separate.**
Intended canonical destination: `docs/superpowers/specs/2026-10-18-scopebase-lx05-proc-contract.md`.
Historical preparation base: `c0cdbd5f4831e2eb64d19981b72c7ad5d1e31356`; actual dispatch origin is bound separately by root.
This successor applies root's ratified A1–A3 drafting direction to the independently reviewed preparation. This records the controller-adopted contract; the exact source admission and immutable dispatch are separately bound. It is not an implemented API or evidence of passing behavior. The immutable predecessors and unchanged provenance are bound in `.scopebase/controller/lx05-final-packet-20261018/input-bindings.json`; the full verification contract is [verification-plan.md](../plans/2026-10-18-scopebase-lx05-verification.md).

## Scope and provenance

Implement pure descriptive maps and mountinfo parsing in `scopebase-linux` 0.1.0, edition 2021, Rust 1.88.0, x86_64-unknown-linux-gnu. Export it in default `[]` and every existing additive feature configuration. No new runtime dependency or feature; preserve exact rustix 1.1.5 `std,fs,pipe` closure. Parser execution does not call rustix. Procfs 0.18.0 has demonstrated missing raw-byte/refusal/bounds contracts; the accepted comparison is an input, not work to repeat.

ADAPT P maps lexical fields, raw bytes, permission checks, interval validation, exclusive ends and checked offsets. Adapt P probe numeric digit validation, which rejects `+` that Rust integer parsing otherwise accepts. ADAPT P's mount-number/device extraction and its retained-table regression into descriptive table-local lookup. NEW: complete bounded raw mountinfo grammar/escape/optional-field handling, fallible arenas and table-local parse provenance; these are absent from the selected donor mechanism. O parser is reference/counterexample only: its skip-malformed/default-zero/string-normalization behavior is intentionally not imported. No application lookup, ELF, proc read, file resolution, process acquisition, calibration or mapping proof enters LX05.

## Public surface to freeze

All fields below are private except `ParseLimits` fields. No serde, public unchecked/raw constructor, `From<StatFileKey>`, `From<MountDevice>`, owner conversion, public mutation, `Deref`, or implicit allocating Clone. All exposed structs/enums have custom fixed-label Debug, excluding raw bytes/IDs/addresses. Snapshot types are Send + Sync and deliberately not Clone/Eq/Hash. Borrowed views are Copy + Clone; equality exists only where explicitly stated. No public trait or callback is added.

```rust
// scopebase_linux::procfs (unconditionally exported on supported Linux target)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ParseLimits {
    pub max_bytes: usize,
    pub max_entries: usize,
    pub max_line_bytes: usize,
} // no Default; all three fields must be nonzero
pub fn parse_maps(input: &[u8], limits: ParseLimits)
    -> Result<MapsSnapshot, LinuxError>;
pub fn parse_mountinfo(input: &[u8], limits: ParseLimits)
    -> Result<MountTableSnapshot, LinuxError>;

pub struct MapsSnapshot { /* raw Vec<u8>, records Vec<MapRecord>, charges */ }
impl MapsSnapshot {
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn entries(&self) -> impl ExactSizeIterator<Item=MapsEntry<'_>> + DoubleEndedIterator;
    pub fn containing(&self, address: u64) -> Option<MapsEntry<'_>>;
    pub fn charges(&self) -> ParseCharges;
}
pub struct MapsEntry<'a> { /* borrowed validated MapRecord and raw arena */ }
impl<'a> MapsEntry<'a> {
    pub fn start(&self) -> u64;
    pub fn end(&self) -> u64;
    pub fn file_offset(&self) -> u64;
    pub fn file_offset_at(&self, address: u64) -> Option<u64>;
    pub fn permissions(&self) -> [u8; 4];
    pub fn file_key(&self) -> MapsFileKey;
    pub fn raw_path(&self) -> Option<&'a [u8]>;
    pub fn path_kind(&self) -> MapsPathKind;
    pub fn path_evidence(&self) -> MapsPathEvidence;
}
#[non_exhaustive]
pub enum MapsPathKind { Absent, Absolute, Other } // Copy Clone Eq PartialEq
pub struct MapsPathEvidence { /* three independent booleans */ }
impl MapsPathEvidence {
    pub fn has_deleted_suffix(&self) -> bool;
    pub fn has_escaped_newline(&self) -> bool;
    pub fn is_utf8(&self) -> bool;
} // Copy Clone Eq PartialEq

// scopebase_linux::identity; Copy Clone Eq PartialEq, fixed Debug
pub struct MapsFileKey { /* major:u64, minor:u64, inode:u64 */ }
impl MapsFileKey {
    pub fn device_major(&self) -> u64;
    pub fn device_minor(&self) -> u64;
    pub fn inode(&self) -> u64;
}
pub struct MountDevice { /* major:u64, minor:u64 */ }
impl MountDevice {
    pub fn major(&self) -> u64;
    pub fn minor(&self) -> u64;
}

// scopebase_linux::procfs
pub struct MountTableSnapshot {
    /* raw Vec<u8>, decoded Vec<u8>, records Vec<MountRecord>,
       sorted_id_index Vec<(u64,usize)>, charges */
}
impl MountTableSnapshot {
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn entries(&self) -> impl ExactSizeIterator<Item=MountEntry<'_>> + DoubleEndedIterator;
    pub fn entry_by_number(&self, number: u64) -> Option<MountEntry<'_>>;
    pub fn charges(&self) -> ParseCharges;
}
pub struct MountEntry<'a> { /* borrowed table and validated record */ }
impl<'a> MountEntry<'a> {
    pub fn id(&self) -> ParsedMountId<'a>;
    pub fn parent_id(&self) -> ParsedMountId<'a>;
    pub fn device(&self) -> MountDevice;
    pub fn root(&self) -> MountField<'a>;
    pub fn mount_point(&self) -> MountField<'a>;
    pub fn mount_options(&self) -> MountField<'a>;
    pub fn optional_fields(&self) -> impl Iterator<Item=MountOptionalField<'a>>;
    pub fn filesystem_type(&self) -> MountField<'a>;
    pub fn source(&self) -> MountField<'a>;
    pub fn super_options(&self) -> MountField<'a>;
}
pub struct ParsedMountId<'a> { /* &'a MountTableSnapshot, number:u64 */ }
impl ParsedMountId<'_> { pub fn number(&self) -> u64; }
// Copy Clone Eq PartialEq. Equality requires std::ptr::eq(table_a, table_b)
// AND equal numbers. No Ord, Hash, serialization, raw constructor or runtime conversion.
pub struct MountField<'a> { /* raw and decoded borrowed slices */ }
impl<'a> MountField<'a> {
    pub fn raw(&self) -> &'a [u8];
    pub fn decoded(&self) -> &'a [u8];
}
pub struct MountOptionalField<'a> { /* MountField plus validated kind */ }
impl<'a> MountOptionalField<'a> {
    pub fn field(&self) -> MountField<'a>;
    pub fn kind(&self) -> MountOptionalKind;
}
#[non_exhaustive]
pub enum MountOptionalKind {
    Shared(u64), Master(u64), PropagateFrom(u64), Unbindable, Unknown,
} // Copy Clone Eq PartialEq

pub struct ParseCharges { /* values below; Copy Clone Eq PartialEq */ }
impl ParseCharges {
    pub fn input_bytes(&self) -> usize;
    pub fn entries_validated(&self) -> usize;
    pub fn allocation_attempts(&self) -> u64;
    pub fn peak_buffer_capacity_bytes(&self) -> usize;
    pub fn peak_metadata_capacity_bytes(&self) -> usize;
}
// scopebase_linux::error: add implemented variants only
// Stage::{ParseMaps, ParseMounts}; LimitKind::{Entries, LineBytes}
impl ResourceCharges {
    pub fn parse(&self) -> Option<scopebase_linux::procfs::ParseCharges>;
}
impl LinuxError {
    pub fn parse_line(&self) -> Option<usize>; // 1-based source row, never a byte payload
}
```

Use an ordinary internal crate path (`crate::procfs::ParseCharges`) in the actual ResourceCharges definition. `MountField`, `MountOptionalField`, `MapsEntry`, `MountEntry` do not implement Eq/Hash. `MapsPathEvidence` is false/false/true for absent path (empty byte sequence is UTF-8). `MapsFileKey` equality means equal lexical maps tuples only, including inode 0; it never establishes unique physical-file identity. `MountDevice` equality compares mountinfo device components only; no dev_t conversion or maps-device conversion is implemented. Existing StatFileKey remains unchanged.

## Two-argument API and view scoping

`parse_mountinfo(&[u8], ParseLimits)` has no runtime view input and cannot honestly issue a MountViewId or runtime MountId. Its `ParsedMountId<'a>` is explicitly **one table-parse instance provenance**, anchored by a borrow of the immutable snapshot, not a namespace identity, generation, process authority, retained handle, observation interval or unique global ID. The same table object/number compares equal, even when the number is a parent absent from the table. Different snapshot objects compare unequal even for byte-identical input. A snapshot move cannot invalidate a live handle because the handle borrows it; no Clone permits scope duplication. Pointer values are not exposed or serialized. Dropping and reparsing starts a different descriptive scope; this makes no uniqueness claim after all old borrows expire.

`entry_by_number` is explicitly raw lexical lookup in *that table*. A zero/absent number returns None; a malformed table never returns a snapshot. It performs no cross-table or live-view association. `MountId`, `MountViewId`, `ProcViewId`, `UntrustedObservation<T>` and their constructors remain with LX08/LX06; the canonical Linux design keeps those authority-adjacent types with their later owners. LX08 may attach its retained view provenance using crate-private construction at its own reviewed boundary. It must not treat ParsedMountId, pointer identity, a caller chosen number or a matching namespace inode report as authority. Preserve the existing two-argument API; avoid an invented counter/random/hash ID or a caller-supplied view label hidden in ParseLimits.

This preserves the reviewed two-argument/table-instance design as the controller-adopted baseline. A raw-number-only interface would omit the table-scoping regression; a runtime-view argument would break the frozen interface and introduce an LX08 dependency. No architecture choice is delegated to the executor. Root records canonical ratification and the actual dispatch binding separately.

## Input grammar and byte semantics

Common: byte slices are caller-provided complete snapshots. Positive nonzero limits are mandatory; empty bytes is valid absence (zero entries), including empty mountinfo as a descriptive input; that does not assert a live process can have no mounts. Every nonempty input must end in LF. There is no parser truncation flag, partial-success path, lossy decoding or skip-malformed mode. Missing final LF is Malformed even if the last row is otherwise valid; syntactically complete prefixes ending in LF cannot reveal missing later rows and do not certify acquisition completeness. Empty/interior blank/whitespace-only rows are Malformed, not absent. A final LF terminates a row and does not create an extra row. CR is not stripped. NUL anywhere is Malformed. High bytes in pathname/text fields are accepted. Numeric/structural fields are ASCII only. No input is acquired, opened, statted, sorted into a different observation order or implicitly refreshed.

Maps:

- Exactly five structural fields: `start-end perms offset major:minor inode`, then optional remaining raw path. Structural delimiters are one or more SP/HT. Leading SP/HT before the first field is accepted, as in the donor field scanner. After inode, consume the complete SP/HT separator run; the remaining bytes, if any, are raw_path exactly, including internal/trailing spaces, tabs, parentheses, CR and non-UTF8 bytes. Leading filename spaces cannot be distinguished from kernel alignment; no round-trip pathname promise follows.
- Every hex/decimal numeric token is nonempty, has only the selected radix's digits and fits u64 through checked multiply/add. Hex permits a-f/A-F, leading zeroes and no prefix/sign; decimal permits leading zeroes and no prefix/sign. Exactly one `-` in range and one `:` in device. No width, page alignment or machine-pointer-size assumption is imposed on u64 observed addresses/device components.
- Permissions have exactly four bytes: `[r-][w-][x-][ps]`. Refuse invalid length/bytes, empty or reversed intervals (`start >= end`), duplicate starts, descending order and overlap (`previous_end > start`). Adjacent ranges and gaps are valid; end is exclusive. Do not sort input. Check `offset.checked_add(end-start-1)` for **every** row, including anonymous/other path rows, before acceptance; this deliberately strengthens P's absolute-path-only overflow check without weakening any original case. `file_offset_at` returns None outside `[start,end)`, otherwise checked `offset + address-start`. It is descriptive arithmetic, never ELF translation or backing-file resolution.
- Preserve backslashes literally. In particular, do not unescape maps `\012`: a newline-escaped pathname and a literal backslash-plus-012 can be ambiguous. `has_escaped_newline` reports presence of the four-byte marker anywhere. `has_deleted_suffix` reports exact terminal ` (deleted)` bytes, not proven unlink or a stripped filename; literal filenames with that suffix stay ambiguous. `is_utf8` is informational and does not gate acceptance. PathKind is Absent for None, Absolute for a present path starting `/`, Other otherwise, including bracket pseudo-paths and relative-looking text. No PathBuf/openable locator is manufactured; all original unusable cases remain mapping evidence.

Mountinfo:

- Fields are `id parent major:minor root point mount_options [optional ...] - filesystem source super_options`. Tokens are separated by one or more literal SP; leading/trailing SP is refused. Unescaped HT is refused. Require exactly one standalone `-` separator after the six mandatory pre-separator fields, and exactly three nonempty post-separator fields. Missing/extra fixed fields or multiple separators is Malformed. Unknown *optional* fields are accepted/preserved; unknown extra fixed fields are refused. Option comma contents are opaque, with no normalization/sorting/deduplication.
- id and parent are positive decimal u64; mount devices are nonnegative decimal u64 components, not maps hex or encoded stat dev_t. Parent can be absent from this table or equal id; do not infer a complete mount graph/root topology. Duplicate numeric IDs (including alternate leading-zero spellings) refuse the entire table. Preserve input row order; a separate fixed-size ID index supplies duplicate detection and O(log E) lexical lookup.
- In root, point, mount_options, every optional token, filesystem, source and super_options, each backslash must be followed by exactly three octal digits encoding one nonzero byte (octal `001..377`). Decode one escape at a time exactly once. Truncated escapes, non-octal digits, values above `377` and decoded NUL (`000`) are Malformed. Every raw NUL remains Malformed. Consume exactly three digits; a fourth digit is an ordinary following byte. Thus `\134040` decodes to the literal four bytes `\040`, never SP, and `\134043` becomes literal `\043`, never `#`. This accepts syntactically valid descriptive bytes beyond those a particular kernel renderer emits; it does not authenticate kernel output. Validate raw escape spelling before any optional-field interpretation. Preserve both raw and decoded bytes, including non-UTF8. root and point must begin `/` after decoding. Filesystem/source/options must be nonempty; source `none`, `-` within the post-separator source position, and arbitrary opaque nonempty bytes are valid. Separator detection stops at the first standalone delimiter after the six pre-separator fields, then parses exactly three fixed positions. A `-` token in any of those three positions is opaque field data, not another delimiter. An extra fourth post-separator token is malformed. This positional rule replaces a naive count-all-dashes scan.
- Optional known fields are recognized from decoded token bytes: `shared:N`, `master:N`, `propagate_from:N`, `unbindable`, with positive decimal u64 N and no suffix/extra colon. A token starting the exact known key with colon but invalid value is Malformed; `unbindable:value` is malformed. Duplicate recognized kinds per row refuse, regardless of spelling/escape normalization. Distinct known kinds may coexist; no mount policy is inferred from their combination. Unknown tokens are otherwise opaque nonempty decoded byte strings, including non-UTF8, colons and escaped whitespace; retain them in original order and allow duplicate unknown tokens. Do not impose a speculative future tag/key grammar. Exact known-name tokens lacking their required colon/value refuse. Numeric optional IDs occupy their own propagation-group domain and are never ParsedMountId.

## Validation order, allocations, work and errors

Both entry points use the same explicit phases; errors carry Stage::ParseMaps or Stage::ParseMounts throughout, source None, zero attempted/completed operations/syscalls/FDs/mappings, CleanupDisposition::NotNeeded, DescriptorFlagEffect::NotAttempted and `read()==None`. `parse()==Some(ParseCharges)` on every parser failure including invalid configuration. Other existing operations return parse None and parse_line None. `parse_line` is Some(1-based original input row) for row shape/lexical/interval failures, including unterminated within-limit tail; None for limit configuration, total byte/capacity arithmetic/allocation failures where no particular row is responsible. LineBytes/Entries refusals identify the first rejecting row. Duplicate-ID refusal reports the second earliest original input row among rows sharing the lowest numeric ID that occurs more than once. Original row indices are zero-based in the internal index and converted to one-based only for parse_line. All individually valid rows remain counted in entries_validated at this phase. Do not drop the original P line-location diagnostic: `malformed_nonempty_line_is_rejected` must assert parse_line()==Some(1), with a second-row variant asserting Some(2), instead of parsing a string. Default LinuxError Display may include this optional numeric line while keeping its existing bound. No error message includes raw data, address or ID; LinuxError Display/Debug keeps the existing <=256 printable ASCII-byte bound.

1. Validate all three limits nonzero; else InvalidInput, no input scan/allocation. Set `input_bytes` from the slice length, including refused input. Check input.len <= max_bytes next, else LimitExceeded(InputBytes) without inspecting input bytes.
2. Empty input publishes an empty snapshot and zero capacities/attempts; no allocation. Otherwise shape-preflight scans linearly, inspecting at most max_line_bytes+1 bytes before a line-length refusal. For each row check line bytes (excluding LF) against max_line_bytes, then physical row count against max_entries, then reject empty row/NUL; after the final scan require terminal LF. Use checked row-count increments and compare line length before incrementing; never calculate max_line_bytes+1 when it would overflow usize. At the same row a line-size violation precedes entry-count refusal; byte limit and configuration precede both. Shape does not validate token semantics. Overlong final unterminated row returns LineBytes first; a within-limit unterminated row returns Malformed.
3. Let B=input.len and N=preflight row count. Compute requested logical capacities using checked usize arithmetic before any reserve: maps B + N*sizeof(MapRecord); mounts 2*B + N*(sizeof(MountRecord)+sizeof((u64,usize))). Arithmetic overflow => LimitExceeded(BufferCapacity), no allocation. MapRecord fields are start/end/offset:u64, permissions:[u8;4], key:MapsFileKey, raw_path:Option<Range<usize>>. MountRecord fields are id/parent:u64, device:MountDevice, six FieldSpan values, optional_block:Range<usize>; FieldSpan is raw:Range<usize> plus decoded_len:usize. These are private layouts, not repr(C) or stable byte ABI. Metadata formula uses actual size_of on the admitted target.
4. Reserve exactly once per vector with `try_reserve_exact`: raw buffer then records (maps); raw, decoded, records, ID index (mounts). Increment allocation_attempts before each call; failure => Allocation, no retry. Record actual aggregate capacities immediately after each success, including overgrant. If a vector's capacity exceeds its requested B or N, refuse LimitExceeded(BufferCapacity) before the next reservation or copy. This bounds accepted-result logical capacities; allocator overgrant may transiently exceed the request and remains charged. There is no allocator-usable-size, allocator-overhead, RSS, kernel memory or hard transient bound. Private reserve seams inject failure/overgrant only in unit tests, never public allocator callbacks.
5. Copy admitted input once into the preallocated raw arena. For mounts, initialize the decoded arena from raw once; decode each textual token **in place in its original token slot**, store decoded length, leaving unused trailing slot bytes unexposed. Optional fields retain the raw block range; iterator replays already validated token spans without allocation and obtains decoded slices from corresponding slots. Do not allocate a Vec/String per path, token, error or optional field. Filling records/index uses admitted capacity only, never growing collect/HashMap/BTreeMap.
6. Validate rows in input order. Maps row precedence: structural field presence; range syntax/digits/order; permissions; offset; device; inode; NUL/path observation; checked full interval offset; previous-row order/nonoverlap; then publish record and increment entries_validated. Mount row precedence: fixed/separator structure; id; parent; device; root; point; options; optional tokens in order; filesystem/source/super-options; then publish record/index and increment entries_validated. All lexical/numeric/interval/escape/duplicate errors => Malformed, with no invented errno. The preflight phase may therefore precede a lexical error on an earlier row; this is intentional and tested.
7. Mounts sort the preallocated `(u64, usize)` ID index by the complete `(number, original_zero_based_row_index)` tuple using `slice::sort_unstable_by_key`, without reordering records or allocating heap storage. The first adjacent pair with equal numbers determines the error; report the second pair member's original row plus one. Duplicate => Malformed after entries_validated reflects all individually valid rows. Successful raw-number binary lookup compares the numeric component only. The selected standard sorting route has bounded worst-case O(N log N) comparison work, not an exact instruction or elapsed-time ceiling. The wrapper must not replace it with an unbounded collector. Binary search is over this unique index. Maps require no sort.
8. Publish infallibly after validation; return charges. On failure drop all temporary Vecs; no partial snapshot, resource custody or process authority escapes. Buffer/memory charges are historical peaks, never refunded by failure/Drop; entries_validated is the committed valid-row prefix before the rejecting row, or all rows before duplicate-ID rejection. No OperationControl parameter, checkpoint/deadline, background worker, locks, retries, global state, syscall or explicit I/O is introduced. Allocation runtime may itself enter the kernel; zero operational effect counters do not claim zero allocator syscalls.

Work: shape/token/copy/decode processing is O(B), plus O(N log N) mount duplicate/index work; each numeric/escape check advances bounded bytes and no recursive grammar exists. Optional-field count is bounded by raw line bytes; its caller-driven iterator work is outside the parser invocation. Maps containing is O(log N); raw mount lookup O(log N). Repeated user iteration/formatting is caller work. There is no finite wall-clock/CPU-instruction bound promised by these size ceilings. Accepted maps retain <=B buffer bytes and <=N*sizeof(MapRecord) metadata capacity; accepted mounts retain <=2B buffer bytes and <=N*(sizeof(MountRecord)+sizeof(index entry)) metadata capacity. Caller input and fixed stack/header storage are separate and excluded. Reserve-attempt bound is 2/4, zero for absence or shape refusal; no Arc allocation is hidden at publication.
