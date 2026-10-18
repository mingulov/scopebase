# LX02 acquisition preservation map

[Exact source mapping](LX02-source-mapping-20261018.json) binds the four frozen
donor files, narrow source ranges, actual destination hashes and reference-only
contrasts. The original intake remains immutable and says NOT_COPIED; the
separate selected-port receipt records this completed adaptation. Historical
GPL source labels and the author's Apache-2.0 host grant remain distinct.

| Original mechanism or regression | Destination and independent oracle | Reached wrong control | Difference and remaining owner |
|---|---|---|---|
| P `open_regular` type gate; P FIFO regression | `HeldFile::open_with` opens an O_PATH owner, checks regular type, then reopens that held file. A real FIFO without a writer and an operation trace independently establish that no FIFO data-open occurs. | Opening the FIFO for data before type validation fails the intended trace assertion. | Retained proc-fd resolver, context validation, complete device/inode parity and structured errors are package adapters. No global privilege or mount policy is installed. |
| P Pin metadata observations and retained-original/change regression | Private full stat key and `StatObservation`; fixture-owned descriptors, independent MetadataExt and simultaneous equal-byte distinct inodes establish expected identity. | Inode-only/pathname-stat substitutions and the genuine original-owner replacement fail unchanged assertions. | Content-mutation detection and mapping calibration remain LX03/LX06. Original mapping-level assertions are not certified by acquisition tests. |
| O PinnedFile, held-link path and opened-file stat regression | `HeldFile`, descriptor-based reopening and stat; independent open A/B owners, metadata and errno supply truth. | Pathname fallback/stat and conditional fallback after retained-reopen failure fail original-owner assertions. | P's type-before-data-open ordering is retained. The public package exports no durable proc path, mutable/raw owning descriptor or forged observation constructor. |
| O link lifetime/retirement assertion population | Shared owning handles and final-drop tests use exact live descriptor identity and an independent inheritable canary. | Genuine production owner replacement and creation-time CLOEXEC removals fail identity/inheritance assertions. | File descriptor retirement does not prove native BPF link cleanup; BP05 and later adapters retain that obligation. |
| O H4-T1 replacement population | A distinct package barrier test covers A-to-B-to-original-A rename, unlink and accessible replacement B while the retained original stays live. | Reopen-by-path and fallback-on-error mutants retarget and fail the independent A identity/data oracle. | H4-T1 itself is a replacement test, not an original complete ABA test. Attachment firing/retirement remains later BPF and migration work. |

New package contracts additionally cover same-process proc-fd validation, foreign
descriptor-table refusal, fallible File adoption with original ownership
returned, access/CLOEXEC flags, signed timestamps, bounded raw paths, exact
operation/FD charges, symlink policies and printable redacted diagnostics.
Known-bad controls change production behavior while keeping the independent
assertion unchanged. The earlier test-oracle-only early-drop mutation is excluded;
the later genuine owner replacement supplies that sensitivity evidence.

The six review repairs cover imported IntoRawFd trait scope and genuine exposure
mutants; dangling Follow versus RejectFinal; EACCES/ENOENT/EMFILE injected after
accessible replacement B; empty regular, owned FIFO/directory/socket populations;
retained resolver and live O_PATH CLOEXEC across exec; and printable ASCII in
normal/alternate/nested diagnostics. Successful/restored denial tests cover all
three errnos; the fallback mutant stops at the first EACCES assertion. These are
controlled error injections plus real owned files, not a qualified permission
environment. Socket setup failures remain historical failures; the final owned
directory descriptor alias exercises the corrected real socket population.

P `open_view_object_cached` lines 1912–1925, O `resolve_pinned_retry` lines
256–267 and its lines 998–1050 regression, O attachment custody and O product
fixture/installed-at helpers are reference-only. No such code or test body was
copied or adapted. The package's one-attempt/first-error behavior and its model
test are the new ratified package contract; O's retry policy remains local.
The corrected mapping preserves the original overbroad descriptive maps by
hash and explains the classification correction, without changing old evidence.

This increment qualifies neither held-file-v1 nor mapped-image-v1. Full bounded
reads, mapping/content/view relations, real filesystem/namespace cells, retained
attachment custody and installed operator/downstream delivery remain with their
existing LX/BP/TT owners. Donor tests were inspected as source; none was rerun
or relabeled as a passing ScopeBase test by this provenance record.
