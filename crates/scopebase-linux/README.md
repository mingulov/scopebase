# scopebase-linux

ScopeBase `0.1.0` supplies retained readable regular-file acquisition and descriptor stat observations on Linux. This is the LX02 acquisition increment. Reads, mapping association, process APIs, developer conformance adapters, installed operator clients and supported conformance profiles remain later work.

```rust
use scopebase_linux::file::{HeldFile, ProcFdResolver, SymlinkPolicy};
use std::path::Path;
let resolver = ProcFdResolver::open_self()?;
let held = HeldFile::open(Path::new("input"), &resolver, SymlinkPolicy::Follow)?;
let observation = held.stat()?;
# Ok::<(), scopebase_linux::error::LinuxError>(())
```

`open` first pins an O_PATH descriptor and rejects a nonregular object before a data open. It reopens through a retained validated proc-FD directory, compares both raw device and inode while both descriptors remain live, then retains the readable owner. It never falls back to the original pathname or retries. `RejectFinal` refuses only the final symlink; intermediate symlinks still resolve normally. Raw Unix path bytes must be nonempty, at most 4095 bytes, and contain no NUL. Non-UTF8 paths are supported; kernel component and resolution limits still apply.

`ProcFdResolver::open_self` checks procfs type, canonical own-PID links and resolution of a fresh anonymous pipe created after directory acquisition. It supports ordinary threads sharing the creating process's FD table, with main-thread proc entries available. Recreate after a context transition. Fork-without-exec reuse, private/unshared tables, coherent hostile descriptor/mount substitution and malicious kernels are unsupported. The PID check is defensive. A retained directory remains in use across ordinary replacement of the ambient `/proc` pathname. This check is not universal namespace attestation or a uniqueness guarantee for stat identities.

`HeldFile::from_file` consumes exactly the submitted readable regular `File`. It never dupes, reopens, seeks or changes status flags. Every refusal returns that original owner in `AdoptFileError.file`. Admission establishes CLOEXEC; refusals distinguish a set that was not attempted from Unchanged/CloexecSet/Unknown after one failed-set verification and preserves the primary errno without rollback or retry. Earlier inheritance exposure of a submitted non-CLOEXEC FD is not retroactively removed. Library-created descriptors have atomic CLOEXEC.

Share owners with `Arc`. `AsFd` lends integration access; deliberate close, flag changes and other mutating syscalls through a borrow invalidate affected guarantees. Stat getters describe the held descriptor, including signed seconds, without proving immutable content, mapping identity or an atomic snapshot. Observations cannot construct owners. Debug uses fixed owner/observation labels; error Display and Debug are silent, ASCII and bounded to 256 bytes, with no paths, payload, raw owner fields or source-error text. Opt-in getters expose errno and observations.

Failures report stage/reason, actual primary `io::Error`, operation effects and incurred syscall/FD charges. Successful predicates that later refuse remain charged. Pipe creation counts one syscall and two FDs; PID queries count operations but no explicit syscall. RAII close is excluded. `Complete` cleanup records release of temporary owners, without claiming observed close or backend retirement success. No target content read, mapping, hidden thread, process-global policy change, hard syscall/Drop time or RSS bound is supplied.

From this package source, run `cargo test --lib`, `cargo test --test held_file`, `cargo test --test traits` and `cargo test --doc`. `cargo build --example fd_probe` builds the single-purpose exec/retirement oracle; setting `SCOPEBASE_EXEC_PROBE` to that executable when running `held_file` uses it directly. Without that override, tests run a single selected fixture in a new test process. `tests/ui/cases.json` binds shipped compile-refusal sources to exact diagnostic code/message/primary line, with a positive source first. The ScopeBase SB02 bounded JSON-diagnostic route executes these against the same archived library/features on both selected compilers. Dependency tests do not automatically run from a downstream client's `cargo test`.

Host target: `x86_64-unknown-linux-gnu`; edition 2021; MSRV 1.88.0. Default host features require no BPF, async runtime or native compiler. Additive `process`, `mapping`, `supervision` and `walk` retain package boundaries; these feature names do not implement their future APIs. Rustix 1.1.5 uses only `std`, `fs`, `pipe`. Apache-2.0 project source and explicit third-party options/notices are distinct.

Selected source preservation: P at `2c2713e66292b0d2688508a25f79e813ae823d81`, `crates/manifest/src/identity.rs::open_regular` and `src/discovery/identity.rs::{Pin,pin_of,pin_from_metadata,open_view_object_cached}`; O at `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a`, `src/plan.rs::{PinnedFile,resolve_pinned,resolve_pinned_retry}` and `tests/count_deadline.rs` retention/replacement regressions. Historical source headers were GPL-3.0-or-later. The owner's D03 grant authorizes Apache-2.0 for these selected host adaptations; observed author attribution includes Denis Mingulov and the owner-authorized `osslscope-dev` automation alias. Existing third-party dependency terms remain in the notices. Resolver/adoption/error wrappers are new narrow mechanisms absent from those selected slices.

| Original regression | Preserved acquisition behavior |
| --- | --- |
| P `retained_view_object_open_rejects_a_fifo_without_data_open` | Public FIFO refusal plus private operation-order trace |
| P `retained_mapped_identity_keeps_the_original_file_and_rejects_changes` | Distinct same-bytes inodes, original Arc lifetime and descriptor stat after truncate/replacement; mapping proof remains LX06 |
| O `resolve_pinned_stats_the_open_file` | Independent `MetadataExt` descriptor oracle and missing-input errno |
| O `h4_t1_mid_attach_swap_binds_pinned_inode_via_fd_path` | A barrier confirms B installation before retained reopen; separate complete A→B→A and unlink-before-reopen populations |
| O `h4_t3_pin_survives_path_deletion_until_session_drop` | Unlink retention, Arc sharing and single-purpose exact-slot retirement with a live alias; attachment retirement remains BP04/MG02 |
| O `h4_t2_pin_open_retries_bounded_then_fails` | Its bounded 1/2/3-attempt, last-error retry remains O application policy; ScopeBase makes one attempt and preserves the first errno |

Real host fixtures, model conversion/fault seams, actual compiler diagnostics and later kernel/installed/profile qualification are separate evidence tiers. Acquisition success does not qualify `held-file-v1` or `mapped-image-v1`.
