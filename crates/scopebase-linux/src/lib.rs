// SPDX-License-Identifier: Apache-2.0
//! ScopeBase Linux package boundary (0.1.0).
//!
//! This increment exports no runtime APIs. File, process, mapping, supervision
//! and traversal behavior and all conformance profiles remain unimplemented.
//! The additive features `process`, `mapping`, `supervision` and `walk` reserve
//! boundaries; `mapping` and `supervision` each imply `process`. The default
//! feature set is empty. There are no production or development dependencies.
//!
//! The build target is `x86_64-unknown-linux-gnu`, edition 2021, with prospective
//! MSRV 1.88.0. Compiler checks establish package/import behavior only; other
//! targets and all runtime/kernel capabilities remain unsupported. Builds do not
//! discover BPF tools, install tools or change process-global policy.
//!
//! ```
//! use scopebase_linux as _;
//! ```
//!
//! New user-owned host source uses provisional Apache-2.0 terms. No donor or
//! third-party implementation is bundled in this boundary.

#[cfg(not(target_os = "linux"))]
compile_error!("scopebase-linux requires Linux");
