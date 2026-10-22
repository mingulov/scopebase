// SPDX-License-Identifier: Apache-2.0
//! Retained file acquisition, bounded positional reads and cooperative controls.
//!
//! Descriptor observations and read results do not prove immutable snapshots.
//! Mappings, processes and conformance profiles remain later work. Host target
//! x86_64-unknown-linux-gnu, edition 2021, MSRV 1.88.0. No BPF tools or implicit
//! policy changes are required.
//!
//! ```
//! use scopebase_linux::file::ProcFdResolver;
//! let resolver = ProcFdResolver::open_self()?;
//! # Ok::<(), scopebase_linux::error::LinuxError>(())
//! ```
#[cfg(not(target_os = "linux"))]
compile_error!("scopebase-linux requires Linux");
pub mod control;
pub mod error;
/// Retained file authority and bounded positional reads with observation-only results.
pub mod file;
pub mod identity;
pub mod procfs;

// Unit fixtures which inspect retired numeric slots must coordinate every
// competing descriptor allocation in this test process. This is not runtime
// library state; subprocesses exec a fresh test executable before taking it.
#[cfg(test)]
pub(crate) static FD_TABLE: std::sync::Mutex<()> = std::sync::Mutex::new(());
