// SPDX-License-Identifier: Apache-2.0
//! First-party CLI boundary: native argv admission and fallible output.
//!
//! Every shipped binary (reference consumers, the conformance operator,
//! test-subject bins) enters through here so the two classic process
//! boundary panics cannot recur:
//!
//! - R03: `std::env::args()` panics when argv holds non-UTF-8 bytes.
//!   [`argv_strings`] collects `args_os` and refuses with `None`
//!   instead; binaries map that to a usage error (exit 2), never a
//!   panic. (Native paths stay native up to this refusal: no lossy
//!   conversion invents a different path.)
//! - R04: `println!`/`eprintln!` panic when the stream fails
//!   (`/dev/full`, a closed pipe). [`put_line`]/[`err_line`] report
//!   success so the caller picks the exit code; a reporting failure
//!   never triggers another report.
//!
//! NEW (R03/R04 follow-up): no donor lines copied.

use std::ffi::OsString;
use std::io::Write;

/// Collect native argv as Unicode strings. `None` when any argument
/// (including argv[0]) is not valid Unicode: the caller must refuse
/// with usage, never panic and never lossy-convert a path.
pub fn argv_strings() -> Option<Vec<String>> {
    argv_strings_from(std::env::args_os())
}

/// Testable core of [`argv_strings`] over an explicit argument source.
pub fn argv_strings_from(args: impl Iterator<Item = OsString>) -> Option<Vec<String>> {
    args.map(|arg| arg.into_string().ok()).collect()
}

/// Write one line plus `\n` to stdout. `false` when the write or
/// flush fails: the caller turns that into its IO-failure exit code.
/// Never panics: locking stdio cannot poison from this crate (no
/// panics happen under the guard) and every IO error maps to `false`.
pub fn put_line(line: &str) -> bool {
    write_line_to(std::io::stdout().lock(), line)
}

/// Write one line plus `\n` to stderr. `false` when the write fails;
/// the caller must exit with its already-determined code and attempt
/// no further report (a reporting failure never triggers another).
pub fn err_line(line: &str) -> bool {
    write_line_to(std::io::stderr().lock(), line)
}

fn write_line_to(mut sink: impl Write, line: &str) -> bool {
    sink.write_all(line.as_bytes())
        .and_then(|()| sink.write_all(b"\n"))
        .and_then(|()| sink.flush())
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    fn os(bytes: &[u8]) -> OsString {
        OsString::from_vec(bytes.to_vec())
    }

    /// R03: native argv round-trips; any non-UTF-8 argument refuses
    /// the whole vector (no lossy path invention, no panic).
    #[test]
    fn argv_admission_is_all_or_nothing_unicode() {
        let good = vec![os(b"bin"), os(b"inspect"), os(b"/tmp/plain")];
        assert_eq!(
            argv_strings_from(good.into_iter()),
            Some(vec![
                "bin".to_string(),
                "inspect".to_string(),
                "/tmp/plain".to_string()
            ])
        );
        assert_eq!(
            argv_strings_from(vec![os(b"bin")].into_iter())
                .unwrap()
                .len(),
            1
        );
        assert_eq!(argv_strings_from(Vec::new().into_iter()), Some(vec![]));
        let bad = vec![os(b"bin"), os(b"/tmp/\xff\xfe")];
        assert_eq!(argv_strings_from(bad.into_iter()), None);
        // A bad argv[0] alone refuses too.
        let bad_zero = vec![os(b"\xff"), os(b"ok")];
        assert_eq!(argv_strings_from(bad_zero.into_iter()), None);
    }

    struct FailWrites;

    impl Write for FailWrites {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("scripted output failure"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("scripted flush failure"))
        }
    }

    struct FailFlushOnly {
        pub bytes: Vec<u8>,
    }

    impl Write for FailFlushOnly {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("scripted flush failure"))
        }
    }

    /// R04: the line writer reports every failure mode instead of
    /// panicking, and a flush failure fails even when the bytes
    /// landed (no silent truncation success).
    #[test]
    fn line_writer_reports_write_and_flush_failures() {
        let mut ok = Vec::new();
        assert!(write_line_to(&mut ok, "hello"));
        assert_eq!(ok, b"hello\n");
        assert!(!write_line_to(FailWrites, "hello"));
        let mut flush_fail = FailFlushOnly { bytes: Vec::new() };
        assert!(!write_line_to(&mut flush_fail, "hello"));
        assert_eq!(flush_fail.bytes, b"hello\n");
    }
}
