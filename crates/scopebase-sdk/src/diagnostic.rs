// SPDX-License-Identifier: Apache-2.0
//! Bounded, structured, inert diagnostics (SDK02).
//!
//! A [`Diagnostic`] borrows its input for the call and carries a static
//! code, severity, stage, effect classification, human text and an optional
//! byte path. There is no raw captured-payload field. Retained display is
//! capped at [`MAX_DIAGNOSTIC_BYTES_PER_DIAGNOSTIC`] bytes per diagnostic
//! (text plus escaped-path bytes) and [`MAX_DIAGNOSTIC_AGGREGATE_BYTES`]
//! aggregate bytes by the host profile; the configured count and aggregate
//! allowance bind first when smaller.
//!
//! Every bound is measured before any copy is allocated. The escape
//! measurement advances by whole bytes -- each byte contributes its complete
//! escape -- and stops early once the per-diagnostic cap is exceeded, so
//! arbitrarily long inputs cost bounded scanning work. Diagnostics that
//! exceed a bound, or carry an invalid code, are omitted whole: retained
//! diagnostics are always complete, and the loss is recorded in the
//! saturating [`OmittedDiagnostics`] count rather than disappearing
//! silently. Diagnostics never change admission.

/// Maximum static diagnostic code length in bytes.
pub const MAX_DIAGNOSTIC_CODE_BYTES: usize = 64;
/// Maximum retained display bytes (text plus escaped path) per diagnostic.
pub const MAX_DIAGNOSTIC_BYTES_PER_DIAGNOSTIC: u64 = 4_096;
/// Maximum retained diagnostic display bytes per host context.
pub const MAX_DIAGNOSTIC_AGGREGATE_BYTES: u64 = 65_536;

/// Diagnostic severity. Severity describes; it never upgrades or downgrades
/// the underlying admission verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Severity {
    Note,
    Warning,
    Error,
}

/// Application stage the diagnostic describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Stage {
    Configuration,
    Admission,
    Observation,
    Output,
    Retirement,
}

/// Effect classification carried by the diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EffectState {
    None,
    Partial,
    Unresolved,
}

/// One caller-supplied diagnostic, borrowed for the call. `code` is a static
/// identifier so retained storage never owns unbounded caller strings;
/// `text` is valid UTF-8 retained verbatim; `path` is arbitrary bytes shown
/// only through [`escape_path`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Diagnostic<'a> {
    pub code: &'static str,
    pub severity: Severity,
    pub stage: Stage,
    pub effect: EffectState,
    pub text: &'a str,
    pub path: Option<&'a [u8]>,
}

/// One retained diagnostic with owned display strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedDiagnostic {
    pub code: &'static str,
    pub severity: Severity,
    pub stage: Stage,
    pub effect: EffectState,
    pub text: String,
    pub escaped_path: Option<String>,
}

/// How a [`Diagnostic`] was disposed: retained complete, or omitted whole
/// with the loss counted in [`OmittedDiagnostics`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DiagnosticDisposition {
    Retained,
    Truncated,
}

/// Explicit count of omitted diagnostics. `count` saturates at `u64::MAX`;
/// `at_least` turns true exactly when saturation has hidden further loss, so
/// `at_least == false` always means the count is exact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OmittedDiagnostics {
    pub count: u64,
    pub at_least: bool,
}

impl OmittedDiagnostics {
    /// Record one omission with saturating arithmetic. Stays exact until the
    /// counter itself would wrap, then pins at `u64::MAX` with `at_least`.
    pub(crate) fn record(&mut self) {
        match self.count.checked_add(1) {
            Some(next) => self.count = next,
            None => self.at_least = true,
        }
    }
}

/// Whether `code` is a nonempty ASCII alphanumeric/underscore identifier of
/// at most [`MAX_DIAGNOSTIC_CODE_BYTES`] bytes.
pub(crate) fn valid_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= MAX_DIAGNOSTIC_CODE_BYTES
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Escaped display length of one raw path byte: printable ASCII passes
/// through, backslash/quote and common controls take two-byte escapes, and
/// every other byte takes a four-byte `\xHH` escape.
fn escaped_byte_len(byte: u8) -> u64 {
    match byte {
        b'"' | b'\\' | b'\n' | b'\r' | b'\t' => 2,
        0x20..=0x7e => 1,
        _ => 4,
    }
}

/// Measure escaped path display bytes without allocating, stopping early
/// once `cap` is exceeded. Returns `None` when the escaped length exceeds
/// `cap`; the scan then consumed only the prefix needed for the decision.
fn measured_escaped_len(path: &[u8], cap: u64) -> Option<u64> {
    let mut total: u64 = 0;
    for byte in path.iter().copied() {
        total = total.saturating_add(escaped_byte_len(byte));
        if total > cap {
            return None;
        }
    }
    Some(total)
}

fn push_escaped(output: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    match byte {
        b'"' => output.push_str("\\\""),
        b'\\' => output.push_str("\\\\"),
        b'\n' => output.push_str("\\n"),
        b'\r' => output.push_str("\\r"),
        b'\t' => output.push_str("\\t"),
        0x20..=0x7e => output.push(byte as char),
        _ => {
            output.push_str("\\x");
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
}

/// Deterministic display escaping for arbitrary path bytes. Printable ASCII
/// (except `"` and `\`) passes through; `"`, `\`, newline, carriage return
/// and tab take short escapes; every other byte becomes lowercase `\xHH`.
/// Output is printable ASCII only.
pub(crate) fn escape_path(path: &[u8]) -> String {
    let mut output = String::new();
    for byte in path.iter().copied() {
        push_escaped(&mut output, byte);
    }
    output
}

/// Crate-internal bounded diagnostic store owned by the application context.
/// Count and aggregate checks run before any copy is allocated; refused
/// diagnostics leave retained storage untouched.
#[derive(Clone, Debug)]
pub(crate) struct DiagnosticStore {
    retained: Vec<RetainedDiagnostic>,
    omitted: OmittedDiagnostics,
    used_bytes: u64,
}

impl DiagnosticStore {
    pub(crate) fn new() -> Self {
        DiagnosticStore {
            retained: Vec::new(),
            omitted: OmittedDiagnostics {
                count: 0,
                at_least: false,
            },
            used_bytes: 0,
        }
    }

    pub(crate) fn retained(&self) -> &[RetainedDiagnostic] {
        &self.retained
    }

    pub(crate) fn omitted(&self) -> OmittedDiagnostics {
        self.omitted
    }

    /// Admit `value` within `count_cap` retained diagnostics and the
    /// effective aggregate byte allowance (the smaller of the configured
    /// `byte_cap` and the host aggregate cap), plus the fixed
    /// per-diagnostic cap. Invalid codes and over-cap diagnostics are
    /// omitted whole with [`DiagnosticDisposition::Truncated`]; retained
    /// diagnostics are always complete.
    pub(crate) fn push(
        &mut self,
        count_cap: u32,
        byte_cap: u64,
        value: Diagnostic<'_>,
    ) -> DiagnosticDisposition {
        if !valid_code(value.code) {
            self.omitted.record();
            return DiagnosticDisposition::Truncated;
        }
        if u64::from(count_cap) <= self.retained.len() as u64 {
            self.omitted.record();
            return DiagnosticDisposition::Truncated;
        }
        // Text is valid UTF-8 retained verbatim, so its length is exact
        // without scanning; the path pays escaped display bytes measured
        // before allocation, with early stop past the per-diagnostic cap.
        let text_len = value.text.len() as u64;
        if text_len > MAX_DIAGNOSTIC_BYTES_PER_DIAGNOSTIC {
            self.omitted.record();
            return DiagnosticDisposition::Truncated;
        }
        let path_len = match value.path {
            None => 0,
            Some(path) => {
                match measured_escaped_len(
                    path,
                    MAX_DIAGNOSTIC_BYTES_PER_DIAGNOSTIC.saturating_sub(text_len),
                ) {
                    Some(len) => len,
                    None => {
                        self.omitted.record();
                        return DiagnosticDisposition::Truncated;
                    }
                }
            }
        };
        let cost = text_len.saturating_add(path_len);
        debug_assert!(cost <= MAX_DIAGNOSTIC_BYTES_PER_DIAGNOSTIC);
        let aggregate = byte_cap.min(MAX_DIAGNOSTIC_AGGREGATE_BYTES);
        if self.used_bytes.saturating_add(cost) > aggregate {
            self.omitted.record();
            return DiagnosticDisposition::Truncated;
        }
        let escaped_path = value.path.map(escape_path);
        if let Some(ref escaped) = escaped_path {
            debug_assert_eq!(escaped.len() as u64, path_len);
        }
        self.used_bytes = self.used_bytes.saturating_add(cost);
        self.retained.push(RetainedDiagnostic {
            code: value.code,
            severity: value.severity,
            stage: value.stage,
            effect: value.effect,
            text: value.text.to_owned(),
            escaped_path,
        });
        DiagnosticDisposition::Retained
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_count_saturates_with_at_least_flag() {
        let mut omitted = OmittedDiagnostics {
            count: 41,
            at_least: false,
        };
        omitted.record();
        assert_eq!(
            omitted,
            OmittedDiagnostics {
                count: 42,
                at_least: false,
            }
        );
        let mut omitted = OmittedDiagnostics {
            count: u64::MAX - 1,
            at_least: false,
        };
        omitted.record();
        assert_eq!(omitted.count, u64::MAX);
        assert!(!omitted.at_least, "exact maximum stays exact");
        omitted.record();
        assert_eq!(omitted.count, u64::MAX);
        assert!(omitted.at_least, "hidden loss must set at_least");
        omitted.record();
        assert_eq!(omitted.count, u64::MAX);
        assert!(omitted.at_least, "at_least never clears");
    }

    #[test]
    fn escape_measurement_matches_escaped_copy() {
        // The pre-copy measurement agrees with the allocated escape for a
        // hostile input, and early stop reports over-cap without scanning
        // the tail.
        let hostile: Vec<u8> = (0u8..=255).collect();
        let escaped = escape_path(&hostile);
        assert_eq!(
            measured_escaped_len(&hostile, u64::MAX),
            Some(escaped.len() as u64)
        );
        assert_eq!(measured_escaped_len(&hostile, 10), None);
        assert!(escaped.bytes().all(|b| (0x20..=0x7e).contains(&b)));
    }
}
