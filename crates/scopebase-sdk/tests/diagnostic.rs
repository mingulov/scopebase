// SPDX-License-Identifier: Apache-2.0
//! SDK02 diagnostic tests: per-diagnostic and aggregate byte caps checked
//! before any copy, safe byte-path escaping, static code validation and the
//! saturating omitted count. Diagnostics are inert report metadata: they
//! never move admission and never carry raw captured bytes.

use scopebase_sdk::context::AppContext;
use scopebase_sdk::diagnostic::{
    Diagnostic, DiagnosticDisposition, EffectState, Severity, Stage,
    MAX_DIAGNOSTIC_AGGREGATE_BYTES, MAX_DIAGNOSTIC_BYTES_PER_DIAGNOSTIC,
};
use scopebase_sdk::limits::Limits;
use scopebase_sdk::profile::Profile;
use std::time::Duration;

fn test_limits() -> Limits {
    Limits {
        input_bytes: 1,
        retained_bytes: 1024,
        work_items: 1,
        live_owners: 1,
        diagnostic_count: 128,
        diagnostic_bytes: 65_536,
        wait: Duration::from_millis(1),
    }
}

fn test_context() -> AppContext {
    let profile = Profile::new("diagnostic-test", vec![], vec![]).expect("valid profile");
    AppContext::new(profile, test_limits()).expect("valid context")
}

fn note<'a>(code: &'static str, text: &'a str) -> Diagnostic<'a> {
    Diagnostic {
        code,
        severity: Severity::Note,
        stage: Stage::Observation,
        effect: EffectState::None,
        text,
        path: None,
    }
}

#[test]
fn diagnostic_cap_precedes_copy() {
    assert_eq!(MAX_DIAGNOSTIC_BYTES_PER_DIAGNOSTIC, 4_096);
    assert_eq!(MAX_DIAGNOSTIC_AGGREGATE_BYTES, 65_536);

    // Exactly 4,096 text bytes with no path fit the per-diagnostic cap.
    let mut context = test_context();
    let full = "t".repeat(4_096);
    assert_eq!(
        context.diagnostic(note("EXACT_FIT", &full)),
        DiagnosticDisposition::Retained
    );
    assert_eq!(context.report().diagnostics.len(), 1);
    assert_eq!(context.report().diagnostics[0].text.len(), 4_096);
    assert_eq!(context.report().omitted.count, 0);
    assert!(!context.report().omitted.at_least);

    // One byte more is omitted whole: nothing is retained, the saturating
    // omitted count records the loss explicitly, and the verdict stays put.
    let over = "t".repeat(4_097);
    let admission_before = context.report().admission;
    assert_eq!(
        context.diagnostic(note("ONE_OVER", &over)),
        DiagnosticDisposition::Truncated
    );
    assert_eq!(context.report().diagnostics.len(), 1);
    assert_eq!(context.report().omitted.count, 1);
    assert!(!context.report().omitted.at_least);
    assert_eq!(context.report().admission, admission_before);

    // Text and escaped-path bytes share the per-diagnostic allowance: 4,095
    // text bytes plus a one-byte printable path fit, while 4,096 text bytes
    // plus any path exceed.
    let mut context = test_context();
    let text = "u".repeat(4_095);
    let fitting = Diagnostic {
        path: Some(b"/"),
        ..note("PATH_FIT", &text)
    };
    assert_eq!(context.diagnostic(fitting), DiagnosticDisposition::Retained);
    let text = "u".repeat(4_096);
    let crowded = Diagnostic {
        path: Some(b"/"),
        ..note("PATH_CROWDED", &text)
    };
    assert_eq!(
        context.diagnostic(crowded),
        DiagnosticDisposition::Truncated
    );
    assert_eq!(context.report().diagnostics.len(), 1);
    assert_eq!(context.report().omitted.count, 1);

    // Escaped expansion counts, not raw input length: one 0xFF byte escapes
    // to four display bytes.
    let mut context = test_context();
    let text = "v".repeat(4_092);
    let fits = Diagnostic {
        path: Some(&[0xff]),
        ..note("ESCAPED_FIT", &text)
    };
    assert_eq!(context.diagnostic(fits), DiagnosticDisposition::Retained);
    let text = "v".repeat(4_093);
    let spills = Diagnostic {
        path: Some(&[0xff]),
        ..note("ESCAPED_SPILL", &text)
    };
    assert_eq!(context.diagnostic(spills), DiagnosticDisposition::Truncated);

    // The host aggregate caps retained display bytes at 65,536 even when the
    // configured allowance is larger: sixteen full diagnostics fit, and any
    // further byte is omitted.
    let profile = Profile::new("aggregate", vec![], vec![]).expect("valid profile");
    let mut limits = test_limits();
    limits.diagnostic_count = 64;
    // S217: `usize::MAX as u64` — the largest valid budget on every
    // target (`u64::MAX` fails `usize` validation on 32-bit and
    // panics the `.expect` below). Still far above the 65_536 host
    // aggregate cap, so the host-cap-binds intent is unchanged.
    limits.diagnostic_bytes = usize::MAX as u64;
    let mut context = AppContext::new(profile, limits).expect("valid context");
    let chunk = "a".repeat(4_096);
    for _ in 0..16 {
        assert_eq!(
            context.diagnostic(note("CHUNK", &chunk)),
            DiagnosticDisposition::Retained
        );
    }
    assert_eq!(
        context.diagnostic(note("ONE_MORE_BYTE", "b")),
        DiagnosticDisposition::Truncated
    );
    assert_eq!(context.report().diagnostics.len(), 16);
    assert_eq!(context.report().omitted.count, 1);

    // A configured aggregate smaller than the host cap binds first.
    let profile = Profile::new("configured", vec![], vec![]).expect("valid profile");
    let mut limits = test_limits();
    limits.diagnostic_bytes = 10;
    let mut context = AppContext::new(profile, limits).expect("valid context");
    assert_eq!(
        context.diagnostic(note("SMALL", "0123456789")),
        DiagnosticDisposition::Retained
    );
    assert_eq!(
        context.diagnostic(note("SMALL_TWO", "x")),
        DiagnosticDisposition::Truncated
    );
    assert_eq!(context.report().omitted.count, 1);

    // A configured count smaller than remaining bytes binds first.
    let profile = Profile::new("count", vec![], vec![]).expect("valid profile");
    let mut limits = test_limits();
    limits.diagnostic_count = 2;
    let mut context = AppContext::new(profile, limits).expect("valid context");
    assert_eq!(
        context.diagnostic(note("FIRST", "one")),
        DiagnosticDisposition::Retained
    );
    assert_eq!(
        context.diagnostic(note("SECOND", "two")),
        DiagnosticDisposition::Retained
    );
    assert_eq!(
        context.diagnostic(note("THIRD", "three")),
        DiagnosticDisposition::Truncated
    );
    assert_eq!(context.report().diagnostics.len(), 2);
    assert_eq!(context.report().omitted.count, 1);
}

#[test]
fn weird_path_escapes_without_payload() {
    // Byte paths use deterministic C-style display escaping: printable
    // ASCII passes through, backslash/quote and common controls take short
    // escapes, and every other byte becomes lowercase \xHH. No raw captured
    // byte survives into retained display.
    let cases: &[(&[u8], &str)] = &[
        (b"/owned/run/a", "/owned/run/a"),
        (b"back\\slash", "back\\\\slash"),
        (b"quote\"here", "quote\\\"here"),
        (b"line\nbreak", "line\\nbreak"),
        (b"tab\there", "tab\\there"),
        (b"return\rhere", "return\\rhere"),
        (b"nul\0byte", "nul\\x00byte"),
        (
            b"\x01\x08\x0b\x0c\x0e\x1f",
            "\\x01\\x08\\x0b\\x0c\\x0e\\x1f",
        ),
        (b"\x7f\x80\xff", "\\x7f\\x80\\xff"),
        (b"", ""),
    ];
    for (raw, expected) in cases {
        let mut context = test_context();
        let value = Diagnostic {
            path: Some(raw),
            ..note("PATH_CASE", "text")
        };
        assert_eq!(
            context.diagnostic(value),
            DiagnosticDisposition::Retained,
            "raw path {raw:?} must be retained"
        );
        let retained = &context.report().diagnostics[0];
        assert_eq!(
            retained.escaped_path.as_deref(),
            Some(*expected),
            "raw path {raw:?}"
        );
        // Escaped display is printable ASCII only: nothing above 0x7E and
        // no raw control byte leaks through.
        for byte in retained.escaped_path.as_ref().expect("path").bytes() {
            assert!(
                (0x20..=0x7e).contains(&byte),
                "escaped byte {byte:#x} outside printable ASCII for {raw:?}"
            );
        }
    }

    // Absent paths stay absent rather than becoming empty strings.
    let mut context = test_context();
    assert_eq!(
        context.diagnostic(note("NO_PATH", "text")),
        DiagnosticDisposition::Retained
    );
    assert_eq!(context.report().diagnostics[0].escaped_path, None);

    // Human text is already valid UTF-8, so it is retained verbatim while
    // the sibling path is escaped; the two channels never mix.
    let mut context = test_context();
    let value = Diagnostic {
        path: Some(b"\n"),
        ..note("MIXED", "keep\nnewline")
    };
    assert_eq!(context.diagnostic(value), DiagnosticDisposition::Retained);
    let retained = &context.report().diagnostics[0];
    assert_eq!(retained.text, "keep\nnewline");
    assert_eq!(retained.escaped_path.as_deref(), Some("\\n"));

    // Severity, stage and effect classifications are preserved exactly.
    let mut context = test_context();
    let value = Diagnostic {
        code: "CLASSIFIED",
        severity: Severity::Error,
        stage: Stage::Retirement,
        effect: EffectState::Unresolved,
        text: "classified",
        path: None,
    };
    assert_eq!(context.diagnostic(value), DiagnosticDisposition::Retained);
    let retained = &context.report().diagnostics[0];
    assert_eq!(retained.code, "CLASSIFIED");
    assert_eq!(retained.severity, Severity::Error);
    assert_eq!(retained.stage, Stage::Retirement);
    assert_eq!(retained.effect, EffectState::Unresolved);
}

#[test]
fn diagnostic_codes_are_validated_before_copy() {
    // Static codes are nonempty ASCII alphanumeric/underscore identifiers
    // of at most 64 bytes. Invalid codes are discarded with truncation
    // disposition and an explicit omitted count, never emitted as corrupt
    // framing.
    let valid_64: &'static str = Box::leak("C".repeat(64).into_boxed_str());
    for code in ["A", "warn_1", "X9_", valid_64] {
        let mut context = test_context();
        assert_eq!(
            context.diagnostic(note(code, "ok")),
            DiagnosticDisposition::Retained,
            "code {code:?} must be retained"
        );
        assert_eq!(context.report().diagnostics[0].code, code);
        assert_eq!(context.report().omitted.count, 0);
    }

    let invalid_65: &'static str = Box::leak("D".repeat(65).into_boxed_str());
    for code in [
        "",
        "has space",
        "has-dash",
        "has.dot",
        "unicodé",
        invalid_65,
    ] {
        let mut context = test_context();
        assert_eq!(
            context.diagnostic(note(code, "dropped")),
            DiagnosticDisposition::Truncated,
            "code {code:?} must be discarded"
        );
        assert!(context.report().diagnostics.is_empty());
        assert_eq!(context.report().omitted.count, 1);
    }
}

#[test]
fn diagnostics_never_move_admission() {
    // Even error-severity diagnostics leave the underlying verdict alone:
    // diagnostics describe, they never upgrade or downgrade admission.
    let mut context = test_context();
    let before = context.report().admission;
    let value = Diagnostic {
        code: "LOUD_ERROR",
        severity: Severity::Error,
        stage: Stage::Admission,
        effect: EffectState::Partial,
        text: "loud but inert",
        path: Some(b"\xff"),
    };
    assert_eq!(context.diagnostic(value), DiagnosticDisposition::Retained);
    assert_eq!(
        context.diagnostic(note("SECOND", "also inert")),
        DiagnosticDisposition::Retained
    );
    assert_eq!(context.report().admission, before);
    assert_eq!(context.report().diagnostics.len(), 2);
}

#[test]
fn bad_silent_drop_hides_truncation() {
    // A mutant that drops over-cap diagnostics without counting would leave
    // omitted at zero; the honest count is explicit and exact.
    let mut context = test_context();
    let over = "z".repeat(4_097);
    assert_eq!(
        context.diagnostic(note("OVER", &over)),
        DiagnosticDisposition::Truncated
    );
    assert_eq!(
        context.report().diagnostics.len(),
        0,
        "over-cap diagnostic must not be retained"
    );
    assert_ne!(
        context.report().omitted.count,
        0,
        "omitted count must record the dropped diagnostic"
    );
}

#[test]
fn bad_unescaped_path_leaks_raw_bytes() {
    // A mutant that stores the raw path would retain nonprintable bytes;
    // the honest escaped copy differs and stays printable.
    let mut context = test_context();
    let raw: &[u8] = b"\x00\xff\n";
    let value = Diagnostic {
        path: Some(raw),
        ..note("RAW", "text")
    };
    assert_eq!(context.diagnostic(value), DiagnosticDisposition::Retained);
    let escaped = context.report().diagnostics[0]
        .escaped_path
        .clone()
        .expect("path");
    assert_eq!(escaped, "\\x00\\xff\\n");
    assert_ne!(
        escaped.as_bytes(),
        raw,
        "escaped display must differ from raw bytes"
    );
}
