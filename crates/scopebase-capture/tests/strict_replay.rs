#![cfg(feature = "json")]
// SPDX-License-Identifier: Apache-2.0
//! CP10 strict replay: bounded vectors refuse before promotion.
#[path = "support/cp10_cases.rs"]
mod cases;
use cases::*;
use scopebase_capture::{
    domain::Origin,
    neutral::{NeutralSource, NeutralUnit},
    replay::{
        decode, encode, ReplayDocument, ReplayErrorKind, ReplayLimits, ReplayRecord,
        ReplayTerminal, ReplayValue,
    },
    ContractError,
};

const SCHEMA: &str = "scopebase-capture/replay-v1";

fn counter_record(channel: &str, value: &str) -> String {
    format!(
        "{{\"kind\":\"counter\",\"epoch\":\"0\",\"channel\":{channel},\"policy\":\"monotonic\",\
         \"clock\":\"{CLOCK}\",\"start\":\"0\",\"end\":\"9\",\"value\":{value},\"unit\":\"events\"}}",
        CLOCK = CLOCK_HEX
    )
}

fn terminal_record(counters: &str) -> String {
    format!(
        "{{\"kind\":\"terminal\",\"epoch\":\"0\",\"counters\":{counters},\"loss\":\"0\",\
         \"signals\":\"0\",\"claims\":\"0\",\"partitions\":\"0\",\"corrections\":\"0\"}}"
    )
}

fn doc_str(records: &str) -> String {
    format!(
        "{{\"schema\":\"{SCHEMA}\",\"capture\":\"{CAPTURE_HEX}\",\
         \"producer\":\"{PRODUCER_HEX}\",\"epoch\":\"0\",\"binding\":\"{BINDING_HEX}\",\
         \"origin\":\"synthetic\",\"unit\":\"events\",\"records\":[{records}]}}"
    )
}

fn doc(records: &str) -> Vec<u8> {
    doc_str(records).into_bytes()
}

fn valid_doc() -> Vec<u8> {
    doc(&format!(
        "{},{}",
        counter_record("\"7\"", "\"5\""),
        terminal_record("\"1\"")
    ))
}

fn kind_of(bytes: &[u8]) -> ReplayErrorKind {
    decode(bytes, ReplayLimits::default()).unwrap_err().kind()
}

fn offset_of(bytes: &[u8]) -> usize {
    decode(bytes, ReplayLimits::default()).unwrap_err().offset()
}

#[test]
fn nested_duplicate_members_refuse() {
    for (name, bytes) in [
        (
            "root",
            doc_str(&format!(
                "{},{}",
                counter_record("\"7\"", "\"5\""),
                terminal_record("\"1\"")
            ))
            .replace("\"binding\":\"", "\"binding\":\"00\",\"binding\":\"")
            .into_bytes(),
        ),
        (
            "counter",
            doc(&format!(
                "{},{}",
                counter_record("\"7\"", "\"5\"")
                    .replace("\"channel\"", "\"channel\":\"7\",\"channel\""),
                terminal_record("\"1\"")
            )),
        ),
        (
            "terminal",
            doc(&format!(
                "{},{}",
                counter_record("\"7\"", "\"5\""),
                terminal_record("\"1\"").replace("\"loss\"", "\"loss\":\"0\",\"loss\""),
            )),
        ),
        (
            "escaped-twin",
            doc(&format!(
                "{},{}",
                counter_record("\"7\"", "\"5\"")
                    .replace(",\"value\":\"5\"", ",\"value\":\"5\",\"valu\\u0065\":\"6\""),
                terminal_record("\"1\"")
            )),
        ),
    ] {
        assert_eq!(
            kind_of(&bytes),
            ReplayErrorKind::DuplicateMember,
            "CP10:duplicate member at {name} depth refuses"
        );
        assert_ne!(
            offset_of(&bytes),
            0,
            "CP10:{name} duplicate carries an offset"
        );
    }
}

#[test]
fn bool_nan_and_bad_decimal_refuse() {
    for (name, value, want) in [
        ("bool", "true", ReplayErrorKind::TypeMismatch),
        ("float", "1.5", ReplayErrorKind::TypeMismatch),
        ("null", "null", ReplayErrorKind::TypeMismatch),
        ("bare-int", "5", ReplayErrorKind::TypeMismatch),
        (
            "leading-zero",
            "\"01\"",
            ReplayErrorKind::NonCanonicalNumber,
        ),
        ("plus", "\"+1\"", ReplayErrorKind::NonCanonicalNumber),
        (
            "overflow",
            "\"18446744073709551616\"",
            ReplayErrorKind::NonCanonicalNumber,
        ),
    ] {
        let bytes = doc(&format!(
            "{},{}",
            counter_record("\"7\"", value),
            terminal_record("\"1\"")
        ));
        assert_eq!(kind_of(&bytes), want, "CP10:{name} count refuses");
        assert_ne!(
            offset_of(&bytes),
            0,
            "CP10:{name} refusal carries an offset"
        );
    }
    let bytes = doc_str(&format!(
        "{},{}",
        counter_record("\"7\"", "\"5\""),
        terminal_record("\"1\"")
    ))
    .replace("\"epoch\":\"0\"", "\"epoch\":NaN")
    .into_bytes();
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::Malformed,
        "CP10:NaN is malformed JSON"
    );
    let bytes = doc(&format!(
        "{},{}",
        counter_record("true", "\"5\""),
        terminal_record("\"1\"")
    ));
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::TypeMismatch,
        "CP10:bool channel refuses"
    );
    for (text, want) in [
        ("\"9007199254740993\"", 9_007_199_254_740_993u64),
        ("\"18446744073709551615\"", u64::MAX),
    ] {
        let bytes = doc(&format!(
            "{},{}",
            counter_record("\"7\"", text),
            terminal_record("\"1\"")
        ));
        let document = decode(&bytes, ReplayLimits::default()).unwrap();
        assert_eq!(
            document.validated().counters()[0].value(),
            want,
            "CP10:exact {text} survives replay"
        );
    }
}

#[test]
fn duplicate_missing_or_nonfinal_terminal_refuses() {
    let bytes = doc(&format!(
        "{},{},{}",
        counter_record("\"7\"", "\"5\""),
        terminal_record("\"1\""),
        terminal_record("\"1\"")
    ));
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::TerminalDuplicate,
        "CP10:second terminal refuses"
    );
    let bytes = doc(&counter_record("\"7\"", "\"5\""));
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::TerminalMissing,
        "CP10:missing terminal refuses"
    );
    let bytes = doc(&format!(
        "{},{}",
        terminal_record("\"0\""),
        counter_record("\"7\"", "\"5\"")
    ));
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::TerminalNotFinal,
        "CP10:record after terminal refuses"
    );
    let bytes = doc(&format!(
        "{},{}",
        counter_record("\"7\"", "\"5\""),
        terminal_record("\"2\"")
    ));
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::InventoryMismatch,
        "CP10:terminal inventory must match unique prior records"
    );
    decode(&valid_doc(), ReplayLimits::default()).unwrap();
}

#[test]
fn binding_pins_are_exact_fullmatch() {
    let good = "2".repeat(64);
    for (name, binding, ok) in [
        ("exact", BINDING_HEX.to_string(), true),
        ("all-hex", good, true),
        ("newline-escape", format!("{BINDING_HEX}\\n"), false),
        ("crlf-escape", format!("{BINDING_HEX}\\r\\n"), false),
        ("space", format!("{BINDING_HEX} "), false),
        ("upper", BINDING_HEX.to_uppercase(), false),
        ("short", BINDING_HEX[..63].to_string(), false),
        ("long", format!("{BINDING_HEX}2"), false),
        ("nonhex", format!("{}zz", &BINDING_HEX[..62]), false),
    ] {
        let bytes = doc_str(&format!(
            "{},{}",
            counter_record("\"7\"", "\"5\""),
            terminal_record("\"1\"")
        ))
        .replace(BINDING_HEX, &binding)
        .into_bytes();
        if ok {
            decode(&bytes, ReplayLimits::default())
                .unwrap_or_else(|err| panic!("CP10:{name} pin must parse: {err:?}"));
        } else {
            assert_eq!(
                kind_of(&bytes),
                ReplayErrorKind::TypeMismatch,
                "CP10:{name} binding refuses"
            );
        }
    }
    let bytes = doc_str(&format!(
        "{},{}",
        counter_record("\"7\"", "\"5\""),
        terminal_record("\"1\"")
    ))
    .replace(BINDING_HEX, &format!("{BINDING_HEX}\n"))
    .into_bytes();
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::Malformed,
        "CP10:literal newline inside a string is malformed"
    );
    let zero = "0".repeat(64);
    let bytes = doc_str(&format!(
        "{},{}",
        counter_record("\"7\"", "\"5\""),
        terminal_record("\"1\"")
    ))
    .replace(BINDING_HEX, &zero)
    .into_bytes();
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::Contract(ContractError::InvalidId),
        "CP10:all-zero binding refuses at the constructor"
    );
}

#[test]
fn mixed_epochs_refuse() {
    let bytes = doc(&format!(
        "{},{}",
        counter_record("\"7\"", "\"5\"").replace("\"epoch\":\"0\"", "\"epoch\":\"1\""),
        terminal_record("\"1\"")
    ));
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::EpochMismatch,
        "CP10:mixed epochs refuse"
    );
    decode(&valid_doc(), ReplayLimits::default()).unwrap();
}

#[test]
fn constructors_and_replay_agree() {
    use scopebase_capture::{
        conservation::check_conservation,
        counter::{CounterPolicy, Sample},
        domain::{BindingId, CaptureId, ProducerId, SourceRef},
        loss::{CappedLossSignal, LossFact, LossKind, LossMagnitude},
        quantity::{Count, Events},
        time::{TimeInterval, Timestamp},
    };
    let epoch = scopebase_capture::domain::Epoch::new(
        CaptureId::new(hex_bytes(CAPTURE_HEX)).unwrap(),
        ProducerId::new(hex_bytes(PRODUCER_HEX)).unwrap(),
        0,
    );
    let source = SourceRef::new(
        epoch,
        BindingId::new(hex_bytes(BINDING_HEX)).unwrap(),
        Origin::Synthetic,
    );
    let interval = TimeInterval::new(
        Timestamp::new(
            scopebase_capture::domain::ClockDomain::new(hex_bytes(CLOCK_HEX)).unwrap(),
            0,
        ),
        Timestamp::new(
            scopebase_capture::domain::ClockDomain::new(hex_bytes(CLOCK_HEX)).unwrap(),
            9,
        ),
    )
    .unwrap();
    let direct = Sample::new(
        source.clone(),
        scopebase_capture::domain::ChannelId::new(7),
        CounterPolicy::Monotonic,
        interval.clone(),
        Count::<Events>::new(5),
    );
    assert!(direct.is_ok(), "CP10:direct valid sample");
    let replayed = decode(&valid_doc(), ReplayLimits::default()).unwrap();
    assert_eq!(
        replayed.validated().counters()[0].value(),
        5,
        "CP10:replay agrees on the valid value"
    );
    let direct = Sample::new(
        source.clone(),
        scopebase_capture::domain::ChannelId::new(7),
        CounterPolicy::Saturating { maximum: 4 },
        interval.clone(),
        Count::<Events>::new(5),
    );
    assert_eq!(direct.unwrap_err(), ContractError::InvalidSample);
    let bytes = doc(&format!(
        "{},{}",
        counter_record("\"7\"", "\"5\"").replace(
            "\"policy\":\"monotonic\"",
            "\"policy\":{\"saturating\":\"4\"}"
        ),
        terminal_record("\"1\"")
    ));
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::Contract(ContractError::InvalidSample),
        "CP10:replay refuses the same saturating sample"
    );
    let direct = CappedLossSignal::new(
        source.clone(),
        scopebase_capture::domain::ChannelId::new(2),
        10,
        9,
    );
    assert_eq!(direct.unwrap_err(), ContractError::InvalidSample);
    let bytes = doc(&format!(
        "{{\"kind\":\"signal\",\"epoch\":\"0\",\"channel\":\"2\",\"observed\":\"10\",\
         \"cap\":\"9\",\"unit\":\"diagnostic-signals\"}},{}",
        terminal_record_full(0, 0, 1)
    ));
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::Contract(ContractError::InvalidSample),
        "CP10:replay refuses the same over-cap signal"
    );
    let direct = check_conservation(
        Count::<Events>::new(9),
        &[Count::new(2), Count::new(3), Count::new(5)],
    );
    assert_eq!(direct.unwrap_err(), ContractError::ConservationMismatch);
    let bytes = doc(&format!(
        "{{\"kind\":\"partition\",\"epoch\":\"0\",\"total\":\"9\",\
         \"parts\":[\"2\",\"3\",\"5\"],\"unit\":\"events\"}},{}",
        terminal_record_full(0, 0, 0).replace("\"partitions\":\"0\"", "\"partitions\":\"1\"")
    ));
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::Contract(ContractError::ConservationMismatch),
        "CP10:replay refuses partition 9!=2+3+5"
    );
    let bytes = doc(&format!(
        "{{\"kind\":\"correction\",\"epoch\":\"0\",\"from\":\"0\",\"to\":\"2\"}},{}",
        terminal_record_full(0, 0, 0).replace("\"corrections\":\"0\"", "\"corrections\":\"1\"")
    ));
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::Contract(ContractError::StaleRevision),
        "CP10:replay refuses correction 0->2"
    );
    let fact = LossFact::new(
        source,
        scopebase_capture::domain::ChannelId::new(1),
        LossKind::Transport,
        LossMagnitude::Exact(Count::<Events>::new(0)),
    )
    .unwrap();
    assert!(
        matches!(fact.magnitude(), LossMagnitude::Exact(_)),
        "CP10:direct known-zero loss"
    );
}

fn terminal_record_full(counters: u32, loss: u32, signals: u32) -> String {
    format!(
        "{{\"kind\":\"terminal\",\"epoch\":\"0\",\"counters\":\"{counters}\",\
         \"loss\":\"{loss}\",\"signals\":\"{signals}\",\"claims\":\"0\",\
         \"partitions\":\"0\",\"corrections\":\"0\"}}"
    )
}

#[test]
fn synthetic_origin_cannot_promote_replay() {
    let document = decode(&valid_doc(), ReplayLimits::default()).unwrap();
    assert_eq!(
        document.origin(),
        Origin::Synthetic,
        "CP10:replayed synthetic stays synthetic"
    );
    assert_eq!(
        document.validated().source().origin(),
        Origin::Synthetic,
        "CP10:validated source stays synthetic"
    );
    let bytes = doc_str(&format!(
        "{},{}",
        counter_record("\"7\"", "\"5\""),
        terminal_record("\"1\"")
    ))
    .replace("\"origin\":\"synthetic\",", "")
    .into_bytes();
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::MissingMember,
        "CP10:missing origin refuses instead of defaulting"
    );
    let bytes = doc_str(&format!(
        "{},{}",
        counter_record("\"7\"", "\"5\""),
        terminal_record("\"1\"")
    ))
    .replace("\"origin\":\"synthetic\"", "\"origin\":\"native-truth\"")
    .into_bytes();
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::TypeMismatch,
        "CP10:unknown origin refuses"
    );
}

#[test]
fn record_count_limit_precedes_growth() {
    let mut records = String::new();
    for channel in 0..4096u32 {
        if channel > 0 {
            records.push(',');
        }
        records.push_str(&counter_record(&format!("\"{channel}\""), "\"1\""));
    }
    records.push(',');
    records.push_str(&terminal_record("\"4096\""));
    let bytes = doc(&records);
    decode(&bytes, ReplayLimits::default())
        .expect("CP10:4096 valid records succeed at the maximum");
    let mut records = String::new();
    for channel in 0..4097u32 {
        if channel > 0 {
            records.push(',');
        }
        records.push_str(&counter_record(&format!("\"{channel}\""), "\"1\""));
    }
    records.push(',');
    records.push_str(&terminal_record("\"4097\""));
    let bytes = doc(&records);
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::LimitExceeded,
        "CP10:4097th record refuses before buffer growth"
    );
    let tight = ReplayLimits {
        max_records: 1,
        ..ReplayLimits::default()
    };
    let bytes = doc(&format!(
        "{},{},{}",
        counter_record("\"7\"", "\"1\""),
        counter_record("\"8\"", "\"1\""),
        terminal_record("\"2\"")
    ));
    assert_eq!(
        decode(&bytes, tight).unwrap_err().kind(),
        ReplayErrorKind::LimitExceeded,
        "CP10:caller record limit refuses"
    );
    assert_eq!(
        ReplayLimits::default(),
        ReplayLimits {
            max_bytes: 1_048_576,
            max_records: 4096,
            max_nesting: 16,
            max_items: 4096,
            max_string: 256,
        },
        "CP10:installed replay limits"
    );
}

#[test]
fn replay_document_constructor_agrees_with_decode() {
    let source: NeutralSource = neutral_source();
    let record = ReplayRecord::new(
        "counter",
        0,
        vec![
            ("kind".to_string(), ReplayValue::Text("counter".to_string())),
            ("epoch".to_string(), ReplayValue::Text("0".to_string())),
            ("channel".to_string(), ReplayValue::Text("7".to_string())),
            (
                "policy".to_string(),
                ReplayValue::Text("monotonic".to_string()),
            ),
            (
                "clock".to_string(),
                ReplayValue::Text(CLOCK_HEX.to_string()),
            ),
            ("start".to_string(), ReplayValue::Text("0".to_string())),
            ("end".to_string(), ReplayValue::Text("9".to_string())),
            ("value".to_string(), ReplayValue::Text("5".to_string())),
            ("unit".to_string(), ReplayValue::Text("events".to_string())),
        ],
    );
    let terminal = ReplayTerminal::new(0, 1, 0, 0, 0, 0, 0);
    let built = ReplayDocument::new(source, NeutralUnit::Events, vec![record], terminal).unwrap();
    let decoded = decode(&valid_doc(), ReplayLimits::default()).unwrap();
    assert_eq!(
        built.records(),
        decoded.records(),
        "CP10:constructed and decoded records agree"
    );
    assert_eq!(built.binding(), decoded.binding(), "CP10:bindings agree");
    assert_eq!(built.origin(), decoded.origin(), "CP10:origins agree");
    let bad = ReplayRecord::new("counter", 1, Vec::new());
    let terminal = ReplayTerminal::new(0, 1, 0, 0, 0, 0, 0);
    assert_eq!(
        ReplayDocument::new(neutral_source(), NeutralUnit::Events, vec![bad], terminal)
            .unwrap_err()
            .kind(),
        ReplayErrorKind::EpochMismatch,
        "CP10:constructor refuses mixed epochs"
    );
}

#[test]
fn schema_and_shape_refusals_are_typed() {
    let bytes = doc_str(&format!(
        "{},{}",
        counter_record("\"7\"", "\"5\""),
        terminal_record("\"1\"")
    ))
    .replace(SCHEMA, "scopebase-capture/replay-v2")
    .into_bytes();
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::Contract(ContractError::IncompatibleVersion),
        "CP10:wrong schema refuses as incompatible"
    );
    let bytes = doc(&format!(
        "{},{}",
        counter_record("\"7\"", "\"5\"").replace("\"kind\":\"counter\"", "\"kind\":\"needle\""),
        terminal_record("\"1\"")
    ));
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::UnknownKind,
        "CP10:unknown record kind refuses"
    );
    let bytes = doc(&format!(
        "{},{}",
        counter_record("\"7\"", "\"5\"").replace("}", ",\"extra\":\"1\"}"),
        terminal_record("\"1\"")
    ));
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::UnknownMember,
        "CP10:unknown member refuses"
    );
    let bytes = doc(&format!(
        "{},{}",
        counter_record("\"7\"", "\"5\"").replace(",\"value\":\"5\"", ""),
        terminal_record("\"1\"")
    ));
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::MissingMember,
        "CP10:missing member refuses instead of defaulting"
    );
    let bytes = b"[".to_vec();
    assert_eq!(
        kind_of(&bytes),
        ReplayErrorKind::Malformed,
        "CP10:truncated input is malformed"
    );
    let big = vec![b' '; 1_048_577];
    assert_eq!(
        kind_of(&big),
        ReplayErrorKind::TooLarge,
        "CP10:oversize input refuses before parsing"
    );
    let deep = format!("{{\"a\":{}}}", "[".repeat(17) + &"]".repeat(17));
    assert_eq!(
        kind_of(deep.as_bytes()),
        ReplayErrorKind::TooDeep,
        "CP10:over-deep nesting refuses"
    );
    let long = format!("{{\"a\":\"{}\"}}", "x".repeat(257));
    assert_eq!(
        kind_of(long.as_bytes()),
        ReplayErrorKind::StringTooLong,
        "CP10:over-long string refuses"
    );
    let tight = ReplayLimits {
        max_items: 2,
        ..ReplayLimits::default()
    };
    assert_eq!(
        decode(&valid_doc(), tight).unwrap_err().kind(),
        ReplayErrorKind::TooManyItems,
        "CP10:object breadth uses max_items"
    );
    let wide = "[".repeat(3) + &"]".repeat(3);
    let bytes = format!("{{\"a\":{wide},\"b\":1,\"c\":2}}");
    assert_eq!(
        decode(bytes.as_bytes(), tight).unwrap_err().kind(),
        ReplayErrorKind::TooManyItems,
        "CP10:small-object breadth uses max_items"
    );
    let reasons: Vec<ReplayValue> = (0..4097)
        .map(|_| ReplayValue::Text("capacity".to_string()))
        .collect();
    let record = ReplayRecord::new(
        "claim",
        0,
        vec![
            ("kind".to_string(), ReplayValue::Text("claim".to_string())),
            ("epoch".to_string(), ReplayValue::Text("0".to_string())),
            ("claim".to_string(), ReplayValue::Text("3".to_string())),
            ("reasons".to_string(), ReplayValue::Array(reasons)),
        ],
    );
    let terminal = ReplayTerminal::new(0, 0, 0, 0, 1, 0, 0);
    assert_eq!(
        ReplayDocument::new(
            neutral_source(),
            NeutralUnit::Events,
            vec![record],
            terminal
        )
        .unwrap_err()
        .kind(),
        ReplayErrorKind::TooManyItems,
        "CP10:semantic collections use max_items before growth"
    );
}

#[test]
fn every_truncation_boundary_of_small_vectors_refuses() {
    for vector in small_valid_vectors() {
        assert!(
            decode(&vector, ReplayLimits::default()).is_ok(),
            "CP10:full small vector is accepted"
        );
        for end in 0..vector.len() {
            assert!(
                decode(&vector[..end], ReplayLimits::default()).is_err(),
                "CP10:truncation at {end}/{} refuses",
                vector.len()
            );
        }
    }
}

fn small_valid_vectors() -> Vec<Vec<u8>> {
    vec![
        valid_doc(),
        doc(&terminal_record("\"0\"")),
        doc(&format!(
            "{{\"kind\":\"loss\",\"epoch\":\"0\",\"channel\":\"1\",\
             \"loss-kind\":\"transport\",\"magnitude\":\"unknown\",\"unit\":\"events\"}},{}",
            terminal_record_full(0, 1, 0)
        )),
    ]
}

#[test]
fn fixture_vectors_match_hand_authored_expectations() {
    use std::path::Path;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/capture/replay-v1");
    let vectors = std::fs::read_to_string(root.join("vectors.jsonl")).unwrap();
    let expected = std::fs::read_to_string(root.join("expected.jsonl")).unwrap();
    let vectors: Vec<&str> = vectors.lines().collect();
    let expected: Vec<&str> = expected.lines().collect();
    assert_eq!(
        vectors.len(),
        expected.len(),
        "CP10:vectors and expectations correlate by line"
    );
    assert!(!vectors.is_empty(), "CP10:fixture corpus is nonempty");
    for (index, (vector, want)) in vectors.iter().zip(expected.iter()).enumerate() {
        let outcome = decode(vector.as_bytes(), ReplayLimits::default());
        if let Some(rest) = want.strip_prefix("{\"expect\":\"accept\"") {
            let document = outcome.unwrap_or_else(|err| {
                panic!("CP10:fixture line {} must accept: {err:?}", index + 1)
            });
            if let Some(count) = rest.strip_prefix(",\"records\":") {
                let count: usize = count
                    .trim_end_matches('}')
                    .parse()
                    .expect("CP10:fixture record count");
                assert_eq!(
                    document.records().len(),
                    count,
                    "CP10:fixture line {} record count",
                    index + 1
                );
            }
            let canonical = encode(&document).unwrap();
            let reparsed = decode(&canonical, ReplayLimits::default()).unwrap();
            assert_eq!(
                reparsed.records(),
                document.records(),
                "CP10:fixture line {} reparse agrees",
                index + 1
            );
        } else if let Some(kind) = want
            .strip_prefix("{\"expect\":\"refuse\",\"kind\":\"")
            .and_then(|rest| rest.strip_suffix("\"}"))
        {
            let Err(err) = outcome else {
                panic!("CP10:fixture line {} must refuse as {kind}", index + 1)
            };
            assert_eq!(
                format!("{:?}", err.kind()),
                kind,
                "CP10:fixture line {} refusal kind",
                index + 1
            );
        } else {
            panic!("CP10:fixture line {} has unknown expectation", index + 1);
        }
    }
}

#[test]
fn encode_is_canonical_over_hand_authored_bytes() {
    let document = decode(&valid_doc(), ReplayLimits::default()).unwrap();
    let canonical = encode(&document).unwrap();
    let expected = format!(
        "{{\"schema\":\"{SCHEMA}\",\"capture\":\"{CAPTURE_HEX}\",\
         \"producer\":\"{PRODUCER_HEX}\",\"epoch\":\"0\",\"binding\":\"{BINDING_HEX}\",\
         \"origin\":\"synthetic\",\"unit\":\"events\",\"records\":[{},{}]}}",
        counter_record_canonical(),
        terminal_record_canonical()
    );
    assert_eq!(
        String::from_utf8(canonical).unwrap(),
        expected.replace(char::is_whitespace, ""),
        "CP10:canonical encoding matches hand-authored bytes"
    );
}

fn counter_record_canonical() -> String {
    format!(
        "{{\"kind\":\"counter\",\"epoch\":\"0\",\"channel\":\"7\",\"policy\":\"monotonic\",\
         \"clock\":\"{CLOCK_HEX}\",\"start\":\"0\",\"end\":\"9\",\"value\":\"5\",\
         \"unit\":\"events\"}}"
    )
    .replace(char::is_whitespace, "")
}

fn terminal_record_canonical() -> String {
    "{\"kind\":\"terminal\",\"epoch\":\"0\",\"counters\":\"1\",\"loss\":\"0\",\
     \"signals\":\"0\",\"claims\":\"0\",\"partitions\":\"0\",\"corrections\":\"0\"}"
        .replace(char::is_whitespace, "")
}

#[test]
fn cp10_control_script_passes() {
    let helper = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/support/check_cp10_controls.py");
    let status = std::process::Command::new("python3")
        .arg("-I")
        .arg(&helper)
        .arg(env!("CARGO_MANIFEST_DIR"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .status()
        .expect("CP10:control script must run");
    assert!(status.success(), "CP10:control script passes");
}

#[test]
fn library_calls_emit_no_output_in_owned_subprocess() {
    // Behavioral silence probe: re-run the silent API exercise below with
    // unbuffered harness output and require only harness framing on stdout
    // and nothing on stderr.
    if std::env::var("CP10_SILENCE_PROBE").is_ok() {
        exercise_silent_apis();
        return;
    }
    let exe = std::env::current_exe().expect("CP10:own test binary");
    let output = std::process::Command::new(exe)
        .arg("--exact")
        .arg("library_calls_emit_no_output_in_owned_subprocess")
        .arg("--nocapture")
        .env("CP10_SILENCE_PROBE", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("CP10:owned subprocess must run");
    assert!(output.status.success(), "CP10:probe subprocess passes");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        assert!(
            trimmed.is_empty() || trimmed.starts_with("running") || trimmed.starts_with("test "),
            "CP10:unexpected subprocess stdout: {trimmed:?}"
        );
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.trim().is_empty(), "CP10:stderr stays empty");
}

fn exercise_silent_apis() {
    let document = decode(&valid_doc(), ReplayLimits::default()).unwrap();
    let _ = encode(&document).unwrap();
    let _ = kind_of(b"");
    let source = neutral_source();
    let _ = ReplayDocument::new(
        source,
        NeutralUnit::Events,
        Vec::new(),
        ReplayTerminal::new(0, 0, 0, 0, 0, 0, 0),
    )
    .unwrap();
}
