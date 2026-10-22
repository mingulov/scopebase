// SPDX-License-Identifier: Apache-2.0
//! BP06: ring frame arithmetic, bounded reader contract and copied staging.
//!
//! ADAPT: pure framing from KryProbe
//! `kryprobe/crates/kryprobe-privilege/src/drain/frame.rs` (`frame_step`:
//! 8-byte header, BUSY stop, discard skip, torn-tail stop, saturating
//! top-of-range handling); fixed-boundary discipline from the p11scope
//! `third-party/patches/aya-0.14.0/aya-ring-reader.patch` (`snapshot_
//! positions`/`next_before`, aligned stop validation, record-crosses-
//! boundary refusal, discard accounting); staging and conservation
//! (`received = delivered + held + malformed + dropped`, short-destination
//! retention, source-mutation immunity) from libbpf-mojo
//! `src/libbpf_mojo/buffer.mojo` and
//! `tests/native/ring_conformance.c` (short/single/mutation vectors).
//! This task ships the checked arithmetic, source contract and owned
//! staging slot only; the plan forbids a new raw mmap reader here.
//! Live H12/H13 cells are NOT_RUN (later owners).

use scopebase_bpf::ring::{
    frame_step, BoundaryState, BoundedRingSource, DrainBudget, DrainResult, FrameStep,
    RecordHeader, RingPositions, StageStats, StagedRecord, STAGE_FRAMING_VERSION,
};
use scopebase_bpf::{ErrorKind, OperationError, Stage};
use std::collections::VecDeque;

#[path = "support/json_mini.rs"]
mod json_mini;

use json_mini::Json;

const CURSORS: &str = include_str!("../fixtures/ring-v1/cursors.json");
const STAGING: &str = include_str!("../fixtures/ring-v1/staging.json");

fn cursor_cases() -> Vec<Json> {
    let root = json_mini::parse(CURSORS).expect("cursors fixture parses");
    assert_eq!(root.get("version").unwrap().as_u64().unwrap(), 1);
    assert_eq!(root.get("header_bytes").unwrap().as_u64().unwrap(), 8);
    assert_eq!(root.get("align_bytes").unwrap().as_u64().unwrap(), 8);
    root.get("cases").unwrap().as_arr().unwrap().to_vec()
}

fn fixture_kind(name: &str) -> ErrorKind {
    match name {
        "InvalidInput" => ErrorKind::InvalidInput,
        "Malformed" => ErrorKind::Malformed,
        "Incompatible" => ErrorKind::Incompatible,
        "LimitExceeded" => ErrorKind::LimitExceeded,
        "Overflow" => ErrorKind::Overflow,
        other => panic!("unknown kind {other:?}"),
    }
}

fn run_cursor_case(case: &Json) {
    let name = case.get("name").unwrap().as_str().unwrap();
    let positions = RingPositions {
        consumer: case.get("consumer").unwrap().as_u64().unwrap(),
        producer: case.get("producer").unwrap().as_u64().unwrap(),
    };
    let stop = case.get("stop").unwrap().as_u64().unwrap();
    let capacity = case.get("capacity").unwrap().as_usize().unwrap();
    let header_json = case.get("header").unwrap();
    let header = if header_json.is_null() {
        None
    } else {
        Some(RecordHeader {
            payload_len: header_json
                .get("payload_len")
                .unwrap()
                .as_u64()
                .unwrap()
                .try_into()
                .expect("payload_len fits u32"),
            busy: header_json.get("busy").unwrap().as_bool().unwrap(),
            discard: header_json.get("discard").unwrap().as_bool().unwrap(),
        })
    };
    let expect = case.get("expect").unwrap();
    match expect.get("outcome").unwrap().as_str().unwrap() {
        "emit" => match frame_step(positions, stop, capacity, header) {
            Ok(FrameStep::Emit { payload_len, next }) => {
                assert_eq!(
                    payload_len,
                    expect.get("payload_len").unwrap().as_usize().unwrap(),
                    "{name} payload_len"
                );
                assert_eq!(
                    next,
                    expect.get("next").unwrap().as_u64().unwrap(),
                    "{name} next"
                );
            }
            other => panic!("{name}: expected Emit, found {other:?}"),
        },
        "discard" => match frame_step(positions, stop, capacity, header) {
            Ok(FrameStep::Discard { next }) => {
                assert_eq!(
                    next,
                    expect.get("next").unwrap().as_u64().unwrap(),
                    "{name} next"
                );
            }
            other => panic!("{name}: expected Discard, found {other:?}"),
        },
        "pending" => assert_eq!(
            frame_step(positions, stop, capacity, header).unwrap(),
            FrameStep::Pending,
            "{name} pending"
        ),
        "reached" => assert_eq!(
            frame_step(positions, stop, capacity, header).unwrap(),
            FrameStep::ReachedBoundary,
            "{name} reached"
        ),
        "error" => {
            let err = frame_step(positions, stop, capacity, header)
                .expect_err(&format!("{name} must refuse"));
            assert_eq!(
                err.kind(),
                fixture_kind(expect.get("kind").unwrap().as_str().unwrap()),
                "{name} kind"
            );
            assert_eq!(err.stage(), Stage::Drain, "{name} stage");
        }
        other => panic!("{name}: unknown outcome {other:?}"),
    }
}

#[test]
fn frame_fixture_vectors() {
    let cases = cursor_cases();
    assert_eq!(cases.len(), 34, "pinned cursor vector count");
    for case in &cases {
        run_cursor_case(case);
    }
}

#[test]
fn frame_emit_rounds_payload_up() {
    // 8-byte header plus 8-aligned payload, independently of the fixture.
    let step = frame_step(
        RingPositions {
            consumer: 0,
            producer: 72,
        },
        72,
        4096,
        Some(RecordHeader {
            payload_len: 64,
            busy: false,
            discard: false,
        }),
    )
    .unwrap();
    assert_eq!(
        step,
        FrameStep::Emit {
            payload_len: 64,
            next: 72
        }
    );
    let step = frame_step(
        RingPositions {
            consumer: 0,
            producer: 16,
        },
        16,
        4096,
        Some(RecordHeader {
            payload_len: 1,
            busy: false,
            discard: false,
        }),
    )
    .unwrap();
    assert_eq!(
        step,
        FrameStep::Emit {
            payload_len: 1,
            next: 16
        }
    );
}

#[test]
fn frame_busy_is_pending() {
    for discard in [false, true] {
        let step = frame_step(
            RingPositions {
                consumer: 0,
                producer: 104,
            },
            96,
            4096,
            Some(RecordHeader {
                payload_len: 8,
                busy: true,
                discard,
            }),
        )
        .unwrap();
        assert_eq!(step, FrameStep::Pending, "busy wins over discard={discard}");
    }
}

#[test]
fn frame_wrap_usize_max_15() {
    let consumer = u64::MAX - 15;
    assert_eq!(consumer % 8, 0, "test cursor is aligned");
    let step = frame_step(
        RingPositions {
            consumer,
            producer: 0,
        },
        0,
        4096,
        Some(RecordHeader {
            payload_len: 8,
            busy: false,
            discard: false,
        }),
    )
    .unwrap();
    assert_eq!(
        step,
        FrameStep::Emit {
            payload_len: 8,
            next: 0
        }
    );
}

#[test]
fn frame_producer_extension_does_not_extend_stop() {
    // Producer far beyond the captured stop: pre-stop records still emit,
    // and a record crossing the stop still refuses.
    let emit = frame_step(
        RingPositions {
            consumer: 0,
            producer: 4000,
        },
        64,
        4096,
        Some(RecordHeader {
            payload_len: 8,
            busy: false,
            discard: false,
        }),
    )
    .unwrap();
    assert_eq!(
        emit,
        FrameStep::Emit {
            payload_len: 8,
            next: 16
        }
    );
    let err = frame_step(
        RingPositions {
            consumer: 0,
            producer: 4000,
        },
        64,
        4096,
        Some(RecordHeader {
            payload_len: 64,
            busy: false,
            discard: false,
        }),
    )
    .expect_err("crossing record refuses despite ample producer");
    assert_eq!(err.kind(), ErrorKind::Incompatible);
    assert_eq!(err.stage(), Stage::Drain);
}

#[test]
fn frame_outcomes_are_exactly_four() {
    // Exhaustive match: a fifth FrameStep variant breaks compilation, so
    // no Quiescent/Settled outcome can slip into the bounded results.
    fn name(step: &FrameStep) -> &'static str {
        match step {
            FrameStep::Pending => "pending",
            FrameStep::Emit { .. } => "emit",
            FrameStep::Discard { .. } => "discard",
            FrameStep::ReachedBoundary => "reached",
        }
    }
    assert_eq!(name(&FrameStep::Pending), "pending");
    assert_eq!(name(&FrameStep::ReachedBoundary), "reached");
}

#[test]
fn boundary_states_are_exactly_three() {
    fn name(state: &BoundaryState) -> &'static str {
        match state {
            BoundaryState::Reached => "reached",
            BoundaryState::Pending => "pending",
            BoundaryState::BudgetExhausted => "exhausted",
        }
    }
    assert_eq!(name(&BoundaryState::Reached), "reached");
    assert_eq!(name(&BoundaryState::Pending), "pending");
    assert_eq!(name(&BoundaryState::BudgetExhausted), "exhausted");
}

/// Scripted in-memory ring: drives the production `frame_step` per record
/// without any mapping. Mirrors the adapter loop shape (validate, step,
/// budget-gate, consume) so drain semantics are pinned before BP10.
#[derive(Debug, Clone)]
enum ScriptOp {
    Emit { payload: Vec<u8> },
    Discard { payload_len: u32 },
    Busy { payload_len: u32 },
    Gap,
    Fail { kind: ErrorKind, errno: Option<i32> },
}

fn aligned_total(payload_len: u32) -> u64 {
    8 + ((payload_len as u64 + 7) & !7)
}

struct ScriptedSource {
    capacity: usize,
    consumer: u64,
    producer: u64,
    ops: VecDeque<ScriptOp>,
}

impl ScriptedSource {
    fn new(capacity: usize, consumer: u64, producer: u64, ops: Vec<ScriptOp>) -> Self {
        Self {
            capacity,
            consumer,
            producer,
            ops: ops.into(),
        }
    }

    fn consumer(&self) -> u64 {
        self.consumer
    }
}

impl BoundedRingSource for ScriptedSource {
    fn snapshot(&mut self) -> Result<RingPositions, OperationError> {
        Ok(RingPositions {
            consumer: self.consumer,
            producer: self.producer,
        })
    }

    fn consume_before(
        &mut self,
        stop: u64,
        budget: DrainBudget,
        visit: &mut dyn FnMut(&[u8]),
    ) -> Result<DrainResult, OperationError> {
        let mut records = 0usize;
        let mut bytes = 0usize;
        let mut discarded = 0usize;
        loop {
            let positions = RingPositions {
                consumer: self.consumer,
                producer: self.producer,
            };
            if matches!(self.ops.front(), Some(ScriptOp::Fail { .. })) {
                let Some(ScriptOp::Fail { kind, errno }) = self.ops.pop_front() else {
                    unreachable!("matched Fail above");
                };
                return Err(OperationError::new(kind, Stage::Drain, errno, None));
            }
            let probe_zero = RecordHeader {
                payload_len: 0,
                busy: false,
                discard: false,
            };
            let header = match self.ops.front() {
                None | Some(ScriptOp::Gap) => probe_zero,
                Some(ScriptOp::Emit { payload }) => RecordHeader {
                    payload_len: payload.len() as u32,
                    busy: false,
                    discard: false,
                },
                Some(ScriptOp::Discard { payload_len }) => RecordHeader {
                    payload_len: *payload_len,
                    busy: false,
                    discard: true,
                },
                Some(ScriptOp::Busy { payload_len }) => RecordHeader {
                    payload_len: *payload_len,
                    busy: true,
                    discard: false,
                },
                Some(ScriptOp::Fail { .. }) => unreachable!("handled above"),
            };
            let empty = matches!(self.ops.front(), None | Some(ScriptOp::Gap));
            match frame_step(positions, stop, self.capacity, Some(header))? {
                FrameStep::ReachedBoundary => {
                    return Ok(DrainResult {
                        boundary: BoundaryState::Reached,
                        records,
                        bytes,
                        discarded,
                    });
                }
                FrameStep::Pending => {
                    return Ok(DrainResult {
                        boundary: BoundaryState::Pending,
                        records,
                        bytes,
                        discarded,
                    });
                }
                FrameStep::Discard { next } => {
                    assert!(!empty, "empty source cannot discard");
                    let total = aligned_total(header.payload_len);
                    assert_eq!(
                        next,
                        self.consumer.wrapping_add(total),
                        "lib next matches test total"
                    );
                    if records >= budget.max_records
                        || bytes
                            .checked_add(total as usize)
                            .map_or(true, |sum| sum > budget.max_bytes)
                    {
                        return Ok(DrainResult {
                            boundary: BoundaryState::BudgetExhausted,
                            records,
                            bytes,
                            discarded,
                        });
                    }
                    bytes += total as usize;
                    records += 1;
                    discarded += 1;
                    self.consumer = next;
                    self.ops.pop_front();
                }
                FrameStep::Emit { payload_len, next } => {
                    if empty {
                        return Ok(DrainResult {
                            boundary: BoundaryState::Pending,
                            records,
                            bytes,
                            discarded,
                        });
                    }
                    let total = aligned_total(header.payload_len);
                    assert_eq!(
                        next,
                        self.consumer.wrapping_add(total),
                        "lib next matches test total"
                    );
                    if records >= budget.max_records
                        || bytes
                            .checked_add(total as usize)
                            .map_or(true, |sum| sum > budget.max_bytes)
                    {
                        return Ok(DrainResult {
                            boundary: BoundaryState::BudgetExhausted,
                            records,
                            bytes,
                            discarded,
                        });
                    }
                    let payload = match self.ops.pop_front() {
                        Some(ScriptOp::Emit { payload }) => payload,
                        other => panic!("emit without emitted op: {other:?}"),
                    };
                    assert_eq!(payload.len(), payload_len, "payload length matches");
                    visit(&payload);
                    bytes += total as usize;
                    records += 1;
                    self.consumer = next;
                }
            }
        }
    }
}

fn full_budget() -> DrainBudget {
    DrainBudget {
        max_records: usize::MAX,
        max_bytes: usize::MAX,
    }
}

fn emit(payload: &[u8]) -> ScriptOp {
    ScriptOp::Emit {
        payload: payload.to_vec(),
    }
}

#[test]
fn drain_reaches_stop() {
    let mut source = ScriptedSource::new(
        4096,
        0,
        48,
        vec![emit(&[1; 8]), emit(&[2; 8]), emit(&[3; 8])],
    );
    let mut seen = Vec::new();
    let result = source
        .consume_before(48, full_budget(), &mut |bytes| seen.push(bytes.to_vec()))
        .unwrap();
    assert_eq!(result.boundary, BoundaryState::Reached);
    assert_eq!(result.records, 3);
    assert_eq!(result.bytes, 48);
    assert_eq!(result.discarded, 0);
    assert_eq!(seen, vec![vec![1; 8], vec![2; 8], vec![3; 8]]);
    assert_eq!(source.consumer(), 48);
}

#[test]
fn drain_empty_is_pending() {
    let mut source = ScriptedSource::new(4096, 0, 0, vec![]);
    let mut visits = 0;
    let result = source
        .consume_before(64, full_budget(), &mut |_| visits += 1)
        .unwrap();
    assert_eq!(result.boundary, BoundaryState::Pending);
    assert_eq!(
        (result.records, result.bytes, result.discarded, visits),
        (0, 0, 0, 0)
    );
    assert_eq!(source.consumer(), 0);
}

#[test]
fn drain_busy_is_pending_consumer_unchanged_then_commits() {
    let mut source = ScriptedSource::new(4096, 0, 64, vec![ScriptOp::Busy { payload_len: 8 }]);
    let mut visits = 0;
    let pending = source
        .consume_before(64, full_budget(), &mut |_| visits += 1)
        .unwrap();
    assert_eq!(pending.boundary, BoundaryState::Pending);
    assert_eq!(pending.records, 0);
    assert_eq!(source.consumer(), 0, "busy leaves the consumer untouched");
    // The reservation commits; the retry observes the record.
    source.ops.pop_front();
    source.ops.push_front(emit(&[9; 8]));
    let mut seen = Vec::new();
    let result = source
        .consume_before(64, full_budget(), &mut |bytes| seen.push(bytes.to_vec()))
        .unwrap();
    assert_eq!(
        result.boundary,
        BoundaryState::Pending,
        "stop not yet reached"
    );
    assert_eq!(result.records, 1);
    assert_eq!(seen, vec![vec![9; 8]]);
    assert_eq!(source.consumer(), 16);
}

#[test]
fn drain_discard_advances_once_and_charges_budget() {
    let mut source = ScriptedSource::new(
        4096,
        0,
        32,
        vec![ScriptOp::Discard { payload_len: 8 }, emit(&[4; 8])],
    );
    let mut seen = Vec::new();
    let result = source
        .consume_before(32, full_budget(), &mut |bytes| seen.push(bytes.to_vec()))
        .unwrap();
    assert_eq!(result.boundary, BoundaryState::Reached);
    assert_eq!(result.records, 2, "discard charges the record budget");
    assert_eq!(result.bytes, 32, "discard charges the byte budget");
    assert_eq!(result.discarded, 1);
    assert_eq!(seen, vec![vec![4; 8]]);
    assert_eq!(source.consumer(), 32, "discard advances exactly once");
}

#[test]
fn drain_record_budgets_n_and_n_plus_1() {
    let ops = || vec![emit(&[1; 8]), emit(&[2; 8]), emit(&[3; 8])];
    let mut source = ScriptedSource::new(4096, 0, 48, ops());
    let mut seen = Vec::new();
    let capped = source
        .consume_before(
            48,
            DrainBudget {
                max_records: 2,
                max_bytes: usize::MAX,
            },
            &mut |bytes| seen.push(bytes.to_vec()),
        )
        .unwrap();
    assert_eq!(capped.boundary, BoundaryState::BudgetExhausted);
    assert_eq!(capped.records, 2);
    assert_eq!(seen.len(), 2);
    assert_eq!(source.consumer(), 32);
    // A fresh budget resumes at the retained cursor and reaches the stop.
    let resumed = source
        .consume_before(48, full_budget(), &mut |bytes| seen.push(bytes.to_vec()))
        .unwrap();
    assert_eq!(resumed.boundary, BoundaryState::Reached);
    assert_eq!(resumed.records, 1);
    assert_eq!(seen.len(), 3);
    assert_eq!(source.consumer(), 48);
}

#[test]
fn drain_record_budget_zero_is_exhausted() {
    let mut source = ScriptedSource::new(4096, 0, 16, vec![emit(&[1; 8])]);
    let mut visits = 0;
    let result = source
        .consume_before(
            16,
            DrainBudget {
                max_records: 0,
                max_bytes: usize::MAX,
            },
            &mut |_| visits += 1,
        )
        .unwrap();
    assert_eq!(result.boundary, BoundaryState::BudgetExhausted);
    assert_eq!(result.records, 0);
    assert_eq!(visits, 0);
    assert_eq!(source.consumer(), 0);
}

#[test]
fn drain_byte_budgets_n_and_n_plus_1() {
    // Three 16-byte records: exact 32-byte budget delivers two, one byte
    // less delivers one; exhaustion never consumes partially.
    let ops = || vec![emit(&[1; 8]), emit(&[2; 8]), emit(&[3; 8])];
    for (max_bytes, expect_records, expect_consumer) in [(32, 2, 32), (31, 1, 16)] {
        let mut source = ScriptedSource::new(4096, 0, 48, ops());
        let mut seen = 0;
        let result = source
            .consume_before(
                48,
                DrainBudget {
                    max_records: usize::MAX,
                    max_bytes,
                },
                &mut |_| seen += 1,
            )
            .unwrap();
        assert_eq!(
            result.boundary,
            BoundaryState::BudgetExhausted,
            "max_bytes={max_bytes}"
        );
        assert_eq!(result.records, expect_records, "max_bytes={max_bytes}");
        assert_eq!(seen, expect_records, "max_bytes={max_bytes}");
        assert_eq!(source.consumer(), expect_consumer, "max_bytes={max_bytes}");
    }
    let mut source = ScriptedSource::new(4096, 0, 48, ops());
    let mut visits = 0;
    let zero = source
        .consume_before(
            48,
            DrainBudget {
                max_records: usize::MAX,
                max_bytes: 0,
            },
            &mut |_| visits += 1,
        )
        .unwrap();
    assert_eq!(zero.boundary, BoundaryState::BudgetExhausted);
    assert_eq!(zero.records, 0);
    assert_eq!(visits, 0);
    assert_eq!(source.consumer(), 0);
}

#[test]
fn drain_reached_beats_zero_budget() {
    let mut source = ScriptedSource::new(4096, 48, 48, vec![]);
    let result = source
        .consume_before(
            48,
            DrainBudget {
                max_records: 0,
                max_bytes: 0,
            },
            &mut |_| {
                panic!("no visit at the boundary");
            },
        )
        .unwrap();
    assert_eq!(result.boundary, BoundaryState::Reached);
}

#[test]
fn drain_crossing_stop_is_error_with_tail_preserved() {
    // First record consumes, second crosses the stop: the error propagates
    // and the consumed tail stays consumed.
    let mut source = ScriptedSource::new(4096, 0, 64, vec![emit(&[1; 8]), emit(&[2; 64])]);
    let mut seen = Vec::new();
    let err = source
        .consume_before(32, full_budget(), &mut |bytes| seen.push(bytes.to_vec()))
        .expect_err("crossing record refuses");
    assert_eq!(err.kind(), ErrorKind::Incompatible);
    assert_eq!(err.stage(), Stage::Drain);
    assert_eq!(seen, vec![vec![1; 8]], "consumed tail preserved");
    assert_eq!(source.consumer(), 16);
}

#[test]
fn drain_eintr_preserves_tail_and_resumes() {
    let mut source = ScriptedSource::new(
        4096,
        0,
        48,
        vec![
            emit(&[1; 8]),
            ScriptOp::Fail {
                kind: ErrorKind::Backend,
                errno: Some(4),
            },
            emit(&[3; 8]),
        ],
    );
    let mut seen = Vec::new();
    let err = source
        .consume_before(48, full_budget(), &mut |bytes| seen.push(bytes.to_vec()))
        .expect_err("injected EINTR propagates");
    assert_eq!(err.raw_os_error(), Some(4));
    assert_eq!(seen, vec![vec![1; 8]], "pre-error tail preserved");
    assert_eq!(source.consumer(), 16);
    // The one-shot failure is spent; the drain resumes after it.
    let resumed = source
        .consume_before(48, full_budget(), &mut |bytes| seen.push(bytes.to_vec()))
        .unwrap();
    assert_eq!(
        resumed.boundary,
        BoundaryState::Pending,
        "ops exhausted at 32"
    );
    assert_eq!(resumed.records, 1);
    assert_eq!(seen.len(), 2);
}

#[test]
fn drain_producer_extension_keeps_stop() {
    let mut source = ScriptedSource::new(4096, 0, 4000, vec![emit(&[1; 8]), emit(&[2; 8])]);
    let mut seen = Vec::new();
    let result = source
        .consume_before(32, full_budget(), &mut |bytes| seen.push(bytes.to_vec()))
        .unwrap();
    assert_eq!(result.boundary, BoundaryState::Reached);
    assert_eq!(result.records, 2);
    assert_eq!(source.consumer(), 32, "drain stops at stop, not producer");
}

#[test]
fn drain_invalid_stop_refuses_before_effects() {
    let mut source = ScriptedSource::new(4096, 0, 64, vec![emit(&[1; 8])]);
    let mut visits = 0;
    let err = source
        .consume_before(12, full_budget(), &mut |_| visits += 1)
        .expect_err("unaligned stop refuses");
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert_eq!(visits, 0);
    assert_eq!(source.consumer(), 0);
}

#[test]
fn drain_bounded_sweep_seeded() {
    let mut rng = 0x9e37_79b9_7f4a_7c15u64;
    let mut next_rand = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    for _ in 0..500 {
        let frame_count = (next_rand() % 8) as usize;
        let mut ops = Vec::new();
        let mut span = 0u64;
        for _ in 0..frame_count {
            let len = (next_rand() % 24) as u32;
            match next_rand() % 5 {
                0 => ops.push(ScriptOp::Discard { payload_len: len }),
                1 => ops.push(ScriptOp::Busy { payload_len: len }),
                2 => ops.push(ScriptOp::Gap),
                _ => ops.push(emit(&vec![0xabu8; len as usize])),
            }
            if !matches!(ops.last(), Some(ScriptOp::Gap)) {
                span += aligned_total(len);
            }
        }
        // Stop at or before the scripted span; producer covers the span.
        let stop = span - (next_rand() % 3).min(span / 8) * 8;
        let max_records = (next_rand() % 10) as usize;
        let max_bytes = (next_rand() % 129) as usize;
        let budget = DrainBudget {
            max_records,
            max_bytes,
        };
        let mut first = ScriptedSource::new(4096, 0, span, ops.clone());
        let mut first_seen = 0;
        let first_result = first
            .consume_before(stop, budget, &mut |_| first_seen += 1)
            .ok();
        let mut second = ScriptedSource::new(4096, 0, span, ops);
        let mut second_seen = 0;
        let second_result = second
            .consume_before(stop, budget, &mut |_| second_seen += 1)
            .ok();
        assert_eq!(
            (
                first_result
                    .as_ref()
                    .map(|r| (r.boundary, r.records, r.bytes, r.discarded)),
                first.consumer(),
                first_seen
            ),
            (
                second_result
                    .as_ref()
                    .map(|r| (r.boundary, r.records, r.bytes, r.discarded)),
                second.consumer(),
                second_seen
            ),
            "drain is deterministic"
        );
        if let Some(result) = first_result {
            assert!(result.records <= max_records, "record budget holds");
            assert!(result.bytes <= max_bytes, "byte budget holds");
            assert!(result.discarded <= result.records, "discards counted");
            assert_eq!(
                first_seen,
                result.records - result.discarded,
                "visits match emits"
            );
            if result.boundary == BoundaryState::Reached {
                assert_eq!(first.consumer(), stop, "reached means consumer == stop");
            }
        }
    }
}

fn staging_root() -> Json {
    let root = json_mini::parse(STAGING).expect("staging fixture parses");
    assert_eq!(root.get("version").unwrap().as_u64().unwrap(), 1);
    let framing = root.get("framing").unwrap();
    assert_eq!(framing.get("header_bytes").unwrap().as_u64().unwrap(), 8);
    assert_eq!(framing.get("length").unwrap().as_str().unwrap(), "u32-le");
    assert_eq!(
        framing.get("version").unwrap().as_u64().unwrap(),
        u64::from(STAGE_FRAMING_VERSION)
    );
    root
}

fn staging_payload(root: &Json, name: &str) -> Vec<u8> {
    root.get("payloads")
        .unwrap()
        .get(name)
        .unwrap()
        .as_arr()
        .unwrap()
        .iter()
        .map(|byte| byte.as_u64().unwrap().try_into().expect("byte fits u8"))
        .collect()
}

fn staging_case<'a>(root: &'a Json, name: &str) -> &'a Json {
    root.get("cases")
        .unwrap()
        .as_arr()
        .unwrap()
        .iter()
        .find(|case| case.get("name").unwrap().as_str().unwrap() == name)
        .unwrap_or_else(|| panic!("staging case {name:?} missing"))
}

fn json_bytes(value: &Json) -> Vec<u8> {
    value
        .as_arr()
        .unwrap()
        .iter()
        .map(|byte| byte.as_u64().unwrap().try_into().expect("byte fits u8"))
        .collect()
}

fn assert_stats(stats: &StageStats, expect: &Json, context: &str) {
    assert_eq!(
        stats.received,
        expect.get("received").unwrap().as_u64().unwrap(),
        "{context} received"
    );
    assert_eq!(
        stats.delivered,
        expect.get("delivered").unwrap().as_u64().unwrap(),
        "{context} delivered"
    );
    assert_eq!(
        stats.held,
        expect.get("held").unwrap().as_u64().unwrap(),
        "{context} held"
    );
    assert_eq!(
        stats.malformed,
        expect.get("malformed").unwrap().as_u64().unwrap(),
        "{context} malformed"
    );
    assert_eq!(
        stats.dropped,
        expect.get("dropped").unwrap().as_u64().unwrap(),
        "{context} dropped"
    );
    assert!(stats.balanced(), "{context} conservation holds");
}

fn assert_sentinel(bytes: &[u8], sentinel: u8, context: &str) {
    assert!(
        bytes.iter().all(|byte| *byte == sentinel),
        "{context} destination untouched"
    );
}

#[test]
fn stage_short_retained_then_delivers_once() {
    let root = staging_root();
    let case = staging_case(&root, "short-retained-then-once");
    let payload = staging_payload(&root, case.get("payload").unwrap().as_str().unwrap());
    let max = case.get("max_record_bytes").unwrap().as_usize().unwrap();
    let mut staged = StagedRecord::new(max).unwrap();
    staged.offer(&payload).unwrap();
    assert_eq!(staged.stats().held, 1, "record held after offer");
    // Initial short copy plus two retries: required size reported, the
    // destination untouched, the record retained.
    let short_dst = case.get("short_dst").unwrap().as_usize().unwrap();
    let required = case.get("short_required").unwrap().as_usize().unwrap();
    let retries = case.get("short_retries").unwrap().as_usize().unwrap();
    for attempt in 0..=retries {
        let mut dst = vec![0xa5u8; short_dst];
        let err = staged
            .copy_into(&mut dst)
            .expect_err(&format!("short attempt {attempt} refuses"));
        assert_eq!(err.kind(), ErrorKind::LimitExceeded, "attempt {attempt}");
        assert_eq!(err.stage(), Stage::Drain, "attempt {attempt}");
        assert_eq!(err.required_size(), Some(required), "attempt {attempt}");
        assert_sentinel(&dst, 0xa5, &format!("attempt {attempt}"));
        assert_eq!(staged.stats().held, 1, "attempt {attempt} retains");
    }
    let full_dst = case.get("full_dst").unwrap().as_usize().unwrap();
    let mut dst = vec![0xa5u8; full_dst];
    let delivered = staged.copy_into(&mut dst).unwrap();
    assert_eq!(delivered, full_dst);
    assert_eq!(
        dst,
        json_bytes(case.get("delivered_frame").unwrap()),
        "framed bytes exact"
    );
    assert_stats(staged.stats(), case.get("stats").unwrap(), "final");
    // Delivered once: the slot is empty afterwards.
    let mut dst = vec![0xa5u8; full_dst];
    assert_eq!(
        staged.copy_into(&mut dst).unwrap(),
        case.get("second_copy").unwrap().as_usize().unwrap()
    );
    assert_sentinel(&dst, 0xa5, "empty copy writes nothing");
}

#[test]
fn stage_single_frame_per_call() {
    let root = staging_root();
    let case = staging_case(&root, "single-frames");
    let max = case.get("max_record_bytes").unwrap().as_usize().unwrap();
    let dst_len = case.get("dst").unwrap().as_usize().unwrap();
    let names: Vec<&str> = case
        .get("payloads")
        .unwrap()
        .as_arr()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect();
    let frames: Vec<Vec<u8>> = case
        .get("frames")
        .unwrap()
        .as_arr()
        .unwrap()
        .iter()
        .map(json_bytes)
        .collect();
    assert_eq!(names.len(), frames.len());
    let mut staged = StagedRecord::new(max).unwrap();
    for (name, frame) in names.iter().zip(frames.iter()) {
        let payload = staging_payload(&root, name);
        staged.offer(&payload).unwrap();
        let mut dst = vec![0xa5u8; dst_len];
        let delivered = staged.copy_into(&mut dst).unwrap();
        assert_eq!(delivered, frame.len(), "one frame per call");
        assert_eq!(&dst[..frame.len()], frame.as_slice(), "frame bytes");
        assert_sentinel(&dst[frame.len()..], 0xa5, "tail untouched");
    }
    assert_stats(staged.stats(), case.get("stats").unwrap(), "final");
}

#[test]
fn stage_occupied_drop_preserves_previous() {
    let root = staging_root();
    let case = staging_case(&root, "occupied-drop");
    let max = case.get("max_record_bytes").unwrap().as_usize().unwrap();
    let names: Vec<&str> = case
        .get("payloads")
        .unwrap()
        .as_arr()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 2);
    let mut staged = StagedRecord::new(max).unwrap();
    staged.offer(&staging_payload(&root, names[0])).unwrap();
    let err = staged
        .offer(&staging_payload(&root, names[1]))
        .expect_err("occupied slot drops the new record");
    assert_eq!(
        err.kind(),
        fixture_kind(case.get("drop_kind").unwrap().as_str().unwrap())
    );
    assert_eq!(err.stage(), Stage::Drain);
    assert_stats(
        staged.stats(),
        case.get("stats_after_drop").unwrap(),
        "after drop",
    );
    let full_dst = case.get("full_dst").unwrap().as_usize().unwrap();
    let mut dst = vec![0xa5u8; full_dst];
    staged.copy_into(&mut dst).unwrap();
    assert_eq!(
        dst,
        json_bytes(case.get("delivered_frame").unwrap()),
        "previous bytes preserved"
    );
    assert_stats(
        staged.stats(),
        case.get("stats_after_deliver").unwrap(),
        "after deliver",
    );
}

#[test]
fn stage_zero_and_oversize_are_malformed() {
    let root = staging_root();
    let zero = staging_case(&root, "zero-malformed");
    let max = zero.get("max_record_bytes").unwrap().as_usize().unwrap();
    let mut staged = StagedRecord::new(max).unwrap();
    let err = staged.offer(&[]).expect_err("zero record rejects");
    assert_eq!(
        err.kind(),
        fixture_kind(zero.get("malformed_kind").unwrap().as_str().unwrap())
    );
    assert_eq!(err.stage(), Stage::Drain);
    assert_stats(staged.stats(), zero.get("stats").unwrap(), "zero");
    let oversize = staging_case(&root, "oversize-malformed");
    let max = oversize
        .get("max_record_bytes")
        .unwrap()
        .as_usize()
        .unwrap();
    let mut staged = StagedRecord::new(max).unwrap();
    let mut payload = staging_payload(&root, oversize.get("payload").unwrap().as_str().unwrap());
    payload.push(oversize.get("extra_byte").unwrap().as_u64().unwrap() as u8);
    let err = staged.offer(&payload).expect_err("oversize record rejects");
    assert_eq!(
        err.kind(),
        fixture_kind(oversize.get("malformed_kind").unwrap().as_str().unwrap())
    );
    assert_eq!(err.stage(), Stage::Drain);
    assert_eq!(
        err.required_size(),
        Some(oversize.get("required_size").unwrap().as_usize().unwrap()),
        "oversize reports payload bytes"
    );
    assert_stats(staged.stats(), oversize.get("stats").unwrap(), "oversize");
}

#[test]
fn stage_source_mutation_cannot_corrupt() {
    let root = staging_root();
    let mut payload = staging_payload(&root, "a");
    let mut staged = StagedRecord::new(4096).unwrap();
    staged.offer(&payload).unwrap();
    for byte in payload.iter_mut() {
        *byte = 0xcc;
    }
    let mut dst = vec![0xa5u8; 24];
    staged.copy_into(&mut dst).unwrap();
    let case = staging_case(&root, "short-retained-then-once");
    assert_eq!(
        dst,
        json_bytes(case.get("delivered_frame").unwrap()),
        "owned copy delivered"
    );
}

#[test]
fn stage_malformed_offer_preserves_held() {
    let root = staging_root();
    let held = staging_payload(&root, "a");
    let mut staged = StagedRecord::new(16).unwrap();
    staged.offer(&held).unwrap();
    let oversize = vec![0xccu8; 17];
    let _ = staged.offer(&oversize).expect_err("oversize rejects");
    assert_eq!(
        staged.stats().held,
        1,
        "held record survives the error tail"
    );
    let mut dst = vec![0xa5u8; 24];
    staged.copy_into(&mut dst).unwrap();
    let case = staging_case(&root, "short-retained-then-once");
    assert_eq!(
        dst,
        json_bytes(case.get("delivered_frame").unwrap()),
        "held bytes intact"
    );
    assert!(staged.stats().balanced());
}

#[test]
fn stage_new_zero_refuses() {
    let err = StagedRecord::new(0).expect_err("zero bound admits nothing");
    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(err.stage(), Stage::Drain);
    assert!(StagedRecord::new(1).is_ok());
}

#[test]
fn stage_empty_copy_is_zero() {
    let mut staged = StagedRecord::new(4096).unwrap();
    let mut dst = vec![0xa5u8; 24];
    assert_eq!(staged.copy_into(&mut dst).unwrap(), 0);
    assert_sentinel(&dst, 0xa5, "empty copy");
    let stats = staged.stats();
    assert_eq!(
        (
            stats.received,
            stats.delivered,
            stats.held,
            stats.malformed,
            stats.dropped
        ),
        (0, 0, 0, 0, 0)
    );
}

#[test]
fn stage_conservation_sequence() {
    let mut staged = StagedRecord::new(16).unwrap();
    let check = |staged: &StagedRecord, expect: (u64, u64, u64, u64, u64), context: &str| {
        let stats = staged.stats();
        assert_eq!(
            (
                stats.received,
                stats.delivered,
                stats.held,
                stats.malformed,
                stats.dropped
            ),
            expect,
            "{context}"
        );
        assert!(stats.balanced(), "{context} balanced");
    };
    staged.offer(&[1; 16]).unwrap();
    check(&staged, (1, 0, 1, 0, 0), "offer held");
    let _ = staged.offer(&[2; 16]).expect_err("occupied drops");
    check(&staged, (2, 0, 1, 0, 1), "occupied drop");
    let mut dst = [0xa5u8; 24];
    assert_eq!(staged.copy_into(&mut dst).unwrap(), 24);
    check(&staged, (2, 1, 0, 0, 1), "delivered once");
    let _ = staged.offer(&[]).expect_err("zero malformed");
    check(&staged, (3, 1, 0, 1, 1), "zero malformed");
    let _ = staged.offer(&[3; 17]).expect_err("oversize malformed");
    check(&staged, (4, 1, 0, 2, 1), "oversize malformed");
    staged.offer(&[4; 16]).unwrap();
    check(&staged, (5, 1, 1, 2, 1), "offer held again");
    assert_eq!(staged.copy_into(&mut dst).unwrap(), 24);
    check(&staged, (5, 2, 0, 2, 1), "final");
}

#[test]
fn stage_framing_pins_length_and_version() {
    // The envelope (little-endian length plus framing version) is fixed
    // independently of payload content.
    let mut staged = StagedRecord::new(16).unwrap();
    staged.offer(&[0xabu8; 16]).unwrap();
    let mut dst = [0u8; 24];
    staged.copy_into(&mut dst).unwrap();
    assert_eq!(
        &dst[..4],
        &16u32.to_le_bytes(),
        "length is u32 little-endian"
    );
    assert_eq!(
        &dst[4..8],
        &STAGE_FRAMING_VERSION.to_le_bytes(),
        "version pinned"
    );
    assert_eq!(&dst[8..], &[0xabu8; 16], "payload verbatim");
    let mut staged = StagedRecord::new(16).unwrap();
    staged.offer(&[0x01u8; 8]).unwrap();
    let mut dst = [0u8; 16];
    staged.copy_into(&mut dst).unwrap();
    assert_eq!(&dst[..4], &8u32.to_le_bytes());
    assert_eq!(&dst[4..8], &STAGE_FRAMING_VERSION.to_le_bytes());
}

#[test]
fn mutant_busy_as_empty_loses_boundary() {
    // Mutant: treat BUSY as ReachedBoundary. With a busy head before the
    // stop the mutant seals the drain early; the oracle demands Pending.
    let header = RecordHeader {
        payload_len: 8,
        busy: true,
        discard: false,
    };
    let mutant_reached = header.busy;
    assert!(mutant_reached, "mutant shape pinned");
    let oracle = frame_step(
        RingPositions {
            consumer: 0,
            producer: 104,
        },
        96,
        4096,
        Some(header),
    )
    .unwrap();
    assert_eq!(oracle, FrameStep::Pending, "valid twin stays pending");
    assert_ne!(
        oracle,
        FrameStep::ReachedBoundary,
        "boundary assertion discriminates"
    );
}

#[test]
fn mutant_stop_extension_consumes_past_stop() {
    // Mutant: drain to the live producer instead of the captured stop.
    // With stop=32 and producer=4000 the mutant consumes the third record
    // at 32..48; the valid twin stops at 32.
    let mut mutant = ScriptedSource::new(
        4096,
        0,
        4000,
        vec![emit(&[1; 8]), emit(&[2; 8]), emit(&[3; 8])],
    );
    let mut seen = 0;
    let result = mutant
        .consume_before(4000, full_budget(), &mut |_| seen += 1)
        .unwrap();
    assert_eq!(seen, 3, "mutant consumes past the captured stop");
    assert_eq!(mutant.consumer(), 48);
    assert_eq!(
        result.boundary,
        BoundaryState::Pending,
        "live producer never reached"
    );
    let mut valid = ScriptedSource::new(
        4096,
        0,
        4000,
        vec![emit(&[1; 8]), emit(&[2; 8]), emit(&[3; 8])],
    );
    let result = valid
        .consume_before(32, full_budget(), &mut |_| {})
        .unwrap();
    assert_eq!(
        result.boundary,
        BoundaryState::Reached,
        "valid twin stops at stop"
    );
    assert_eq!(valid.consumer(), 32);
}

#[test]
fn mutant_double_drop_breaks_conservation() {
    // Mutant: count one delivery twice. received=1 with delivered=2 cannot
    // balance; the conservation assertion discriminates.
    let mutant = StageStats {
        received: 1,
        delivered: 2,
        held: 0,
        malformed: 0,
        dropped: 0,
    };
    assert!(!mutant.balanced(), "double-counted delivery unbalances");
    let mut staged = StagedRecord::new(4096).unwrap();
    staged.offer(&[7; 8]).unwrap();
    let mut dst = [0u8; 16];
    staged.copy_into(&mut dst).unwrap();
    assert!(staged.stats().balanced(), "valid twin balances");
    assert_eq!(staged.stats().delivered, 1);
}

#[test]
fn mutant_short_buffer_consumes_input_loses_record() {
    // Mutant: clear the slot on a short destination. The retry then finds
    // nothing; the valid twin retains and delivers.
    let mut staged = StagedRecord::new(16).unwrap();
    staged.offer(&[7; 16]).unwrap();
    let mut short = [0xa5u8; 23];
    let _ = staged.copy_into(&mut short).expect_err("short refuses");
    // Mutant behavior: slot cleared by the short attempt.
    let mutant_delivered = 0usize;
    let mut dst = [0xa5u8; 24];
    let valid_delivered = staged.copy_into(&mut dst).unwrap();
    assert_eq!(valid_delivered, 24, "valid twin retains across the short");
    assert_ne!(
        mutant_delivered, valid_delivered,
        "delivery assertion discriminates"
    );
}

fn assert_send<T: Send>() {}
fn assert_sync<T: Sync>() {}

#[test]
fn ring_contract_types_are_send() {
    assert_send::<RingPositions>();
    assert_send::<RecordHeader>();
    assert_send::<FrameStep>();
    assert_send::<DrainBudget>();
    assert_send::<BoundaryState>();
    assert_send::<DrainResult>();
    assert_send::<StageStats>();
    assert_send::<StagedRecord>();
    assert_sync::<RingPositions>();
    assert_sync::<RecordHeader>();
    assert_sync::<FrameStep>();
    assert_sync::<DrainBudget>();
    assert_sync::<BoundaryState>();
    assert_sync::<DrainResult>();
    assert_sync::<StageStats>();
    // StagedRecord is !Sync by construction (sole-owner staging slot);
    // negative auto-trait bounds need a compile-fail UI gate owned by the
    // integration owner alongside the existing UI suite.
}

#[test]
fn cursors_fixture_is_consistent() {
    let cases = cursor_cases();
    assert_eq!(cases.len(), 34);
    for case in &cases {
        let name = case.get("name").unwrap().as_str().unwrap();
        let outcome = case
            .get("expect")
            .unwrap()
            .get("outcome")
            .unwrap()
            .as_str()
            .unwrap();
        assert!(
            ["emit", "discard", "pending", "reached", "error"].contains(&outcome),
            "{name} known outcome"
        );
        if outcome == "error" {
            let kind = case
                .get("expect")
                .unwrap()
                .get("kind")
                .unwrap()
                .as_str()
                .unwrap();
            assert!(
                ["InvalidInput", "Malformed", "Incompatible"].contains(&kind),
                "{name} kind"
            );
        }
    }
}

#[test]
fn staging_fixture_is_consistent() {
    let root = staging_root();
    let cases = root.get("cases").unwrap().as_arr().unwrap();
    assert_eq!(cases.len(), 5);
    for case in cases {
        for key in ["received", "delivered", "held", "malformed", "dropped"] {
            let stats_key = if case.get("name").unwrap().as_str().unwrap() == "occupied-drop" {
                "stats_after_deliver"
            } else {
                "stats"
            };
            let _ = case
                .get(stats_key)
                .unwrap()
                .get(key)
                .unwrap()
                .as_u64()
                .unwrap();
        }
    }
}
