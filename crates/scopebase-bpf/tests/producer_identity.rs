// SPDX-License-Identifier: Apache-2.0
//! BP08: optional producer task/exec identity protocol (host values).
//!
//! ADAPT: p11scope 2c2713e `crates/ebpf-common/src/lib.rs:1316-1332`
//! (`ImageIdentity`, cookie 0 invalid / exec 0 valid, `image_pair_matches`);
//! `crates/ebpf/native/image_identity.h:20-38` (status discipline, CO-RE
//! task shape, identity/control ABI asserts); `image_identity.c:38-119`
//! (zero-cell/quota refusal, bounded ticket CAS), `:121-137` (same typed
//! task supplies both fields), `:147-159` (group-leader identity);
//! `image_identity_fork.c:16-63` (CLONE_THREAD is not a new process, fork
//! identities originate at the birth hook); `exec_task.c:18-76`
//! (existence-before-size/read scalar/bitmap shape guards); VECTORS from
//! `tests/exec_task_continuity.rs:171-241` (supported/unknown shape outcome
//! classes); `src/history.rs:65-102` (`Registry::admit`: retained-domain,
//! stale-exec and capacity refusals, predecessor retirement on advance).
//! Grant: OWNER-2026-10-23 + D03 (user-owned GPL donor, library destination).
//! START/privacy/discovery layouts, loader control cells, BPF maps and
//! product PID/root/affiliation state stay in the donor; only the generic
//! cookie/exec/domain discipline, guard order and admit/retire rules port.
//! Live H01/H03/H08 producer-continuity cells are NOT_RUN (TT05 live
//! binding follow-up); object cells need the TC05/TC06 checker binding.

use scopebase_bpf::identity::{
    advance_exec, plan_exec_read, same_execution, Admission, ExecAdvance, ExecGeneration,
    ExecReadPlan, ExecShapeProbe, IdentityRegistry, IdentityWire, ProducerDomain, ProducerIdentity,
    TaskCookie,
};
use scopebase_bpf::{ErrorKind, Stage};
use std::mem::{align_of, offset_of, size_of};

#[path = "support/json_mini.rs"]
mod json_mini;

use json_mini::Json;

const VECTORS: &str = include_str!("../fixtures/identity-v1/vectors.json");
const LEDGER_SCHEMA: &str = include_str!("../fixtures/identity-v1/ledger.schema.json");
const EXEC_SHAPES: &str = include_str!("../fixtures/identity-v1/exec-shapes.json");

fn domain_a() -> ProducerDomain {
    ProducerDomain([
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
        0xAF,
    ])
}

fn domain_b() -> ProducerDomain {
    ProducerDomain([
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE,
        0xBF,
    ])
}

fn id(domain: ProducerDomain, cookie: u64, exec: u64) -> ProducerIdentity {
    ProducerIdentity::checked(domain, cookie, exec).expect("fixture identity admits")
}

fn kind_stage(err: &scopebase_bpf::OperationError) -> (ErrorKind, Stage) {
    (err.kind(), err.stage())
}

#[test]
fn same_domain_task_exec_compares_equal() {
    let left = id(domain_a(), 7, 3);
    let right = id(domain_a(), 7, 3);
    assert!(same_execution(&left, &right));
    assert!(same_execution(&right, &left));
    assert_eq!(left, right);
}

#[test]
fn token_zero_refuses() {
    assert_eq!(
        kind_stage(&TaskCookie::new(0).expect_err("cookie 0 refuses")),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    assert_eq!(
        kind_stage(&ProducerIdentity::checked(domain_a(), 0, 0).expect_err("zero task refuses")),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    assert!(TaskCookie::new(1).is_ok());
    assert!(TaskCookie::new(u64::MAX).is_ok());
}

#[test]
fn exec_zero_is_valid() {
    let fresh = id(domain_a(), 1, 0);
    assert_eq!(fresh.exec, ExecGeneration(0));
    assert_eq!(fresh.exec, ExecGeneration::ZERO);
    let twin = id(domain_a(), 1, 0);
    assert!(same_execution(&fresh, &twin));
    // Zero exec verifies against a birth-epoch registry entry.
    let mut registry = IdentityRegistry::new(domain_a(), 8);
    assert!(matches!(registry.admit(&fresh), Ok(Admission::Attached(_))));
    assert!(matches!(registry.admit(&twin), Ok(Admission::Verified(_))));
}

#[test]
fn forged_identity_refuses() {
    // A foreign-domain identity is validly shaped but not this session's:
    // the retained registry domain refuses it instead of binding it.
    let mut registry = IdentityRegistry::new(domain_a(), 8);
    let forged = id(domain_b(), 7, 0);
    let err = registry.admit(&forged).expect_err("foreign domain refuses");
    assert_eq!(
        kind_stage(&err),
        (ErrorKind::Incompatible, Stage::Admission)
    );
    assert_eq!(registry.len(), 0, "refusal binds nothing");
    assert_eq!(registry.domain(), domain_a());
    // The same cookie under the genuine domain still attaches afterwards.
    let genuine = id(domain_a(), 7, 0);
    assert!(matches!(
        registry.admit(&genuine),
        Ok(Admission::Attached(_))
    ));
}

#[test]
fn stale_exec_epoch_refuses() {
    let mut registry = IdentityRegistry::new(domain_a(), 8);
    assert!(matches!(
        registry.admit(&id(domain_a(), 9, 5)),
        Ok(Admission::Attached(_))
    ));
    let stale = id(domain_a(), 9, 3);
    let err = registry.admit(&stale).expect_err("stale exec refuses");
    assert_eq!(kind_stage(&err), (ErrorKind::Changed, Stage::Admission));
    // The stored epoch is unchanged: the stale observation binds nothing.
    assert!(matches!(
        registry.admit(&id(domain_a(), 9, 5)),
        Ok(Admission::Verified(_))
    ));
    // The pure exec-epoch primitive agrees with the registry.
    let current = id(domain_a(), 9, 5);
    assert_eq!(
        kind_stage(&advance_exec(&current, 3).expect_err("stale epoch refuses")),
        (ErrorKind::Changed, Stage::Admission)
    );
    assert!(matches!(
        advance_exec(&current, 5),
        Ok(ExecAdvance::Current(_))
    ));
    match advance_exec(&current, 6).expect("newer epoch advances") {
        ExecAdvance::Advanced(next) => {
            assert_eq!(next.exec, ExecGeneration(6));
            assert!(same_execution(&current, &current));
            assert!(!same_execution(&current, &next));
        }
        ExecAdvance::Current(_) => panic!("newer epoch must advance, not verify"),
    }
}

#[test]
fn identity_exec_mismatch_refuses() {
    // Generation-erasure killer: same domain and cookie with different exec
    // generations are different executions, never the same lineage.
    let before = id(domain_a(), 11, 1);
    let after = id(domain_a(), 11, 2);
    assert!(!same_execution(&before, &after));
    let mut registry = IdentityRegistry::new(domain_a(), 8);
    assert!(matches!(
        registry.admit(&before),
        Ok(Admission::Attached(_))
    ));
    match registry.admit(&after).expect("newer exec admits") {
        Admission::Advanced { retired, .. } => assert_eq!(retired, before),
        other => panic!("exec change must advance with retirement, got {other:?}"),
    }
    // Cookie-only and domain-only matches are likewise not same execution.
    assert!(!same_execution(&before, &id(domain_a(), 12, 1)));
    assert!(!same_execution(&before, &id(domain_b(), 11, 1)));
}

#[test]
fn pid_only_lineage_is_rejected() {
    // There is no PID in this protocol: a cookie that survives across an
    // exec boundary never verifies as the pre-exec execution, and two
    // distinct cookies never merge even when their exec counters collide.
    // (A PID/starttime tracker would conflate the first pair.)
    let pre_exec = id(domain_a(), 21, 4);
    let post_exec = id(domain_a(), 21, 5);
    assert!(!same_execution(&pre_exec, &post_exec));
    let sibling = id(domain_a(), 22, 4);
    assert!(!same_execution(&pre_exec, &sibling));
    let mut registry = IdentityRegistry::new(domain_a(), 8);
    assert!(matches!(
        registry.admit(&pre_exec),
        Ok(Admission::Attached(_))
    ));
    assert!(matches!(
        registry.admit(&sibling),
        Ok(Admission::Attached(_))
    ));
    assert_eq!(registry.len(), 2);
}

#[test]
fn exec_advance_retires_predecessor() {
    let mut registry = IdentityRegistry::new(domain_a(), 8);
    let first = id(domain_a(), 31, 1);
    assert!(matches!(registry.admit(&first), Ok(Admission::Attached(_))));
    let second = id(domain_a(), 31, 2);
    match registry.admit(&second).expect("exec advance admits") {
        Admission::Advanced { retired, .. } => {
            assert_eq!(retired, first, "predecessor retires exactly");
            assert!(!same_execution(&retired, &second));
        }
        other => panic!("expected advance with retirement, got {other:?}"),
    }
    // The retired generation is now stale, not verifiable.
    let err = registry.admit(&first).expect_err("retired exec refuses");
    assert_eq!(kind_stage(&err), (ErrorKind::Changed, Stage::Admission));
    assert!(matches!(
        registry.admit(&second),
        Ok(Admission::Verified(_))
    ));
}

#[test]
fn generation_wrap_refuses() {
    // No exec wrap is allowed: the producer mint refuses at u64::MAX.
    let err = ExecGeneration(u64::MAX)
        .next()
        .expect_err("exec mint at MAX refuses");
    assert_eq!(kind_stage(&err), (ErrorKind::Overflow, Stage::Admission));
    assert_eq!(
        ExecGeneration(u64::MAX - 1).next().expect("MAX-1 mints"),
        ExecGeneration(u64::MAX)
    );
    // A MAX epoch still verifies (it is current), it just never advances.
    let mut registry = IdentityRegistry::new(domain_a(), 8);
    let saturated = id(domain_a(), 41, u64::MAX);
    assert!(matches!(
        registry.admit(&saturated),
        Ok(Admission::Attached(_))
    ));
    assert!(matches!(
        registry.admit(&saturated),
        Ok(Admission::Verified(_))
    ));
    assert!(matches!(
        advance_exec(&saturated, u64::MAX),
        Ok(ExecAdvance::Current(_))
    ));
}

#[test]
fn cookie_exhaustion_refuses() {
    let mut registry = IdentityRegistry::new(domain_a(), 2);
    assert!(matches!(
        registry.admit(&id(domain_a(), 51, 0)),
        Ok(Admission::Attached(_))
    ));
    assert!(matches!(
        registry.admit(&id(domain_a(), 52, 0)),
        Ok(Admission::Attached(_))
    ));
    let err = registry
        .admit(&id(domain_a(), 53, 0))
        .expect_err("registry over limit refuses");
    assert_eq!(
        kind_stage(&err),
        (ErrorKind::LimitExceeded, Stage::Admission)
    );
    assert_eq!(registry.len(), 2, "exhaustion binds nothing new");
    // Admitted cookies keep verifying under exhaustion.
    assert!(matches!(
        registry.admit(&id(domain_a(), 51, 0)),
        Ok(Admission::Verified(_))
    ));
    // A zero limit is structurally valid but admits no positive work.
    let mut empty = IdentityRegistry::new(domain_a(), 0);
    assert_eq!(
        kind_stage(
            &empty
                .admit(&id(domain_a(), 51, 0))
                .expect_err("zero-limit registry refuses attach")
        ),
        (ErrorKind::LimitExceeded, Stage::Admission)
    );
}

#[test]
fn wire_layout_matches_c_abi() {
    assert_eq!(size_of::<IdentityWire>(), 32);
    assert_eq!(align_of::<IdentityWire>(), 8);
    assert_eq!(offset_of!(IdentityWire, domain), 0);
    assert_eq!(offset_of!(IdentityWire, task_cookie), 16);
    assert_eq!(offset_of!(IdentityWire, exec_generation), 24);
    let identity = id(domain_a(), 0x0102_0304_0506_0708, 0x1112_1314_1516_1718);
    let wire = identity.to_wire();
    assert_eq!(wire.domain, domain_a().0);
    assert_eq!(wire.task_cookie, 0x0102_0304_0506_0708);
    assert_eq!(wire.exec_generation, 0x1112_1314_1516_1718);
    assert_eq!(IdentityWire::from_wire(&wire).expect("roundtrip"), identity);
    // A forged all-zero wire record never decodes into an identity.
    let zeroed = IdentityWire {
        domain: [0u8; 16],
        task_cookie: 0,
        exec_generation: 0,
    };
    assert_eq!(
        kind_stage(&IdentityWire::from_wire(&zeroed).expect_err("zero wire refuses")),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
}

fn fixture_domain(value: &Json) -> ProducerDomain {
    let bytes = value.as_arr().expect("domain array");
    assert_eq!(bytes.len(), 16, "domains are 16 bytes");
    let mut raw = [0u8; 16];
    for (slot, byte) in raw.iter_mut().zip(bytes.iter()) {
        *slot = u8::try_from(byte.as_u64().expect("domain byte")).expect("byte range");
    }
    ProducerDomain(raw)
}

#[test]
fn fixture_vectors_drive_attach_verify_refuse() {
    let root = json_mini::parse(VECTORS).expect("vectors parse");
    let domain_a = fixture_domain(root.get("domain_a").expect("domain_a"));
    let domain_b = fixture_domain(root.get("domain_b").expect("domain_b"));
    let limit = root.get("limit").expect("limit").as_usize().expect("limit");
    let mut registry = IdentityRegistry::new(domain_a, limit);
    let cases = root.get("cases").expect("cases").as_arr().expect("cases");
    assert!(!cases.is_empty(), "vectors carry at least one case");
    for (index, case) in cases.iter().enumerate() {
        let tag = format!("case {index}");
        let domain = match case.get("domain").expect(&tag).as_str().expect(&tag) {
            "a" => domain_a,
            "b" => domain_b,
            other => panic!("{tag}: unknown domain {other:?}"),
        };
        let cookie = case.get("cookie").expect(&tag).as_u64().expect(&tag);
        let exec = case.get("exec").expect(&tag).as_u64().expect(&tag);
        let expect = case.get("expect").expect(&tag).as_str().expect(&tag);
        let outcome = match ProducerIdentity::checked(domain, cookie, exec) {
            Err(err) => format!("refused:{:?}", err.kind()),
            Ok(identity) => match registry.admit(&identity) {
                Ok(Admission::Attached(_)) => "attached".to_string(),
                Ok(Admission::Verified(_)) => "verified".to_string(),
                Ok(Admission::Advanced { .. }) => "advanced".to_string(),
                Err(err) => format!("refused:{:?}", err.kind()),
            },
        };
        assert_eq!(outcome, expect, "{tag}: cookie={cookie} exec={exec}");
        if let Ok(expected_len) = case.get("registry_len").map(|v| v.as_usize()) {
            assert_eq!(
                registry.len(),
                expected_len.expect(&tag),
                "{tag}: registry size after outcome"
            );
        }
    }
}

#[test]
fn ledger_schema_declares_tt05_consumer_contract() {
    // Structural presence only: the TT05-owned fork/exec operation ledger
    // executes these records; BP08 only declares what it consumes. Live
    // H01/H03/H08 cells stay NOT_RUN until the TT05 binding exists.
    let root = json_mini::parse(LEDGER_SCHEMA).expect("ledger schema parses");
    assert_eq!(
        root.get("schema_version")
            .expect("version")
            .as_u64()
            .expect("v"),
        1
    );
    assert_eq!(
        root.get("owner").expect("owner").as_str().expect("owner"),
        "TT05"
    );
    let required = root
        .get("required_operation_fields")
        .expect("fields")
        .as_arr()
        .expect("fields");
    for field in ["op_id", "op", "syscall_ok", "expected_exec"] {
        assert!(
            required.iter().any(|v| v.as_str() == Ok(field)),
            "ledger requires {field}"
        );
    }
    let ops = root.get("ops").expect("ops").as_arr().expect("ops");
    for op in [
        "fork",
        "clone_thread",
        "exec_success",
        "exec_failed",
        "barrier",
    ] {
        assert!(
            ops.iter().any(|v| v.as_str() == Ok(op)),
            "ledger covers op {op}"
        );
    }
}

fn fixture_probe(case: &Json) -> ExecShapeProbe {
    let flag = |key: &str| case.get(key).expect(key).as_bool().expect(key);
    ExecShapeProbe {
        newer_exec_state_present: flag("newer_exec_state_present"),
        mm_present: flag("mm_present"),
        mm_size_ok: flag("mm_size_ok"),
        scalar_present: flag("scalar_present"),
        scalar_word_ok: flag("scalar_word_ok"),
        bitmap_present: flag("bitmap_present"),
        bitmap_word_ok: flag("bitmap_word_ok"),
    }
}

#[test]
fn exec_shape_guards_precede_reads() {
    // Guard-order truth table adapted from the donor CO-RE predicate:
    // existence guards precede size/offset/read paths; a newer exec_state
    // layout refuses without reading it; scalar and bitmap flag shapes
    // take their own safe compiled paths; anything else refuses.
    let root = json_mini::parse(EXEC_SHAPES).expect("exec shapes parse");
    let cases = root.get("cases").expect("cases").as_arr().expect("cases");
    assert!(!cases.is_empty(), "shape table carries rows");
    for (index, case) in cases.iter().enumerate() {
        let tag = format!("shape case {index}");
        let probe = fixture_probe(case);
        let expect = case.get("expect").expect(&tag).as_str().expect(&tag);
        let plan = plan_exec_read(&probe);
        let got = match plan {
            ExecReadPlan::Refuse => "refuse",
            ExecReadPlan::ReadScalarMmFlags => "read_scalar",
            ExecReadPlan::ReadBitmapMmFlags => "read_bitmap",
        };
        assert_eq!(got, expect, "{tag}: {probe:?}");
    }
    // Direct order checks: a newer exec_state poisons even a perfect
    // scalar shape, and a missing mm refuses before any flag read.
    let perfect_scalar = ExecShapeProbe {
        newer_exec_state_present: false,
        mm_present: true,
        mm_size_ok: true,
        scalar_present: true,
        scalar_word_ok: true,
        bitmap_present: false,
        bitmap_word_ok: false,
    };
    assert_eq!(
        plan_exec_read(&perfect_scalar),
        ExecReadPlan::ReadScalarMmFlags
    );
    let poisoned = ExecShapeProbe {
        newer_exec_state_present: true,
        ..perfect_scalar
    };
    assert_eq!(plan_exec_read(&poisoned), ExecReadPlan::Refuse);
    let no_mm = ExecShapeProbe {
        mm_present: false,
        ..perfect_scalar
    };
    assert_eq!(plan_exec_read(&no_mm), ExecReadPlan::Refuse);
}

#[cfg(feature = "producer-fixtures")]
#[test]
fn packaged_c_route_matches_host_contract() {
    // The packaged C headers carry compile-time layout asserts for real
    // consumers (verified here by exact marker presence; header compilation
    // itself is consumer-side, exercised locally with gcc at commit time).
    const TASK_IDENTITY_H: &str = include_str!("../include/scopebase/task_identity.h");
    const PRODUCER_CONTRACT_H: &str = include_str!("../include/scopebase/producer_contract.h");
    const PRODUCER_C: &str = include_str!("../fixtures/identity-v1/producer.c");
    for marker in [
        "scopebase_producer_identity_v1",
        "producer_domain[16]",
        "task_cookie",
        "exec_generation",
        "SCOPEBASE_IDENTITY_OK",
        "SCOPEBASE_IDENTITY_ZERO_COOKIE",
        "SCOPEBASE_IDENTITY_EXHAUSTED",
        "_Static_assert",
        "32",
    ] {
        assert!(
            TASK_IDENTITY_H.contains(marker),
            "task_identity.h carries {marker}"
        );
    }
    for marker in [
        "scopebase_identity_assign_task_v1",
        "scopebase_identity_advance_exec_v1",
        "task_identity.h",
    ] {
        assert!(
            PRODUCER_CONTRACT_H.contains(marker),
            "producer_contract.h carries {marker}"
        );
    }
    for marker in [
        "scopebase_identity_assign_task_v1",
        "scopebase_identity_advance_exec_v1",
        "producer_contract.h",
    ] {
        assert!(PRODUCER_C.contains(marker), "producer.c exercises {marker}");
    }
}
