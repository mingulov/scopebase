// SPDX-License-Identifier: Apache-2.0
use super::*;
#[path = "../../tests/fixtures/harness/support.rs"]
mod support;
#[test]
fn review_a2_vector_owner_preserves_pointer_and_capacity() {
    let mut bytes = Vec::with_capacity(8_388_608);
    bytes.resize(8_388_608, b'x');
    let pointer = bytes.as_ptr();
    let capacity = bytes.capacity();
    let owner = share_vector(bytes);
    assert_eq!(
        owner.as_ptr(),
        pointer,
        "the verified Vec payload must move without cloning"
    );
    assert_eq!(owner.capacity(), capacity);
    let alias = Arc::clone(&owner);
    assert!(Arc::ptr_eq(&owner, &alias));
    assert_eq!(alias.as_ptr(), pointer);
}
#[test]
fn review_b5_builtin_truth_shares_retained_vector_payload() {
    let (_, _, c) = support::load();
    let mut session = support::session(c.clone());
    let expected = session.bundle.files[&Label::parse("expected").unwrap()]
        .as_ref()
        .as_ptr();
    let ledger = session.bundle.files[&Label::parse("ledger").unwrap()]
        .as_ref()
        .as_ptr();
    let rule = &c.case_rules()[0];
    let i = CaseInvocation::new(
        CaseInvocationValues {
            key: c.schedule()[0].clone(),
            observation_schema: rule.observation_schema().clone(),
            fixture_schema: rule.fixture_schema().clone(),
            script: rule.script().clone(),
            limits: c.limits().clone(),
        },
        c.limits(),
    )
    .unwrap();
    {
        let access = session.prepare(&i).unwrap();
        assert_eq!(
            access.input(&Label::parse("operands").unwrap()).unwrap(),
            b"2\n3\n"
        );
    }
    let actual = session.collect(&i).unwrap();
    assert_eq!(
        actual.expected_bytes().as_ptr(),
        expected,
        "builtin expected truth must not make an unreserved owned copy"
    );
    assert_eq!(
        actual.ledger_bytes().as_ptr(),
        ledger,
        "builtin ledger must share its verified immutable storage"
    );
    let cloned = actual.clone();
    assert_eq!(
        actual.expected_bytes().as_ptr(),
        cloned.expected_bytes().as_ptr()
    );
}
