// SPDX-License-Identifier: Apache-2.0
use scopebase_bpf::{ErrorKind, Limits, OperationError, Stage};
use std::error::Error;
use std::fmt;
use std::io;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

const KINDS: [ErrorKind; 11] = [
    ErrorKind::InvalidInput,
    ErrorKind::Malformed,
    ErrorKind::Incompatible,
    ErrorKind::Unsupported,
    ErrorKind::Denied,
    ErrorKind::Disappeared,
    ErrorKind::Changed,
    ErrorKind::LimitExceeded,
    ErrorKind::Overflow,
    ErrorKind::Backend,
    ErrorKind::Poisoned,
];
const STAGES: [Stage; 11] = [
    Stage::Admission,
    Stage::Metadata,
    Stage::Allocate,
    Stage::Read,
    Stage::Attach,
    Stage::Drain,
    Stage::Retire,
    Stage::BtfQuery,
    Stage::Compile,
    Stage::Inspect,
    Stage::Execute,
];

#[test]
fn error_fields_are_lossless() {
    for kind in KINDS {
        for stage in STAGES {
            for errno in [
                None,
                Some(13),
                Some(524),
                Some(0),
                Some(-1),
                Some(i32::MIN),
                Some(i32::MAX),
            ] {
                let e = OperationError::new(kind, stage, errno, None);
                assert_eq!(e.kind(), kind, "caller kind was changed");
                assert_eq!(e.stage(), stage, "caller stage was changed");
                assert_eq!(e.raw_os_error(), errno, "caller errno was changed");
                assert!(e.source().is_none());
            }
        }
    }
    let denied = OperationError::new(ErrorKind::Denied, Stage::Admission, Some(13), None);
    let backend = OperationError::new(ErrorKind::Backend, Stage::Execute, Some(13), None);
    assert_eq!(
        (denied.kind(), denied.stage()),
        (ErrorKind::Denied, Stage::Admission)
    );
    assert_eq!(
        (backend.kind(), backend.stage()),
        (ErrorKind::Backend, Stage::Execute)
    );
    for errno in [None, Some(524)] {
        let e = OperationError::new(
            ErrorKind::Changed,
            Stage::Read,
            errno,
            Some(Box::new(io::Error::from_raw_os_error(13))),
        );
        assert_eq!(
            e.raw_os_error(),
            errno,
            "source must not supply/reconcile errno"
        );
        assert_eq!(
            e.source()
                .unwrap()
                .downcast_ref::<io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(13)
        );
    }
}

#[derive(Debug)]
struct Sentinel {
    nested: io::Error,
}
impl fmt::Display for Sentinel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sentinel")
    }
}
impl Error for Sentinel {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.nested)
    }
}

#[test]
fn source_identity_and_chain_survive() {
    let source = Box::new(Sentinel {
        nested: io::Error::from_raw_os_error(13),
    });
    let address = &*source as *const Sentinel;
    let e = OperationError::new(ErrorKind::Backend, Stage::Execute, Some(524), Some(source));
    let original = e
        .source()
        .expect("original source missing")
        .downcast_ref::<Sentinel>()
        .expect("source type erased/replaced");
    assert_eq!(
        original as *const Sentinel, address,
        "source identity changed"
    );
    assert_eq!(
        original
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(13)
    );
    assert!(
        OperationError::new(ErrorKind::Backend, Stage::Read, None, None)
            .source()
            .is_none()
    );
}

#[test]
fn required_size_is_optional_and_replaced() {
    let source = Box::new(Sentinel {
        nested: io::Error::from_raw_os_error(13),
    });
    let address = &*source as *const Sentinel;
    let mut e = OperationError::new(
        ErrorKind::LimitExceeded,
        Stage::Allocate,
        Some(-1),
        Some(source),
    );
    assert_eq!(e.required_size(), None);
    for size in [0, 7, usize::MAX, 0] {
        e = e.with_required_size(size);
        assert_eq!(
            e.required_size(),
            Some(size),
            "required size was normalized/clamped"
        );
        assert_eq!(
            (e.kind(), e.stage(), e.raw_os_error()),
            (ErrorKind::LimitExceeded, Stage::Allocate, Some(-1))
        );
        assert_eq!(
            e.source().unwrap().downcast_ref::<Sentinel>().unwrap() as *const Sentinel,
            address
        );
    }
}

struct PrivateSource {
    calls: Arc<AtomicUsize>,
    panics: bool,
}
impl fmt::Display for PrivateSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panics, "source formatter invoked");
        f.write_str("PRIVATE_SOURCE_λ")
    }
}
impl fmt::Debug for PrivateSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl Error for PrivateSource {}

fn formatted(e: &OperationError) -> [String; 6] {
    [
        format!("{e}"),
        format!("{e:#}"),
        format!("{e:?}"),
        format!("{e:#?}"),
        format!("{:?}", [e]),
        format!("{:#?}", Some(e)),
    ]
}

#[test]
fn formatting_is_bounded_and_does_not_touch_source() {
    let calls = Arc::new(AtomicUsize::new(0));
    for kind in KINDS {
        for stage in STAGES {
            for errno in [None, Some(0), Some(i32::MIN), Some(i32::MAX)] {
                for required in [None, Some(0), Some(usize::MAX)] {
                    let mut e = OperationError::new(
                        kind,
                        stage,
                        errno,
                        Some(Box::new(PrivateSource {
                            calls: calls.clone(),
                            panics: false,
                        })),
                    );
                    if let Some(n) = required {
                        e = e.with_required_size(n);
                    }
                    let texts = formatted(&e);
                    assert_eq!(
                        calls.load(Ordering::SeqCst),
                        0,
                        "source formatter was called"
                    );
                    for text in texts {
                        assert!(
                            text.is_ascii() && text.len() <= 256,
                            "diagnostic exceeded ASCII/size bound"
                        );
                        assert!(!text.contains("PRIVATE_SOURCE"));
                        assert!(
                            text.contains(&format!("{kind:?}"))
                                && text.contains(&format!("{stage:?}"))
                        );
                    }
                    assert_eq!(
                        calls.load(Ordering::SeqCst),
                        0,
                        "source formatter was called"
                    );
                    let display = e.to_string();
                    assert!(display.starts_with(&format!("scopebase-bpf {stage:?}/{kind:?}")));
                    if let Some(n) = errno {
                        assert!(display.contains(&format!("(os error {n})")));
                    }
                    if let Some(n) = required {
                        assert!(display.contains(&format!("(required bytes {n})")));
                    }
                }
            }
        }
    }
    let e = OperationError::new(
        ErrorKind::Backend,
        Stage::Execute,
        None,
        Some(Box::new(PrivateSource {
            calls: calls.clone(),
            panics: true,
        })),
    );
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| formatted(&e))).is_ok(),
        "source formatter panic escaped diagnostic formatting"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let empty = OperationError::new(ErrorKind::Malformed, Stage::Read, None, None);
    assert!(format!("{empty:?}").contains("source_present=false"));
    assert!(format!("{e:?}").contains("source_present=true"));
}

fn limits(v: [usize; 5], work_steps: u64) -> Limits {
    Limits {
        input_bytes: v[0],
        retained_bytes: v[1],
        sites: v[2],
        live_links: v[3],
        pending_retirements: v[4],
        work_steps,
    }
}

#[test]
fn limits_all_representable_caps_are_configuration() {
    let mut populations = vec![
        limits([0; 5], 0),
        limits([usize::MAX; 5], u64::MAX),
        limits([1, 19, 71, 2, 37], 3),
        limits([31, 1, 0, 7, 2], 29),
    ];
    for i in 0..6 {
        let mut maxima = [usize::MAX; 5];
        let mut zeros = [0; 5];
        if i < 5 {
            maxima[i] = 0;
            zeros[i] = usize::MAX;
        }
        populations.push(limits(maxima, if i == 5 { 0 } else { u64::MAX }));
        populations.push(limits(zeros, if i == 5 { u64::MAX } else { 0 }));
    }
    for value in populations {
        let before = value;
        assert!(
            value.validate().is_ok(),
            "independent caps rejected: {value:?}"
        );
        assert_eq!(value, before, "validation mutated configuration");
    }
}

#[test]
fn public_value_traits() {
    fn send_sync<T: Send + Sync>() {}
    fn copy_eq<T: Copy + Clone + PartialEq + Eq + fmt::Debug>(v: T) {
        let copied = v;
        assert_eq!(copied, v);
    }
    send_sync::<ErrorKind>();
    send_sync::<Stage>();
    send_sync::<Limits>();
    send_sync::<OperationError>();
    copy_eq(ErrorKind::Changed);
    copy_eq(Stage::Inspect);
    copy_eq(limits([0; 5], 0));
    let e = OperationError::new(ErrorKind::Backend, Stage::Read, None, None);
    let moved = e;
    let _: &(dyn Error + Send + Sync) = &moved;
    assert_eq!(moved.kind(), ErrorKind::Backend);
}
