// SPDX-License-Identifier: Apache-2.0
use super::*;
#[test]
fn review_b5_owned_copy_meter_precedes_clone() {
    use std::{cell::Cell, rc::Rc};
    struct Payload {
        bytes: String,
        clones: Rc<Cell<usize>>,
    }
    impl Clone for Payload {
        fn clone(&self) -> Self {
            self.clones.set(self.clones.get() + 1);
            Self {
                bytes: self.bytes.clone(),
                clones: self.clones.clone(),
            }
        }
    }
    impl Serialize for Payload {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&self.bytes)
        }
    }
    let clones = Rc::new(Cell::new(0));
    let value = Payload {
        bytes: "x".repeat(64),
        clones: clones.clone(),
    };
    let mut meter = RetainedPayload::new(100, 200).unwrap();
    let first = meter.cloned(&value).unwrap();
    assert_eq!(meter.used, 166);
    assert!(meter.cloned(&value).is_err());
    assert_eq!(meter.used, 166);
    assert_eq!(
        clones.get(),
        1,
        "refused copy must not allocate/clone its payload"
    );
    drop(first);
    let mut restored = RetainedPayload::new(100, 300).unwrap();
    let _first = restored.cloned(&value).unwrap();
    let _second = restored.cloned(&value).unwrap();
    assert_eq!(restored.used, 232);
    assert_eq!(clones.get(), 3);
}
use std::io::Write;
#[test]
fn independently_counted_short_reads_and_sentinel() {
    let path = std::env::temp_dir().join(format!(
        "tt02-short-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut file = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.write_all(b"abc").unwrap();
    let l = RunLimits::default();
    let binding = ArtifactBinding::new(
        ArtifactBindingValues {
            id: Label::parse("short").unwrap(),
            revision: 1,
            role: ArtifactRole::ConsumerExecutable,
            length: 3,
            sha256: Digest256::parse(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )
            .unwrap(),
        },
        &l,
    )
    .unwrap();
    let mut meter = ArtifactMeasurer::new(
        RunId::parse("0123456789abcdef0123456789abcdef").unwrap(),
        l.clone(),
    )
    .unwrap();
    let mut count = 0;
    meter
        .read_with(&binding, &file, false, |f, b, o| {
            count += 1;
            if count == 2 {
                return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
            }
            let n = b.len().min(1);
            f.read_at(&mut b[..n], o)
        })
        .unwrap();
    assert_eq!(count, 5);
    assert_eq!(meter.usage().read_calls, 5);
    assert_eq!(meter.usage().bytes_returned, 3);
    assert_eq!(meter.usage().bytes_hashed, 3);
    let mut meter =
        ArtifactMeasurer::new(RunId::parse("0123456789abcdef0123456789abcdef").unwrap(), l)
            .unwrap();
    let error = meter
        .read_with(&binding, &file, false, |f, b, o| {
            if o == 3 {
                f.write_at(b"x", 3)?;
            }
            f.read_at(b, o)
        })
        .unwrap_err();
    assert_eq!(error.kind(), BindingErrorKind::LengthMismatch);
    assert_eq!(error.progress().unwrap().bytes_returned(), 4);
    assert_eq!(meter.usage().bytes_hashed, 3);
    assert_eq!(meter.usage().reserved_bytes, 4);
    std::fs::remove_file(path).unwrap();
}
