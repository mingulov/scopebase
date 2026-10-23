// SPDX-License-Identifier: Apache-2.0
//! BP10: independent adapters consumer over the public API only.
//!
//! Exercises loader admission, the native configure state machine, the
//! output ledger and inline vector parsing through
//! `scopebase_bpf::adapters` exactly as a downstream crate would. Live
//! loader attach needs a privileged kernel and stays out of this example.
use scopebase_bpf::adapters::{
    admit_loader, parse_configure_vector, LoaderId, LoaderVersion, NativeConfig, NativeState,
    OutputLedger, OutputSpan,
};
use scopebase_bpf::{ErrorKind, Limits};

fn main() {
    let limits = Limits {
        input_bytes: 1 << 20,
        retained_bytes: 1 << 20,
        work_steps: 1 << 20,
        sites: 64,
        live_links: 64,
        pending_retirements: 64,
    };
    let admitted = admit_loader(LoaderId::Aya, &LoaderVersion::new(0, 14, 0)).unwrap();
    assert_eq!(admitted.version(), LoaderVersion::new(0, 14, 0));
    assert_eq!(
        admit_loader(LoaderId::Aya, &LoaderVersion::new(0, 13, 0))
            .unwrap_err()
            .kind(),
        ErrorKind::Incompatible
    );
    let mut state = NativeState::new(NativeConfig::new(true, 0, 1));
    state.configure(&NativeConfig::new(true, 0, 2)).unwrap();
    let ledger = OutputLedger::admit(&[OutputSpan {
        id: 1,
        sentinel: [0xA5; 8],
    }])
    .unwrap();
    assert_eq!(ledger.sentinel(1), Some([0xA5; 8]));
    let vector = parse_configure_vector(
        br#"{"schema_version":1,"kind":"bp10_native_configure_vector","cases":[]}"#,
        &limits,
    )
    .unwrap();
    assert!(vector.cases().is_empty());
    println!("bp10 adapters smoke: admission, configure, ledger and vectors OK");
}
