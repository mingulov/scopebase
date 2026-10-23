// SPDX-License-Identifier: Apache-2.0
use scopebase_bpf::btf::{BtfImages, BtfLimits, BtfView, ByteOrder};
use scopebase_bpf::{ErrorKind, Stage};
fn main() {
    let limits = BtfLimits {
        image_bytes: 1 << 20,
        types: 4096,
        strings: 1 << 20,
        wrapper_depth: 16,
        work_steps: 1_000_000,
    };
    let error = BtfView::parse(
        BtfImages {
            base: &[],
            module: None,
            byte_order: ByteOrder::Little,
        },
        limits,
    )
    .expect_err("empty base image must refuse");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(error.stage(), Stage::Admission);
}
