#![no_main]
// SPDX-License-Identifier: Apache-2.0
//! BP09 bounded-BTF input-boundary fuzz target (parse only).
//!
//! Exercises base and split admission over fixed small budgets. Any input
//! must terminate with `Ok` or a typed `Err`; a panic, hang or runaway
//! allocation is a target failure. Queries are covered by `tests/btf.rs`.
use libfuzzer_sys::fuzz_target;
use scopebase_bpf::btf::{BtfImages, BtfLimits, BtfView, ByteOrder};

const LIMITS: BtfLimits = BtfLimits {
    image_bytes: 4096,
    types: 256,
    strings: 4096,
    wrapper_depth: 8,
    work_steps: 100_000,
};

fuzz_target!(|data: &[u8]| {
    let _ = BtfView::parse(
        BtfImages {
            base: data,
            module: None,
            byte_order: ByteOrder::Little,
        },
        LIMITS,
    );
    if data.len() >= 2 {
        let (base, module) = data.split_at(data.len() / 2);
        let _ = BtfView::parse(
            BtfImages {
                base,
                module: Some(module),
                byte_order: ByteOrder::Little,
            },
            LIMITS,
        );
    }
});
