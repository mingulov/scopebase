// SPDX-License-Identifier: Apache-2.0
use scopebase_capture::quantity::*;
fn unit_only<U: Unit>() {
    let a = Count::<U>::new(0);
    let b = a;
    let _ = a == b;
    let _ = format!("{a:?}");
    let _ = CountBounds::new(a, Some(b)).unwrap();
}
fn main() {
    unit_only::<Events>();
    unit_only::<Records>();
    unit_only::<Bytes>();
    unit_only::<Objects>();
    unit_only::<Attempts>();
    unit_only::<Nonexecutions>();
    unit_only::<DiagnosticSignals>();
}
