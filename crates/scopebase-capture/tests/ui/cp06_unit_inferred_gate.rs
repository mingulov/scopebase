// SPDX-License-Identifier: Apache-2.0
use scopebase_capture::quantity::Unit;
fn impossible<T>() -> T {
    loop {}
}
fn gate<U: Unit>() {
    U::unit_tag(impossible());
}
fn main() {
    gate::<scopebase_capture::quantity::Events>();
}
