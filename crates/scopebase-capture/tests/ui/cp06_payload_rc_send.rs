// SPDX-License-Identifier: Apache-2.0
use scopebase_capture::correction::Versioned;
use std::rc::Rc;
fn needs_send<T: Send>() {}
fn main() {
    needs_send::<Versioned<Rc<()>>>();
}
