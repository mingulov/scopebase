// SPDX-License-Identifier: Apache-2.0
use scopebase_bpf::{ErrorKind, OperationError, Stage};
use std::{fmt, rc::Rc};
#[derive(Debug)]
struct Local(Rc<()>);
impl fmt::Display for Local {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
impl std::error::Error for Local {}
fn main() {
    let _ = OperationError::new(
        ErrorKind::Backend,
        Stage::Read,
        None,
        Some(Box::new(Local(Rc::new(())))),
    );
}
