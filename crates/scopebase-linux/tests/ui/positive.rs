// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::{file::{HeldFile, ProcFdResolver}, identity::StatObservation};
use std::{os::fd::{AsFd, AsRawFd}, sync::Arc};
fn check(value: HeldFile, resolver: ProcFdResolver, stat: StatObservation) {
    let _reference: &HeldFile = Clone::clone(&&value);
    let _resolver_reference: &ProcFdResolver = Clone::clone(&&resolver);
    let borrow = value.as_fd();
    let _ = borrow.as_raw_fd();
    let _ = Arc::clone(&Arc::new(value));
    let _ = Arc::clone(&Arc::new(resolver));
    let _ = (stat.key().device_raw(), stat.key().inode(), stat.len(), stat.mtime(), stat.ctime());
}
fn adopt(file: std::fs::File) { let _ = HeldFile::from_file(file); }
fn send_sync<T: Send + Sync>() {}
fn main() { send_sync::<HeldFile>(); send_sync::<ProcFdResolver>(); }
