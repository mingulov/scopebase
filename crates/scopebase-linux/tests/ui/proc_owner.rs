// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::{file::HeldFile,procfs::MapsSnapshot};
fn reject(s:MapsSnapshot){
    let _:HeldFile = s.into();
}
fn main(){}
