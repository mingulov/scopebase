// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::procfs::MapsSnapshot;
fn reject(s:MapsSnapshot){
    let e = s.entries().next().unwrap();
    drop(s);
    let _ = e.raw_path();
}
fn main(){}
