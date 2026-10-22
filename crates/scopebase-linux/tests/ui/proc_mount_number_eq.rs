// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::procfs::ParsedMountId;
fn reject(id:ParsedMountId<'_>){
    let _ = id == 17u64;
}
fn main(){}
