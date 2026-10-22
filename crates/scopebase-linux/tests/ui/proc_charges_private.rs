// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::procfs::ParseCharges;
fn reject(c:ParseCharges){
    let _ = c.entries_validated;
}
fn main(){}
