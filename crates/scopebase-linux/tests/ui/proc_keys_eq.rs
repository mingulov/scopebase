// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::identity::{StatFileKey,MapsFileKey};
fn reject(s:StatFileKey,m:MapsFileKey){
    let _ = s == m;
}
fn main(){}
