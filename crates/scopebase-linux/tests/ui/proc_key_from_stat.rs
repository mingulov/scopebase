// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::identity::{StatFileKey,MapsFileKey};
fn reject(s:StatFileKey){
    let _: MapsFileKey = s.into();
}
fn main(){}
