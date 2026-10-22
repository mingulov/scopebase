// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::identity::MapsFileKey;
fn reject(m:MapsFileKey){
    let _ = m.major;
}
fn main(){}
