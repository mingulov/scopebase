// SPDX-License-Identifier: Apache-2.0
//! Must fail E0624 on type_by_id only after public aya-btf positive compiles.
pub fn private_query(btf: &aya_obj::btf::Btf) {
    let _ = btf.type_by_id(1); // Expected E0624: intended private API line.
}
