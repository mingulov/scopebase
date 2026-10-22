// SPDX-License-Identifier: Apache-2.0
//! External public-API consumer: retained bytes and actual Any owner survive
//! temporary entry arrays; assertions compare independently supplied data/owner.
#[path = "fixtures/fixture-access/local_arrays.rs"]
mod consumer;
#[test]
fn prepared_access_survives_local_entry_arrays() {
    consumer::run_checks();
}
