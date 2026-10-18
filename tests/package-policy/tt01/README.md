# TT01 package-policy integration inputs

`member.json` is the exact product-member fragment for controller insertion into
root `package-policy.json`. Retain every existing member and source/build grant.
Its mandatory serde/serde_json closure is the already admitted 11-package SB02
inventory; no source acquisition or dependency-version update is required.
`minimal_dependencies` names that exact allowed closure in minimal/default cells.
The controller's reviewed package-policy helper extension admits this explicit
mandatory closure while preserving older members' checks.

Add `crates/scopebase-testkit` to root Cargo workspace members and default-members,
then generate the root lock offline through the existing build lease using the
admitted inventory. The package itself owns no root lock/policy edit. Its version,
edition, MSRV and Apache-2.0 license are literal in the package manifest.

Keep supported_unions empty. The existing matrix executes client0 (inventory)
for both minimal and default on Rust 1.88.0 and 1.98.1. The task adapter explicitly
runs client1 (selection) against the very same admitted/unpacked archive in fresh
independent roots, with real metadata/lock admission. Neither feature unions nor
client counts may be invented to disguise this second route.

The complete archive file list includes Cargo's normalized/original manifests and
lock, source, license/notices, developer tests, canonical catalog/schema copies,
revision fixtures, literal invalid populations and harmless registration bytes.
The two client files contain independent literal inputs and independent expected
results. They exercise actual archive-derived library exports and import no
production-domain package. These checks establish registry package behavior only.
