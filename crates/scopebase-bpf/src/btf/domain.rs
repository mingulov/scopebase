// SPDX-License-Identifier: Apache-2.0
//! Exact BTF domain identity and caller budgets.
//!
//! A domain binds the exact admitted base bytes plus the exact optional
//! module bytes. Type ids are meaningless outside their domain: every query
//! refuses foreign [`TypeRef`] values before touching the parser.

/// SHA-256 identity of the exact admitted image bytes.
///
/// Computed over a domain-separated transcript of the base length, base
/// bytes, module presence, module length and module bytes. Equal ids mean
/// byte-identical admissions; the id binds bytes only, never semantic
/// layout, loader acceptance or kernel behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BtfDomainId(pub [u8; 32]);

/// Domain-bound reference to one BTF type.
///
/// The id is the parser-visible global id: base ids run `1..=n`, split
/// module ids relocate above the base population. Id `0` (VOID) never
/// addresses a stored type; it appears only as [`TypeKind::Pointer::to`]
/// (a `void *` pointee) and [`FunctionShape::result`] (a `void` return).
/// Every other constructor and every query input refuses id `0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TypeRef {
    /// Domain whose parser owns the id.
    pub domain: BtfDomainId,
    /// Global parser-visible type id.
    pub id: u32,
}

/// Independent caller caps for one BTF admission and its queries.
///
/// All representable configurations are structurally valid, including zero
/// and the type maximum; there is no implicit unlimited sentinel and no
/// `Default`. A zero cap refuses the corresponding positive work or
/// resource at admission. Caps are independent: no cross-field inequality
/// is implied. Budgets apply per call: parsing consumes one work budget,
/// and each later query draws a fresh budget of the same size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtfLimits {
    /// Maximum admitted bytes per image (base and module separately).
    pub image_bytes: usize,
    /// Maximum type records per image.
    pub types: usize,
    /// Maximum string-section bytes per image.
    pub strings: usize,
    /// Maximum wrapper/alias and anonymous-descent nesting depth.
    pub wrapper_depth: usize,
    /// Maximum accounting steps per call (the portable time proxy: every
    /// loop charges steps, so wall time is proportional to admitted
    /// structure under this cap; no wall-clock deadline is imposed).
    pub work_steps: u64,
}
