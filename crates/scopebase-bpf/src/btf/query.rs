// SPDX-License-Identifier: Apache-2.0
//! Bounded domain-aware semantic queries over the admitted BTF graph.
//!
//! Every query revalidates domain membership, charges the per-call work
//! budget for each traversed element, and resolves references against the
//! admitted population: dangling ids are corrupt images, never silent
//! stops. Same-name lookup returns every bounded candidate in ascending
//! id order; callers impose their own identity rules on exact ids.

use crate::btf::adapt::{map_query_error, WorkBudget};
use crate::btf::domain::TypeRef;
use crate::btf::BtfView;
use crate::{ErrorKind, OperationError, Stage};

/// Caller-visible shape of one admitted type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeKind {
    /// Integer with exact value width (not storage width) and signedness.
    Integer {
        /// Value width in bits, from the INT aux word.
        bits: u16,
        /// Signed encoding bit.
        signed: bool,
    },
    /// Pointer; `to` is the direct pointee (`id 0` for `void *`).
    Pointer {
        /// Direct pointee reference.
        to: TypeRef,
    },
    /// Structure.
    Struct,
    /// Union.
    Union,
    /// Array with direct element reference and element count.
    Array {
        /// Direct element type.
        element: TypeRef,
        /// Element count.
        count: u32,
    },
    /// Enum or enum64 with storage width and signedness.
    Enum {
        /// Storage width in bits, clamped to `u16::MAX`.
        bits: u16,
        /// Signed (kind-flag) form.
        signed: bool,
    },
    /// Function; use [`BtfView::function`] for the prototype.
    Function,
    /// Function prototype; use [`BtfView::function`] for the shape.
    FunctionPrototype,
    /// Any other admitted kind (forward, variable, datasec, float,
    /// qualifier-adjacent tags). Qualifier wrappers themselves are
    /// transparent: [`BtfView::shape`] chases them to their target.
    Other,
}

/// Resolved kind plus optional byte size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypeShape {
    /// Resolved kind.
    pub kind: TypeKind,
    /// Byte size where the kind carries one (`None` for functions,
    /// prototypes, variables, forwards and tags).
    pub size_bytes: Option<u64>,
}

/// Byte/bit extent of one struct or union member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberExtent {
    /// Whole-byte offset from the root parent.
    pub byte_offset: u64,
    /// Sub-byte remainder in bits.
    pub bit_offset: u8,
    /// Bitfield width, present only for kind-flag members.
    pub bit_width: Option<u8>,
    /// Member type size in bytes.
    pub size_bytes: u64,
    /// Exact (unchased) member type.
    pub ty: TypeRef,
}

/// Validated function prototype shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionShape {
    /// Return type (`id 0` for `void`).
    pub result: TypeRef,
    /// Parameter types in order, excluding the variadic marker.
    pub parameters: Vec<TypeRef>,
    /// True when the prototype ends with the `(0, 0)` marker.
    pub variadic: bool,
}

/// Width of a BPF target pointer in bytes (the profile is 64-bit; BTF
/// pointer records carry no size field).
const POINTER_SIZE: u64 = 8;

fn malformed_query() -> OperationError {
    OperationError::new(ErrorKind::Malformed, Stage::BtfQuery, None, None)
}

fn invalid_query() -> OperationError {
    OperationError::new(ErrorKind::InvalidInput, Stage::BtfQuery, None, None)
}

fn limit_query() -> OperationError {
    OperationError::new(ErrorKind::LimitExceeded, Stage::BtfQuery, None, None)
}

fn overflow_query() -> OperationError {
    OperationError::new(ErrorKind::Overflow, Stage::BtfQuery, None, None)
}

fn incompatible_query() -> OperationError {
    OperationError::new(ErrorKind::Incompatible, Stage::BtfQuery, None, None)
}

/// One located member before extent validation.
struct FoundMember {
    bit_off: u32,
    width: Option<u32>,
    mtype: u32,
}

impl BtfView {
    /// Return every type bearing `name`, in ascending id order.
    ///
    /// The empty name addresses every anonymous type. The locked parser
    /// indexes only anonymous composites and enums under the empty name,
    /// so the adapter completes the set from its own preflight facts;
    /// nonempty names delegate to the parser index, which is complete
    /// for nonzero offsets. Each candidate charges one work step; an
    /// empty result is a valid answer, not an error.
    pub fn types_named(&self, name: &str) -> Result<Vec<TypeRef>, OperationError> {
        let mut budget = WorkBudget::new(&self.limits);
        budget.consume(Stage::BtfQuery, 1)?;
        let mut ids = if name.is_empty() {
            self.facts
                .iter()
                .enumerate()
                .filter(|(_, facts)| facts.name_off == 0)
                .map(|(index, _)| index as u32 + 1)
                .collect()
        } else {
            self.parser
                .resolve_ids_by_name(name)
                .map_err(map_query_error)?
        };
        ids.sort_unstable();
        let mut refs = Vec::with_capacity(ids.len().min(self.facts.len()));
        for id in ids {
            budget.consume(Stage::BtfQuery, 1)?;
            refs.push(TypeRef {
                domain: self.domain,
                id,
            });
        }
        Ok(refs)
    }

    /// Resolve the kind and size of one admitted type.
    ///
    /// Qualifier wrappers (typedef, const, volatile, restrict) are
    /// transparent within the wrapper-depth budget. Foreign domains
    /// refuse as `Incompatible`; id `0` and out-of-range ids refuse as
    /// `InvalidInput`; dangling references refuse as `Malformed`.
    pub fn shape(&self, ty: TypeRef) -> Result<TypeShape, OperationError> {
        let id = self.check_ref(ty)?;
        let mut budget = WorkBudget::new(&self.limits);
        budget.consume(Stage::BtfQuery, 1)?;
        self.shape_inner(id, &mut budget)
    }

    /// Chase qualifier wrappers to the first unwrapped type.
    ///
    /// Typedef, const, volatile and restrict are transparent; tags,
    /// pointers, arrays and all other kinds are terminal and resolve to
    /// themselves. Cycles and `void`/dangling targets refuse as
    /// `Malformed`; chains longer than the wrapper depth refuse as
    /// `LimitExceeded`.
    pub fn canonical(&self, ty: TypeRef) -> Result<TypeRef, OperationError> {
        let id = self.check_ref(ty)?;
        let mut budget = WorkBudget::new(&self.limits);
        budget.consume(Stage::BtfQuery, 1)?;
        Ok(TypeRef {
            domain: self.domain,
            id: self.chase_wrapper(id, &mut budget)?,
        })
    }

    /// Resolve a member path to its root-relative extent.
    ///
    /// Each segment names a direct member; a missing name descends
    /// transparently through anonymous struct/union members within the
    /// wrapper-depth budget (direct matches shadow promoted ones, as in
    /// C). The empty segment addresses an immediate anonymous member.
    /// Returned offsets are absolute from the root parent, and every
    /// level is containment-checked against its immediate parent.
    pub fn member(&self, parent: TypeRef, path: &[&str]) -> Result<MemberExtent, OperationError> {
        let id = self.check_ref(parent)?;
        if path.is_empty() {
            return Err(invalid_query());
        }
        let mut budget = WorkBudget::new(&self.limits);
        budget.consume(Stage::BtfQuery, 1)?;
        let root = self.chase_wrapper(id, &mut budget)?;
        let (_, mut current_size) = self.composite_parts(root)?;
        let mut current = root;
        let mut absolute_bits: u64 = 0;
        let mut leaf: Option<(u64, Option<u32>, u32, u64)> = None;
        for (index, segment) in path.iter().enumerate() {
            budget.consume(Stage::BtfQuery, 1)?;
            let found = self.find_member(current, segment, &mut budget)?;
            if found.mtype == 0 || found.mtype as usize > self.facts.len() {
                return Err(malformed_query());
            }
            if found.width.is_none() && found.bit_off % 8 != 0 {
                return Err(malformed_query());
            }
            let size = self.sized_extent(found.mtype, &mut budget)?;
            let extent_bits = match found.width {
                Some(width) => u64::from(width),
                None => size.checked_mul(8).ok_or_else(overflow_query)?,
            };
            let end = u64::from(found.bit_off)
                .checked_add(extent_bits)
                .ok_or_else(overflow_query)?;
            if end > current_size.checked_mul(8).ok_or_else(overflow_query)? {
                return Err(malformed_query());
            }
            absolute_bits = absolute_bits
                .checked_add(u64::from(found.bit_off))
                .ok_or_else(overflow_query)?;
            if index + 1 == path.len() {
                leaf = Some((absolute_bits, found.width, found.mtype, size));
            } else {
                if found.width.is_some() {
                    return Err(malformed_query());
                }
                let next = self.chase_wrapper(found.mtype, &mut budget)?;
                (_, current_size) = self.composite_parts(next)?;
                current = next;
            }
        }
        let (total, width, mtype, size) = leaf.expect("nonempty path yields a leaf");
        Ok(MemberExtent {
            byte_offset: total / 8,
            bit_offset: (total % 8) as u8,
            bit_width: width.map(|value| value as u8),
            size_bytes: size,
            ty: TypeRef {
                domain: self.domain,
                id: mtype,
            },
        })
    }

    /// Resolve a function to its validated prototype shape.
    ///
    /// The target must be a function prototype; anything else well-formed
    /// refuses as `Incompatible`. Dangling ids, a non-trailing variadic
    /// marker and named `void` parameters refuse as `Malformed`.
    pub fn function(&self, ty: TypeRef) -> Result<FunctionShape, OperationError> {
        use btf_rs::BtfType as _;
        let id = self.check_ref(ty)?;
        let mut budget = WorkBudget::new(&self.limits);
        budget.consume(Stage::BtfQuery, 1)?;
        let target = match self.resolve(id)? {
            btf_rs::Type::Func(func) => func.get_type_id(),
            _ => return Err(incompatible_query()),
        };
        let proto_id = target.unwrap_or(0);
        if proto_id == 0 || proto_id as usize > self.facts.len() {
            return Err(malformed_query());
        }
        let proto = match self.resolve(proto_id)? {
            btf_rs::Type::FuncProto(proto) => proto,
            _ => return Err(incompatible_query()),
        };
        let result_id = proto.return_type_id();
        if result_id != 0 && result_id as usize > self.facts.len() {
            return Err(malformed_query());
        }
        let mut parameters = Vec::new();
        let mut variadic = false;
        for (index, param) in proto.parameters.iter().enumerate() {
            budget.consume(Stage::BtfQuery, 1)?;
            let last = index + 1 == proto.parameters.len();
            if param.is_variadic() {
                if !last {
                    return Err(malformed_query());
                }
                variadic = true;
                continue;
            }
            let param_id = param.get_type_id().unwrap_or(0);
            if param_id == 0 || param_id as usize > self.facts.len() {
                return Err(malformed_query());
            }
            parameters.push(TypeRef {
                domain: self.domain,
                id: param_id,
            });
        }
        Ok(FunctionShape {
            result: TypeRef {
                domain: self.domain,
                id: result_id,
            },
            parameters,
            variadic,
        })
    }

    /// Resolve a map variable to its key/value type linkage.
    ///
    /// `map_name` addresses a `VAR` member of a `DATASEC` whose type
    /// chases to a struct with libbpf-convention `key`/`value` pointer
    /// members; the result is the direct pointee pair. Unknown names
    /// refuse as `InvalidInput`; every linkage failure (ambiguous VAR,
    /// unlinked VAR, missing members, non-pointer members, void or
    /// dangling pointee) refuses as `Malformed`.
    pub fn map_types(&self, map_name: &str) -> Result<(TypeRef, TypeRef), OperationError> {
        use btf_rs::BtfType as _;
        let mut budget = WorkBudget::new(&self.limits);
        budget.consume(Stage::BtfQuery, 1)?;
        let mut vars = Vec::new();
        for candidate in self.types_named(map_name)? {
            budget.consume(Stage::BtfQuery, 1)?;
            if matches!(self.resolve(candidate.id)?, btf_rs::Type::Var(_)) {
                vars.push(candidate.id);
            }
        }
        if vars.is_empty() {
            return Err(invalid_query());
        }
        if vars.len() > 1 {
            return Err(malformed_query());
        }
        let var_id = vars[0];
        let target = match self.resolve(var_id)? {
            btf_rs::Type::Var(var) => var.get_type_id().unwrap_or(0),
            _ => return Err(malformed_query()),
        };
        if target == 0 || target as usize > self.facts.len() {
            return Err(malformed_query());
        }
        let def = self.chase_wrapper(target, &mut budget)?;
        if self.composite_members(def)?.is_none() {
            return Err(malformed_query());
        }
        let definition = TypeRef {
            domain: self.domain,
            id: def,
        };
        let mut linked = false;
        for raw in 1..=self.facts.len() {
            budget.consume(Stage::BtfQuery, 1)?;
            let id = raw as u32;
            if let btf_rs::Type::Datasec(section) = self.resolve(id)? {
                if section
                    .variables
                    .iter()
                    .any(|entry| entry.get_type_id() == Some(var_id))
                {
                    linked = true;
                    break;
                }
            }
        }
        if !linked {
            return Err(malformed_query());
        }
        let mut linkage = Vec::new();
        for member in ["key", "value"] {
            let extent = self.member(definition, &[member]).map_err(|error| {
                if error.kind() == ErrorKind::InvalidInput {
                    malformed_query()
                } else {
                    error
                }
            })?;
            let pointee = self.chase_wrapper(extent.ty.id, &mut budget)?;
            let direct = match self.resolve(pointee)? {
                btf_rs::Type::Ptr(pointer) => pointer.get_type_id().unwrap_or(0),
                _ => return Err(malformed_query()),
            };
            if direct == 0 || direct as usize > self.facts.len() {
                return Err(malformed_query());
            }
            linkage.push(TypeRef {
                domain: self.domain,
                id: direct,
            });
        }
        Ok((linkage[0], linkage[1]))
    }

    /// Validate domain membership and id range.
    fn check_ref(&self, ty: TypeRef) -> Result<u32, OperationError> {
        if ty.domain != self.domain {
            return Err(incompatible_query());
        }
        if ty.id == 0 || ty.id as usize > self.facts.len() {
            return Err(invalid_query());
        }
        Ok(ty.id)
    }

    /// Resolve one range-checked id through the parser.
    fn resolve(&self, id: u32) -> Result<btf_rs::Type, OperationError> {
        debug_assert!(id != 0 && id as usize <= self.facts.len());
        self.parser.resolve_type_by_id(id).map_err(map_query_error)
    }

    /// Chase typedef/const/volatile/restrict to the terminal id.
    fn chase_wrapper(&self, id: u32, budget: &mut WorkBudget) -> Result<u32, OperationError> {
        use btf_rs::BtfType as _;
        let mut current = id;
        let mut visited = Vec::from([id]);
        let mut hops: usize = 0;
        loop {
            let target = match self.resolve(current)? {
                btf_rs::Type::Typedef(inner) => inner.get_type_id(),
                btf_rs::Type::Volatile(inner) => inner.get_type_id(),
                btf_rs::Type::Const(inner) => inner.get_type_id(),
                btf_rs::Type::Restrict(inner) => inner.get_type_id(),
                _ => return Ok(current),
            };
            let target = target.unwrap_or(0);
            if target == 0 || target as usize > self.facts.len() {
                return Err(malformed_query());
            }
            if visited.contains(&target) {
                return Err(malformed_query());
            }
            hops = hops.saturating_add(1);
            if hops > self.limits.wrapper_depth {
                return Err(limit_query());
            }
            budget.consume(Stage::BtfQuery, 1)?;
            visited.push(target);
            current = target;
        }
    }

    /// Resolve kind and size with transparent wrappers.
    fn shape_inner(&self, id: u32, budget: &mut WorkBudget) -> Result<TypeShape, OperationError> {
        use btf_rs::BtfType as _;
        let canon = self.chase_wrapper(id, budget)?;
        let facts = self.facts_for(canon).ok_or_else(malformed_query)?;
        let kind = facts.kind;
        match self.resolve(canon)? {
            btf_rs::Type::Void => Err(malformed_query()),
            btf_rs::Type::Int(int) => {
                if kind != 1 {
                    return Err(malformed_query());
                }
                Ok(TypeShape {
                    kind: TypeKind::Integer {
                        bits: (facts.aux0 & 0xFF) as u16,
                        signed: int.is_signed(),
                    },
                    size_bytes: Some(int.size() as u64),
                })
            }
            btf_rs::Type::Ptr(pointer) => {
                if kind != 2 {
                    return Err(malformed_query());
                }
                let to = pointer.get_type_id().ok_or_else(malformed_query)?;
                if to != 0 && to as usize > self.facts.len() {
                    return Err(malformed_query());
                }
                Ok(TypeShape {
                    kind: TypeKind::Pointer {
                        to: TypeRef {
                            domain: self.domain,
                            id: to,
                        },
                    },
                    size_bytes: Some(POINTER_SIZE),
                })
            }
            btf_rs::Type::Array(array) => {
                if kind != 3 {
                    return Err(malformed_query());
                }
                let element = array.get_type_id().unwrap_or(0);
                if element == 0 || element as usize > self.facts.len() || facts.aux0 != element {
                    return Err(malformed_query());
                }
                if self.facts_for(facts.aux1).map(|entry| entry.kind) != Some(1) {
                    return Err(malformed_query());
                }
                let count = facts.aux2;
                if array.len() != count as usize {
                    return Err(malformed_query());
                }
                Ok(TypeShape {
                    kind: TypeKind::Array {
                        element: TypeRef {
                            domain: self.domain,
                            id: element,
                        },
                        count,
                    },
                    size_bytes: Some(self.array_total_size(canon, budget)?),
                })
            }
            btf_rs::Type::Struct(composite) => {
                if kind != 4 {
                    return Err(malformed_query());
                }
                Ok(TypeShape {
                    kind: TypeKind::Struct,
                    size_bytes: Some(composite.size() as u64),
                })
            }
            btf_rs::Type::Union(composite) => {
                if kind != 5 {
                    return Err(malformed_query());
                }
                Ok(TypeShape {
                    kind: TypeKind::Union,
                    size_bytes: Some(composite.size() as u64),
                })
            }
            btf_rs::Type::Enum(enumeration) => {
                if kind != 6 {
                    return Err(malformed_query());
                }
                Ok(TypeShape {
                    kind: TypeKind::Enum {
                        bits: enumeration.size().saturating_mul(8).min(u16::MAX as usize) as u16,
                        signed: enumeration.is_signed(),
                    },
                    size_bytes: Some(enumeration.size() as u64),
                })
            }
            btf_rs::Type::Enum64(enumeration) => {
                if kind != 19 {
                    return Err(malformed_query());
                }
                Ok(TypeShape {
                    kind: TypeKind::Enum {
                        bits: enumeration.size().saturating_mul(8).min(u16::MAX as usize) as u16,
                        signed: enumeration.is_signed(),
                    },
                    size_bytes: Some(enumeration.size() as u64),
                })
            }
            btf_rs::Type::Func(_) => {
                if kind != 12 {
                    return Err(malformed_query());
                }
                Ok(TypeShape {
                    kind: TypeKind::Function,
                    size_bytes: None,
                })
            }
            btf_rs::Type::FuncProto(_) => {
                if kind != 13 {
                    return Err(malformed_query());
                }
                Ok(TypeShape {
                    kind: TypeKind::FunctionPrototype,
                    size_bytes: None,
                })
            }
            btf_rs::Type::Float(float) => {
                if kind != 16 {
                    return Err(malformed_query());
                }
                Ok(TypeShape {
                    kind: TypeKind::Other,
                    size_bytes: Some(float.size() as u64),
                })
            }
            btf_rs::Type::Datasec(section) => {
                if kind != 15 {
                    return Err(malformed_query());
                }
                Ok(TypeShape {
                    kind: TypeKind::Other,
                    size_bytes: Some(section.size() as u64),
                })
            }
            btf_rs::Type::Fwd(_)
            | btf_rs::Type::Var(_)
            | btf_rs::Type::DeclTag(_)
            | btf_rs::Type::TypeTag(_) => Ok(TypeShape {
                kind: TypeKind::Other,
                size_bytes: None,
            }),
            // Wrappers never survive the chase; unknown future variants
            // fail closed rather than guessing a shape.
            _ => Err(malformed_query()),
        }
    }

    /// Total byte size of a (possibly nested) array.
    fn array_total_size(&self, id: u32, budget: &mut WorkBudget) -> Result<u64, OperationError> {
        let mut total: u64 = 1;
        let mut current = id;
        let mut seen: Vec<u32> = Vec::new();
        loop {
            if seen.contains(&current) {
                return Err(malformed_query());
            }
            seen.push(current);
            if seen.len() > self.limits.wrapper_depth.saturating_add(1) {
                return Err(limit_query());
            }
            budget.consume(Stage::BtfQuery, 1)?;
            let facts = self
                .facts_for(current)
                .filter(|entry| entry.kind == 3)
                .ok_or_else(malformed_query)?;
            if self.facts_for(facts.aux1).map(|entry| entry.kind) != Some(1) {
                return Err(malformed_query());
            }
            if !matches!(self.resolve(current)?, btf_rs::Type::Array(_)) {
                return Err(malformed_query());
            }
            total = total
                .checked_mul(u64::from(facts.aux2))
                .ok_or_else(overflow_query)?;
            let element = facts.aux0;
            if element == 0 || element as usize > self.facts.len() {
                return Err(malformed_query());
            }
            let chased = self.chase_wrapper(element, budget)?;
            match self.resolve(chased)? {
                btf_rs::Type::Array(_) => {
                    current = chased;
                }
                terminal => {
                    let base = Self::terminal_size(&terminal).ok_or_else(malformed_query)?;
                    return total.checked_mul(base).ok_or_else(overflow_query);
                }
            }
        }
    }

    /// Byte size of a chased non-array terminal, if it carries one.
    fn terminal_size(ty: &btf_rs::Type) -> Option<u64> {
        match ty {
            btf_rs::Type::Int(int) => Some(int.size() as u64),
            btf_rs::Type::Ptr(_) => Some(POINTER_SIZE),
            btf_rs::Type::Struct(composite) => Some(composite.size() as u64),
            btf_rs::Type::Union(composite) => Some(composite.size() as u64),
            btf_rs::Type::Enum(enumeration) => Some(enumeration.size() as u64),
            btf_rs::Type::Enum64(enumeration) => Some(enumeration.size() as u64),
            btf_rs::Type::Float(float) => Some(float.size() as u64),
            btf_rs::Type::Datasec(section) => Some(section.size() as u64),
            _ => None,
        }
    }

    /// Byte size of one member/element type; unsized kinds refuse.
    fn sized_extent(&self, id: u32, budget: &mut WorkBudget) -> Result<u64, OperationError> {
        self.shape_inner(id, budget)?
            .size_bytes
            .ok_or_else(malformed_query)
    }

    /// Members and size of a struct/union, refusing other kinds.
    fn composite_parts(&self, id: u32) -> Result<(Vec<btf_rs::Member>, u64), OperationError> {
        self.composite_members(id)?.ok_or_else(incompatible_query)
    }

    /// Members and size for composites; `None` for other well-formed kinds.
    fn composite_members(
        &self,
        id: u32,
    ) -> Result<Option<(Vec<btf_rs::Member>, u64)>, OperationError> {
        match self.resolve(id)? {
            btf_rs::Type::Struct(composite) => {
                Ok(Some((composite.members.clone(), composite.size() as u64)))
            }
            btf_rs::Type::Union(composite) => {
                Ok(Some((composite.members.clone(), composite.size() as u64)))
            }
            _ => Ok(None),
        }
    }

    /// Find one segment: direct match first, else anonymous descent.
    fn find_member(
        &self,
        current: u32,
        segment: &str,
        budget: &mut WorkBudget,
    ) -> Result<FoundMember, OperationError> {
        let (members, _) = self.composite_parts(current)?;
        let mut direct: Vec<btf_rs::Member> = Vec::new();
        for member in &members {
            budget.consume(Stage::BtfQuery, 1)?;
            let name = self.parser.resolve_name(member).map_err(map_query_error)?;
            if name == segment {
                direct.push(member.clone());
            }
        }
        if direct.len() > 1 {
            return Err(malformed_query());
        }
        if let Some(member) = direct.pop() {
            return Ok(Self::found_from(&member));
        }
        if segment.is_empty() {
            return Err(invalid_query());
        }
        let mut deeper: Vec<btf_rs::Member> = Vec::new();
        let mut stack = Vec::from([current]);
        self.search_anonymous(&members, segment, &mut stack, 0, budget, &mut deeper)?;
        if deeper.len() > 1 {
            return Err(malformed_query());
        }
        deeper
            .pop()
            .map(|member| Self::found_from(&member))
            .ok_or_else(invalid_query)
    }

    /// Collect `segment` hits under anonymous composites, bounded.
    fn search_anonymous(
        &self,
        members: &[btf_rs::Member],
        segment: &str,
        stack: &mut Vec<u32>,
        depth: usize,
        budget: &mut WorkBudget,
        hits: &mut Vec<btf_rs::Member>,
    ) -> Result<(), OperationError> {
        use btf_rs::BtfType as _;
        for member in members {
            budget.consume(Stage::BtfQuery, 1)?;
            let name = self.parser.resolve_name(member).map_err(map_query_error)?;
            if !name.is_empty() {
                continue;
            }
            let mtype = member.get_type_id().unwrap_or(0);
            if mtype == 0 || mtype as usize > self.facts.len() {
                return Err(malformed_query());
            }
            let chased = self.chase_wrapper(mtype, budget)?;
            if stack.contains(&chased) {
                return Err(malformed_query());
            }
            let Some((inner, _)) = self.composite_members(chased)? else {
                continue;
            };
            if depth.saturating_add(1) > self.limits.wrapper_depth {
                return Err(limit_query());
            }
            stack.push(chased);
            for member in &inner {
                budget.consume(Stage::BtfQuery, 1)?;
                let name = self.parser.resolve_name(member).map_err(map_query_error)?;
                if name == segment {
                    hits.push(member.clone());
                }
            }
            self.search_anonymous(&inner, segment, stack, depth + 1, budget, hits)?;
            stack.pop();
        }
        Ok(())
    }

    /// Read bit layout and type id from one located member.
    fn found_from(member: &btf_rs::Member) -> FoundMember {
        use btf_rs::BtfType as _;
        FoundMember {
            bit_off: member.bit_offset(),
            width: member.bitfield_size(),
            mtype: member.get_type_id().unwrap_or(0),
        }
    }
}
