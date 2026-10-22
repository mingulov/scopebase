// SPDX-License-Identifier: Apache-2.0
//! Checked descriptive geometry and separately authenticated native map owners.
mod budget;
mod geometry;
mod topology;
use crate::{ArtifactId, ErrorKind, OperationError, Stage};
pub use geometry::PerCpuGeometry;
pub use topology::CpuTopology;
pub(super) fn error(kind: ErrorKind, stage: Stage) -> OperationError {
    OperationError::new(kind, stage, None, None)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueLayout {
    pub size: usize,
    pub alignment: usize,
    pub schema: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapMetadata {
    pub map_id: u32,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
    pub btf_id: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapBtfExpectation {
    pub image: ArtifactId,
    pub key_type_id: u32,
    pub value_type_id: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapExpectation {
    pub map_type: u32,
    pub key_size: u32,
    pub value: ValueLayout,
    pub max_entries: u32,
    pub required_flags: u32,
    pub btf: Option<MapBtfExpectation>,
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64",
    target_endian = "little"
))]
mod handle;
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64",
    target_endian = "little"
))]
#[allow(unsafe_code)]
mod native;
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64",
    target_endian = "little"
))]
mod provenance;
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64",
    target_endian = "little"
))]
pub use {handle::ValidatedMap, provenance::LiveCpuTopology};
