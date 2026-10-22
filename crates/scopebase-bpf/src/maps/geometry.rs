// SPDX-License-Identifier: Apache-2.0
// ADAPT K::percpu_buffer_len and L::map_extent; see selected-port receipt.
use super::error;
use crate::{ErrorKind, OperationError, Stage};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerCpuGeometry {
    stride: usize,
    len: usize,
}
impl PerCpuGeometry {
    pub fn checked(
        value_size: usize,
        possible_cpus: usize,
        byte_limit: usize,
    ) -> Result<Self, OperationError> {
        if value_size == 0 || possible_cpus == 0 {
            return Err(error(ErrorKind::InvalidInput, Stage::Admission));
        }
        let stride = value_size
            .checked_add(7)
            .ok_or_else(|| error(ErrorKind::Overflow, Stage::Admission))?
            & !7;
        let len = stride
            .checked_mul(possible_cpus)
            .ok_or_else(|| error(ErrorKind::Overflow, Stage::Admission))?;
        if len > byte_limit {
            return Err(error(ErrorKind::LimitExceeded, Stage::Admission));
        }
        Ok(Self { stride, len })
    }
    pub fn stride(&self) -> usize {
        self.stride
    }
    pub fn buffer_len(&self) -> usize {
        self.len
    }
}
