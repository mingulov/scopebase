// SPDX-License-Identifier: Apache-2.0
// Known bad arithmetic output. This constant must fail value.equal for 2+3.
pub const WRONG_SUM: u64 = 6;
// Model refusal controls preserve the same errno and change independent truth.
pub const WRONG_CAUSE: &str = "verifier";
pub const WRONG_NEGATIVE_LICENSE: &[u8] = b"GPL\0";
