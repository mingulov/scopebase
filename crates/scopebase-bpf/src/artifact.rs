// SPDX-License-Identifier: Apache-2.0
/// SHA-256 identity of exact artifact bytes; conveys no semantic layout proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ArtifactId(pub [u8; 32]);
