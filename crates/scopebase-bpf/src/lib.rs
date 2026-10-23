// SPDX-License-Identifier: Apache-2.0
//! Host BPF errors, resource caps, descriptive geometry and owned native map reads.
//!
//! Error carriers preserve caller classification; native operations classify their
//! own errors. Caps and parsed topology confer no native-resource authority.
//! Native owners internally authenticate their source and actual map FD.
//!
//! ```
//! use scopebase_bpf::{ErrorKind, Limits, OperationError, Stage};
//! let limits = Limits { input_bytes: 0, retained_bytes: 0, work_steps: 0,
//!     sites: 0, live_links: 0, pending_retirements: 0 };
//! assert!(limits.validate().is_ok()); // structurally valid disabled configuration
//! let error = OperationError::new(ErrorKind::LimitExceeded, Stage::Admission,
//!     None, None).with_required_size(8);
//! assert_eq!(error.kind(), ErrorKind::LimitExceeded);
//! assert_eq!(error.stage(), Stage::Admission);
//! assert_eq!(error.required_size(), Some(8)); // reporting is not allocation
//! ```
//!
//! From an unpacked package run `cargo test --offline --locked --all-targets`
//! and `cargo test --offline --locked --doc`. Downstream `cargo test` does not
//! automatically run dependency tests. External UI controls are described in
//! the package README. No installed operator route or BPF profile is qualified.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod error;
pub mod limits;

pub use error::{ErrorKind, OperationError, Stage};
pub use limits::Limits;

pub mod artifact;
pub mod maps;
pub use artifact::ArtifactId;
pub use maps::{
    CpuTopology, MapBtfExpectation, MapExpectation, MapMetadata, PerCpuGeometry, ValueLayout,
};

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64",
    target_endian = "little"
))]
pub use maps::{LiveCpuTopology, ValidatedMap};

#[cfg(test)]
extern crate self as scopebase_bpf;

pub mod capability;
pub use capability::{
    assess_filter_probe, CapabilityObservation, CapabilityObservationInput, CapabilityState,
    CauseDescriptionInput, DescribedCause, EvidenceStage, HazardState, ObservationOrigin,
    ObservationOutcome, OperationErrorSnapshot, ProbeContext, ProbePopulation, ProfileId,
};

pub mod attach;
pub use attach::{
    adjudicate_split, execute_plan, is_terminal_error, AttachBackend, AttachMode, AttachOutcome,
    AttachPlan, AttachSummary, AttachmentSet, CustodyCharge, ErrorAction, ErrorPolicy,
    NativeAttach, NativeRetire, PoolClose, PoolReconcile, PoolUsage, Retirement, RetirementBudget,
    RetirementCapacity, RetirementPool, Site, UnresolvedAttachments,
};

pub mod ring;
pub use ring::{
    frame_step, BoundaryState, BoundedRingSource, DrainBudget, DrainResult, FrameStep,
    RecordHeader, RingPositions, StageStats, StagedRecord, STAGE_FRAMING_VERSION,
};

pub mod loss;
pub mod writer;
pub use loss::{
    fold_degradation_255, DiagnosticFlag, FullMap, LossEpoch, LossGrid, DEGRADATION_CAP,
};
pub use writer::{
    fold_insertion, guard_admit, insertion_owner, insertion_total, writer_slot, GuardKind,
    IdentityLane, Insertion, MissLedger, WriterArch, WriterDeclaration, WriterPartition,
    IDENTITY_PRESENT,
};

#[cfg(feature = "adapters")]
pub mod adapters;
#[cfg(feature = "adapters")]
pub use adapters::{
    admit_loader, classify_loader_errno, AdapterViolation, AdmittedLoader, AyaBackend,
    AyaUprobeShape, BpfmanBackend, BpfmanShape, LibbpfBackend, LibbpfObjectShape, LoaderId,
    LoaderVersion, NativeConfig, NativeState, OutputLedger, OutputSpan, ProgramAdoptError,
    RULE_ATTACH_MODE, RULE_ATTACH_PAIRING, RULE_CONFIG_AUTOLOAD, RULE_CONFIG_GENERATION,
    RULE_CONFIG_POISONED, RULE_CONFIG_TARGET, RULE_OUTPUT_DISTINCT, RULE_PROFILE_SUPPORTED,
    RULE_VERSION_SUPPORTED,
};
#[cfg(all(feature = "adapters", feature = "json"))]
pub use adapters::{
    parse_configure_vector, parse_output_vector, ConfigureCase, ConfigureVector, OutputCase,
    OutputVector, NATIVE_VECTOR_MAX_CASES, NATIVE_VECTOR_MAX_NAME, NATIVE_VECTOR_MAX_SPANS,
    NATIVE_VECTOR_SCHEMA_VERSION,
};

pub mod identity;
pub use identity::{
    advance_exec, plan_exec_read, same_execution, Admission, ExecAdvance, ExecGeneration,
    ExecReadPlan, ExecShapeProbe, IdentityRegistry, IdentityWire, ProducerDomain, ProducerIdentity,
    TaskCookie,
};

#[cfg(feature = "btf")]
pub mod btf;
#[cfg(feature = "btf")]
pub use btf::{
    BtfDomainId, BtfImages, BtfLimits, BtfView, ByteOrder, FunctionShape, MemberExtent, TypeKind,
    TypeRef, TypeShape, BTF_PROFILE_MAX_IMAGE_BYTES,
};
