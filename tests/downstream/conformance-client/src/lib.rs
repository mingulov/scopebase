// SPDX-License-Identifier: Apache-2.0
//! TT07 downstream consumer: independent adapter over packaged crates.
//!
//! NEW (TT07): no donor lines copied. This crate resolves only the packaged
//! `scopebase-conformance`/`scopebase-testkit` APIs against its own manifest
//! and runs the delivery profile with its own subject coordinates.

use scopebase_conformance::delivery::DeliveryAdapter;
use scopebase_testkit::{
    BindingProvenance, CaseError, CaseInvocation, ConformanceAdapter, FixtureAccess, Observation,
    RetireRequest, RetirementReport, RunLimits, SubjectBinding, SubjectBindingValues,
};
use std::path::PathBuf;

/// This consumer's own package coordinates.
pub const CONSUMER_PACKAGE: &str = "conformance-client";
/// This consumer's adapter name.
pub const CONSUMER_ADAPTER: &str = "conformance-client";

/// Resolve the delivery fixture root: explicit `CONFORMANCE_FIXTURE_ROOT`
/// first, falling back to the in-checkout delivery closure for local runs.
pub fn fixture_root() -> PathBuf {
    if let Ok(root) = std::env::var("CONFORMANCE_FIXTURE_ROOT") {
        return PathBuf::from(root);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../crates/scopebase-conformance/delivery")
}

/// The consumer's own adapter: delegates execution to the reference delivery
/// adapter but reports this crate's own resolved subject coordinates.
pub struct RenamedAdapter {
    inner: DeliveryAdapter,
    subject: SubjectBinding,
}

impl RenamedAdapter {
    /// Build the consumer adapter with its own measured subject.
    pub fn new() -> Result<Self, scopebase_conformance::OperatorError> {
        let inner = DeliveryAdapter::new()?;
        let template = inner.subject();
        let limits = RunLimits::default();
        let subject = SubjectBinding::new(
            SubjectBindingValues {
                package_name: CONSUMER_PACKAGE.into(),
                package_version: env!("CARGO_PKG_VERSION").into(),
                source_sha256: template.source_sha256().clone(),
                build_inputs_sha256: template.build_inputs_sha256().clone(),
                features: Vec::new(),
                backend: None,
                host: template.host().clone(),
                target: template.target().clone(),
                consumer: scopebase_testkit::ConsumerBinding::new(
                    scopebase_testkit::ConsumerBindingValues {
                        name: CONSUMER_ADAPTER.into(),
                        build_inputs_sha256: template.build_inputs_sha256().clone(),
                        executable_sha256: template.consumer().executable_sha256().clone(),
                    },
                    &limits,
                )
                .map_err(|e| {
                    scopebase_conformance::OperatorError::new(
                        scopebase_conformance::OperatorErrorKind::Engine,
                        format!("consumer binding rejected: {e}"),
                    )
                })?,
                objects: Vec::new(),
                provenance: BindingProvenance::GeneratedBuild {
                    manifest_sha256: template.source_sha256().clone(),
                    measurement_sha256: template.consumer().executable_sha256().clone(),
                },
            },
            &limits,
        )
        .map_err(|e| {
            scopebase_conformance::OperatorError::new(
                scopebase_conformance::OperatorErrorKind::Engine,
                format!("consumer subject rejected: {e}"),
            )
        })?;
        Ok(Self {
            inner,
            subject,
        })
    }
}

impl ConformanceAdapter for RenamedAdapter {
    fn subject(&self) -> SubjectBinding {
        self.subject.clone()
    }

    fn execute(
        &mut self,
        i: &CaseInvocation,
        f: &FixtureAccess<'_>,
    ) -> Result<Observation, CaseError> {
        self.inner.execute(i, f)
    }

    fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
        self.inner.retire(r)
    }
}
