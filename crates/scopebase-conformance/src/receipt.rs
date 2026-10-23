// SPDX-License-Identifier: Apache-2.0
//! TT07 receipts: run evidence envelopes, never runtime authority.
//!
//! NEW (TT07): no donor lines copied.

use crate::closure::VerifiedClosure;
use crate::error::{OperatorError, OperatorErrorKind};
use scopebase_testkit::{Qualification, RunContract, RunLimits, RunReport};
use std::path::Path;

/// Receipt envelope schema marker.
pub const RECEIPT_SCHEMA: &str = "operator-receipt-v1";
/// Explicit non-authority statement carried by every receipt.
pub const NON_AUTHORITY_STATEMENT: &str = "This receipt records observed historical evidence only; it is not runtime authority and certifies no other build, version or application embedding.";

/// A verified receipt report.
#[derive(Debug)]
pub struct ReceiptReport {
    /// Envelope schema marker.
    pub schema: String,
    /// Recorded run identifier.
    pub run_id: String,
    /// Recorded profile.
    pub profile: String,
    /// Engine qualification.
    pub qualification: Qualification,
    /// Always false; receipts never grant runtime authority.
    pub runtime_authority: bool,
}

/// Build a receipt envelope for a completed run.
#[allow(clippy::too_many_arguments)]
pub fn build(
    contract: &RunContract,
    report: &RunReport,
    closure: &VerifiedClosure,
    catalog_sha256: &str,
    profile: &str,
    mapping_policy: &str,
    run_id: &str,
) -> Result<serde_json::Value, OperatorError> {
    let report_bytes = report
        .to_json(contract.limits().clone())
        .map_err(|e| OperatorError::new(OperatorErrorKind::Engine, format!("receipt encode: {e}")))?;
    let report_value: serde_json::Value =
        serde_json::from_slice(&report_bytes).map_err(|e| {
            OperatorError::new(OperatorErrorKind::Engine, format!("receipt shape: {e}"))
        })?;
    let envelope = serde_json::json!({
        "schema": RECEIPT_SCHEMA,
        "schema_version": 1,
        "runtime_authority": false,
        "runtime_authority_statement": NON_AUTHORITY_STATEMENT,
        "run_id": run_id,
        "profile": profile,
        "mapping_policy": mapping_policy,
        "catalog_sha256": catalog_sha256,
        "run_contract_sha256": contract.sha256().as_str(),
        "fixture_manifest_sha256": closure.manifest_sha256.as_str(),
        "subject": serde_json::to_value(contract.expected_subject()).unwrap(),
        "report": report_value,
    });
    let digest = scopebase_testkit::Digest256::of_bytes(
        serde_json::to_vec(&envelope_canonical(&envelope)).unwrap().as_slice(),
    )
    .as_str();
    let mut sealed = envelope;
    sealed["envelope_sha256"] = digest.into();
    Ok(sealed)
}

/// Verify a receipt envelope: schema, seal, bindings and verdict shape.
pub fn verify_receipt(path: &Path) -> Result<ReceiptReport, OperatorError> {
    let bytes = std::fs::read(path).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::MissingInput,
            format!("cannot read receipt {}: {e}", path.display()),
        )
    })?;
    let envelope: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::ReceiptInvalid,
            format!("receipt is not JSON: {e}"),
        )
    })?;
    invalid_if(
        envelope.get("schema").and_then(|s| s.as_str()) != Some(RECEIPT_SCHEMA),
        "receipt has the wrong schema",
    )?;
    invalid_if(
        envelope.get("runtime_authority") != Some(&serde_json::Value::from(false)),
        "receipt lacks its non-authority marker",
    )?;
    invalid_if(
        envelope
            .get("runtime_authority_statement")
            .and_then(|s| s.as_str())
            != Some(NON_AUTHORITY_STATEMENT),
        "receipt lacks its non-authority statement",
    )?;
    let sealed = envelope
        .get("envelope_sha256")
        .and_then(|s| s.as_str())
        .ok_or_else(|| {
            OperatorError::new(
                OperatorErrorKind::ReceiptInvalid,
                "receipt lacks its seal",
            )
        })?;
    let recomputed = scopebase_testkit::Digest256::of_bytes(
        serde_json::to_vec(&envelope_canonical(&envelope)).unwrap().as_slice(),
    )
    .as_str();
    invalid_if(
        sealed != recomputed,
        "receipt seal does not match its contents",
    )?;
    let run_id = envelope
        .get("run_id")
        .and_then(|r| r.as_str())
        .unwrap_or("?")
        .to_string();
    let profile = envelope
        .get("profile")
        .and_then(|p| p.as_str())
        .unwrap_or("?")
        .to_string();
    let report_value: serde_json::Value = envelope.get("report").cloned().ok_or_else(|| {
        OperatorError::new(
            OperatorErrorKind::ReceiptInvalid,
            "receipt lacks its report",
        )
    })?;
    let qualification = structural_qualification(&report_value, &run_id)?;
    Ok(ReceiptReport {
        schema: RECEIPT_SCHEMA.into(),
        run_id,
        profile,
        qualification,
        runtime_authority: false,
    })
}

/// Verify a receipt with full engine admission against a catalog.
///
/// Beyond [`verify_receipt`], this reloads the staged contract beside the
/// receipt (written by `run`) and re-admits the embedded report through
/// [`RunReport::from_json`].
pub fn verify_receipt_with_catalog(
    path: &Path,
    catalog_bytes: &[u8],
) -> Result<ReceiptReport, OperatorError> {
    let shallow = verify_receipt(path)?;
    let staged = path
        .parent()
        .map(|d| d.join("staging").join("contract.json"))
        .ok_or_else(|| {
            OperatorError::new(
                OperatorErrorKind::ReceiptInvalid,
                "receipt has no staged contract",
            )
        })?;
    let contract_bytes = std::fs::read(&staged).map_err(|_| {
        OperatorError::new(
            OperatorErrorKind::ReceiptInvalid,
            "receipt has no staged contract",
        )
    })?;
    let catalog = scopebase_testkit::CaseCatalog::load(
        catalog_bytes,
        scopebase_testkit::CatalogLimits::default(),
    )
    .map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::MissingInput,
            format!("catalog rejected: {e}"),
        )
    })?;
    let profile_id =
        scopebase_testkit::ProfileId::parse(&shallow.profile).map_err(|_| {
            OperatorError::new(
                OperatorErrorKind::ReceiptInvalid,
                "receipt profile is not an identifier",
            )
        })?;
    let plan = scopebase_testkit::ProfilePlan::select(&catalog, &profile_id).map_err(|_| {
        OperatorError::new(
            OperatorErrorKind::ReceiptInvalid,
            "receipt profile is not in the catalog",
        )
    })?;
    let contract =
        RunContract::load(&catalog, &plan, &contract_bytes, RunLimits::default()).map_err(|e| {
            OperatorError::new(
                OperatorErrorKind::ReceiptInvalid,
                format!("staged contract rejected: {e}"),
            )
        })?;
    let envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).map_err(|e| {
            OperatorError::new(
                OperatorErrorKind::MissingInput,
                format!("cannot re-read receipt: {e}"),
            )
        })?)
        .map_err(|e| {
            OperatorError::new(
                OperatorErrorKind::ReceiptInvalid,
                format!("receipt is not JSON: {e}"),
            )
        })?;
    let report_bytes = serde_json::to_vec(envelope.get("report").unwrap_or(&serde_json::Value::Null))
        .unwrap();
    let admitted = RunReport::from_json(&contract, &report_bytes, RunLimits::default()).map_err(
        |e| {
            OperatorError::new(
                OperatorErrorKind::ReceiptInvalid,
                format!("report re-admission rejected: {e}"),
            )
        },
    )?;
    if admitted.qualification() != shallow.qualification {
        return Err(OperatorError::new(
            OperatorErrorKind::ReceiptInvalid,
            "re-admitted qualification differs from the envelope",
        ));
    }
    // F30: the seal is unkeyed, so recomputing it over altered outer
    // bindings is trivial. The bindings must equal the independently
    // admitted catalog and staged contract, not merely be self-consistent.
    let envelope_catalog = envelope
        .get("catalog_sha256")
        .and_then(|s| s.as_str())
        .unwrap_or("");
    invalid_if(
        envelope_catalog != catalog.source_sha256().as_str(),
        "receipt catalog binding differs from the supplied catalog",
    )?;
    let envelope_contract = envelope
        .get("run_contract_sha256")
        .and_then(|s| s.as_str())
        .unwrap_or("");
    invalid_if(
        envelope_contract != contract.sha256().as_str(),
        "receipt contract binding differs from the staged contract",
    )?;
    let expected_subject = serde_json::to_value(contract.expected_subject()).unwrap();
    invalid_if(
        envelope.get("subject") != Some(&expected_subject),
        "receipt subject binding differs from the staged contract",
    )?;
    Ok(shallow)
}

fn structural_qualification(
    report: &serde_json::Value,
    run_id: &str,
) -> Result<Qualification, OperatorError> {
    let terminal = report.get("run_terminal").ok_or_else(|| {
        OperatorError::new(
            OperatorErrorKind::ReceiptInvalid,
            "report lacks a terminal verdict",
        )
    })?;
    if terminal.is_null() {
        return Err(OperatorError::new(
            OperatorErrorKind::ReceiptInvalid,
            "report terminal is null",
        ));
    }
    let reported_run = report.get("run_id").and_then(|r| r.as_str()).unwrap_or("");
    if reported_run != run_id {
        return Err(OperatorError::new(
            OperatorErrorKind::ReceiptInvalid,
            "report run id does not match the envelope",
        ));
    }
    match terminal.get("qualification").and_then(|q| q.as_str()) {
        Some("qualified") => Ok(Qualification::Qualified),
        Some("failed") => Ok(Qualification::Failed),
        Some("incomplete") => Ok(Qualification::Incomplete),
        Some("invalid") => Ok(Qualification::Invalid),
        other => Err(OperatorError::new(
            OperatorErrorKind::ReceiptInvalid,
            format!("report carries no known qualification: {other:?}"),
        )),
    }
}

fn invalid_if(cond: bool, detail: &str) -> Result<(), OperatorError> {
    if cond {
        Err(OperatorError::new(
            OperatorErrorKind::ReceiptInvalid,
            detail,
        ))
    } else {
        Ok(())
    }
}

fn envelope_canonical(envelope: &serde_json::Value) -> serde_json::Value {
    let mut copy = envelope.clone();
    if let Some(object) = copy.as_object_mut() {
        object.remove("envelope_sha256");
    }
    copy
}
