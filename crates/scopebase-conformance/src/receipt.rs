// SPDX-License-Identifier: Apache-2.0
//! TT07 receipts: run evidence envelopes, never runtime authority.
//!
//! NEW (TT07): no donor lines copied.

use crate::closure::{self, BoundedReadError, VerifiedClosure};
use crate::error::{OperatorError, OperatorErrorKind};
use scopebase_testkit::{Qualification, RunContract, RunLimits, RunReport, SubjectBinding};
use std::path::Path;

/// Receipt envelope schema marker.
pub const RECEIPT_SCHEMA: &str = "operator-receipt-v1";
/// R48: the only supported receipt envelope version.
pub const RECEIPT_SCHEMA_VERSION: u64 = 1;
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
    let report_bytes = report.to_json(contract.limits().clone()).map_err(|e| {
        OperatorError::new(OperatorErrorKind::Engine, format!("receipt encode: {e}"))
    })?;
    let report_value: serde_json::Value = serde_json::from_slice(&report_bytes).map_err(|e| {
        OperatorError::new(OperatorErrorKind::Engine, format!("receipt shape: {e}"))
    })?;
    let envelope = serde_json::json!({
        "schema": RECEIPT_SCHEMA,
        "schema_version": RECEIPT_SCHEMA_VERSION,
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
        serde_json::to_vec(&envelope_canonical(&envelope))
            .unwrap()
            .as_slice(),
    )
    .as_str();
    let mut sealed = envelope;
    sealed["envelope_sha256"] = digest.into();
    Ok(sealed)
}

/// Verify a receipt envelope: schema, seal, bindings and verdict shape.
pub fn verify_receipt(path: &Path) -> Result<ReceiptReport, OperatorError> {
    // R37: the envelope is read exactly once; seal, bindings and the
    // report are all admitted from those same bytes.
    let bytes = read_envelope_bytes(path)?;
    Ok(verify_envelope(&bytes)?.0)
}

/// Read the receipt envelope bytes: the single read site shared by
/// shallow and full verification.
///
/// S39/S42: bounded through the envelope reader — an oversized
/// envelope refuses here instead of inflating the verifier before
/// JSON admission. Regular files read capped; FIFOs stream under
/// the rendezvous bound (R37 serves the envelope over a FIFO by
/// design), and a writer-less envelope refuses as missing input.
fn read_envelope_bytes(path: &Path) -> Result<Vec<u8>, OperatorError> {
    closure::read_envelope_stream(path, closure::MAX_RECEIPT_BYTES).map_err(|e| match e {
        BoundedReadError::NotFound(detail) => OperatorError::new(
            OperatorErrorKind::MissingInput,
            format!("cannot read receipt {}: {detail}", path.display()),
        ),
        BoundedReadError::Refused(detail) => OperatorError::new(
            OperatorErrorKind::ReceiptInvalid,
            format!("receipt {} unreadable: {detail}", path.display()),
        ),
    })
}

/// Admit one already-read envelope: schema, version, mandatory
/// shapes, seal and structural verdict. Returns the report plus the
/// admitted envelope so full verification reuses these same bytes.
fn verify_envelope(bytes: &[u8]) -> Result<(ReceiptReport, serde_json::Value), OperatorError> {
    let envelope: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::ReceiptInvalid,
            format!("receipt is not JSON: {e}"),
        )
    })?;
    invalid_if(
        envelope.get("schema").and_then(|s| s.as_str()) != Some(RECEIPT_SCHEMA),
        "receipt has the wrong schema",
    )?;
    // R48: the envelope version and mandatory field shapes gate seal
    // and report admission. A resealed envelope with an unsupported
    // version, or with unshaped bindings, never reaches the seal.
    invalid_if(
        envelope.get("schema_version").and_then(|v| v.as_u64()) != Some(RECEIPT_SCHEMA_VERSION),
        "receipt has an unsupported envelope version",
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
    let run_id = envelope
        .get("run_id")
        .and_then(|r| r.as_str())
        .filter(|r| !r.is_empty())
        .ok_or_else(|| {
            OperatorError::new(OperatorErrorKind::ReceiptInvalid, "receipt lacks a run id")
        })?
        .to_string();
    let profile = envelope
        .get("profile")
        .and_then(|p| p.as_str())
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            OperatorError::new(OperatorErrorKind::ReceiptInvalid, "receipt lacks a profile")
        })?
        .to_string();
    let report_value: serde_json::Value = envelope.get("report").cloned().ok_or_else(|| {
        OperatorError::new(
            OperatorErrorKind::ReceiptInvalid,
            "receipt lacks its report",
        )
    })?;
    invalid_if(!report_value.is_object(), "receipt report is not an object")?;
    // S41: mandatory v1 bindings gate the seal. The seal is
    // self-consistent over any sparse shape (anyone can recompute
    // it), so a resealed envelope with removed or malformed bindings
    // must fail HERE, before seal admission — never by seal mismatch
    // alone, which only proves the bytes changed.
    for binding in [
        "catalog_sha256",
        "run_contract_sha256",
        "fixture_manifest_sha256",
    ] {
        let shaped = envelope
            .get(binding)
            .and_then(|s| s.as_str())
            .is_some_and(|d| d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit()));
        if !shaped {
            return Err(OperatorError::new(
                OperatorErrorKind::ReceiptInvalid,
                format!("receipt binding {binding} is missing or malformed"),
            ));
        }
    }
    invalid_if(
        envelope
            .get("mapping_policy")
            .and_then(|p| p.as_str())
            .is_none_or(|p| p.is_empty()),
        "receipt lacks its mapping policy",
    )?;
    // S41: the shallow subject gate admits the TYPED binding through
    // the engine's exact `Decode` + bounds admission — never a bare
    // `is_object` shape check, which a resealed `{}` subject passes.
    // Default limits are the structural gate: the producer's genuine
    // subject decodes under them (see the resealed-control test), so
    // anything rejected here is malformed, not over budget.
    let subject_value = envelope.get("subject").cloned().ok_or_else(|| {
        OperatorError::new(
            OperatorErrorKind::ReceiptInvalid,
            "receipt lacks its subject",
        )
    })?;
    SubjectBinding::from_json(subject_value, &RunLimits::default()).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::ReceiptInvalid,
            format!("receipt subject binding rejected: {e}"),
        )
    })?;
    let sealed = envelope
        .get("envelope_sha256")
        .and_then(|s| s.as_str())
        .ok_or_else(|| {
            OperatorError::new(OperatorErrorKind::ReceiptInvalid, "receipt lacks its seal")
        })?;
    let recomputed = scopebase_testkit::Digest256::of_bytes(
        serde_json::to_vec(&envelope_canonical(&envelope))
            .unwrap()
            .as_slice(),
    )
    .as_str();
    invalid_if(
        sealed != recomputed,
        "receipt seal does not match its contents",
    )?;
    let qualification = structural_qualification(&report_value, &run_id)?;
    Ok((
        ReceiptReport {
            schema: RECEIPT_SCHEMA.into(),
            run_id,
            profile,
            qualification,
            runtime_authority: false,
        },
        envelope,
    ))
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
    // R37: one read; the seal-checked envelope below is the same
    // value the report and bindings are admitted from.
    let bytes = read_envelope_bytes(path)?;
    let (shallow, envelope) = verify_envelope(&bytes)?;
    let staged = path
        .parent()
        .map(|d| d.join("staging").join("contract.json"))
        .ok_or_else(|| {
            OperatorError::new(
                OperatorErrorKind::ReceiptInvalid,
                "receipt has no staged contract",
            )
        })?;
    // S39: the staged contract admits through the bounded reader.
    let contract_bytes = closure::read_bounded(&staged, closure::MAX_STAGED_CONTRACT_BYTES)
        .map_err(|e| match e {
            BoundedReadError::NotFound(_) => OperatorError::new(
                OperatorErrorKind::ReceiptInvalid,
                "receipt has no staged contract",
            ),
            BoundedReadError::Refused(detail) => OperatorError::new(
                OperatorErrorKind::ReceiptInvalid,
                format!("receipt staged contract unreadable: {detail}"),
            ),
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
    let profile_id = scopebase_testkit::ProfileId::parse(&shallow.profile).map_err(|_| {
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
    let contract = RunContract::load(&catalog, &plan, &contract_bytes, RunLimits::default())
        .map_err(|e| {
            OperatorError::new(
                OperatorErrorKind::ReceiptInvalid,
                format!("staged contract rejected: {e}"),
            )
        })?;
    let report_bytes =
        serde_json::to_vec(envelope.get("report").unwrap_or(&serde_json::Value::Null)).unwrap();
    let admitted =
        RunReport::from_json(&contract, &report_bytes, RunLimits::default()).map_err(|e| {
            OperatorError::new(
                OperatorErrorKind::ReceiptInvalid,
                format!("report re-admission rejected: {e}"),
            )
        })?;
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
