// SPDX-License-Identifier: Apache-2.0
//! Independent truth remains outside adapter access.
use crate::artifact::*;
use crate::*;
use serde::Serialize;
use serde_json::Value;
wire_enum!(CheckStatus{Pass=>"pass",Fail=>"fail",NotJudged=>"not_judged"});
wire_enum!(CapabilityState{Supported=>"supported",Unsupported=>"unsupported",Denied=>"denied",Unknown=>"unknown",Incompatible=>"incompatible",NotApplicable=>"not_applicable"});
record!(AssertionCheck,AssertionCheckValues{id:Label,status:CheckStatus,reason:Option<String>},|v:&AssertionCheckValues,l:&RunLimits|{if let Some(s)=&v.reason{bound(s.len(),l.diagnostic_bytes(),"check reason")?}Ok(())});
record!(CapabilityEvidence,CapabilityEvidenceValues{state:CapabilityState,method:Label,context:String,evidence_ids:Vec<Label>},|v:&CapabilityEvidenceValues,l:&RunLimits|{bound(v.context.len(),l.diagnostic_bytes(),"capability context")?;bound(v.evidence_ids.len(),l.effects_total(),"capability evidence")?;sorted(&v.evidence_ids)});
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HarnessValidity {
    Valid,
    Invalid { reason: String },
}
impl Decode for HarnessValidity {
    fn decode(v: Value, l: &RunLimits) -> Result<Self, HarnessError> {
        match v.get("kind").and_then(Value::as_str) {
            Some("valid") => {
                Obj::new(v, &["kind"])?;
                Ok(Self::Valid)
            }
            Some("invalid") => {
                let mut o = Obj::new(v, &["kind", "reason"])?;
                let _: String = o.get("kind", l)?;
                let reason: String = o.get("reason", l)?;
                bound(reason.len(), l.diagnostic_bytes(), "reason")?;
                Ok(Self::Invalid { reason })
            }
            _ => Err(he(HarnessErrorKind::InvalidInput, "harness validity")),
        }
    }
}
record!(AssertionVerdict,AssertionVerdictValues{harness:HarnessValidity,checks:Vec<AssertionCheck>,capability:CapabilityEvidence},|v:&AssertionVerdictValues,l:&RunLimits|{if v.checks.is_empty(){return Err(he(HarnessErrorKind::InvalidInput,"empty checks"))}bound(v.checks.len(),l.assertions_per_case(),"checks")?;unique(&v.checks.iter().map(|c|c.id()).collect::<Vec<_>>())});
pub trait CaseOracle {
    fn identity(&self) -> OracleBinding;
    fn evaluate(
        &self,
        case: &CaseSpec,
        expected: &ExpectedEvidence,
        outcome: &CaseOutcome,
    ) -> AssertionVerdict;
}
impl BoundValue for HarnessValidity {
    fn check_bounds(&self, l: &RunLimits) -> Result<(), HarnessError> {
        if let Self::Invalid { reason } = self {
            if reason.is_empty() {
                return Err(he(
                    HarnessErrorKind::InvalidInput,
                    "empty invalid harness reason",
                ));
            }
            bound(reason.len(), l.diagnostic_bytes(), "harness reason")?
        }
        Ok(())
    }
}
