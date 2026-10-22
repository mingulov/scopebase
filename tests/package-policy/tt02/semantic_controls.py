#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One-at-a-time semantic mutants with exact restored-positive tests.

Mutations affect private copies only. Required predicates are frozen before any
build. Compilation/setup errors never count as detection. Detailed semantic
assertion output is retained for independent review, including failed attempts.
"""
import argparse,hashlib,json,os,pathlib,shutil,sys
ROOT=pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools/build'));import common as p
MUTANTS=[
 ('wrong-sha','artifact.rs','Self(Sha256::digest(b).into())','Self(Sha256::digest(b"\").into())','binding','hash_known_vectors_and_bounds','assertion'),
 ('vector-cap-for-stream','artifact.rs','if len > self.limits.measure_file_bytes() || (retain && len > self.limits.vector_bytes()) {','if len > self.limits.vector_bytes() || (retain && len > self.limits.vector_bytes()) {','binding','large_artifacts_do_not_raise_vector_cap','LimitExceeded'),
 ('failed-budget-refund','artifact.rs','let total = self\n            .usage\n            .reserved_bytes','self.usage.reserved_bytes = 0;\n        let total = self\n            .usage\n            .reserved_bytes','binding','stream_budget_and_progress','assertion'),
 ('omit-eof-sentinel','artifact.rs','loop {\n            if self.usage.read_calls','loop {\n            if offset == len { break; }\n            if self.usage.read_calls','lib','artifact::tests::independently_counted_short_reads_and_sentinel','assertion'),
 ('ignore-lower-only','artifact.rs','if v.execution_ms > self.0.execution_ms {','if false {','binding','limits_construct_and_lower','unwrap_err'),
 ('ignore-invalid','result.rs','if self.invalid {','if false {','verdict','precedence_truth_table','independent Cartesian row must reconstruct'),
 ('ignore-fail','result.rs','} else if self.failed {','} else if false {','verdict','precedence_truth_table','independent Cartesian row must reconstruct'),
 ('ignore-coverage-prerequisite','result.rs','} else if !gate {','} else if false {','verdict','precedence_truth_table','independent Cartesian row must reconstruct'),
 ('ignore-draft','result.rs','if !*c.selection().definition_complete() {','if false {','verdict','precedence_truth_table','independent Cartesian row must reconstruct'),
 ('ignore-known-pending','result.rs','if !self.pending(owner, scope).is_empty()','if false && !self.pending(owner, scope).is_empty()','harness_controls','cleanup_survives_zero_exit','assertion'),
 ('accept-empty-snapshot-erasure','result.rs','if *r.complete() && r.pending_snapshot() != &expected {','if false {','harness_controls','cleanup_survives_zero_exit','unwrap_err'),
 ('global-missing-twin-downgrade','result.rs','} else if !gate {','} else if !gate || !twin_ok {','verdict','blocked_twin_preserves_independent_fail','assertion'),
 ('refresh-retirement-budget','runner.rs','let available = allowance.saturating_sub(self.closed);','let available = allowance;','lib','runner::tests::retirement_budget_is_cumulative','cleanup phase accounting'),
 ('call-zero-budget-owner','runner.rs','if participate && remaining.is_zero() {','if false && participate && remaining.is_zero() {','lib','runner::tests::retirement_budget_is_cumulative','retirement called without allowance'),
 ('skip-empty-participant-retire','runner.rs','let participate = self.ledger.participates(owner, &scope);','let participate = self.ledger.participates(owner, &scope) && !self.ledger.pending(owner, &scope).is_empty();','harness_controls','participation_and_empty_effects','false no participation'),
 ('erase-incomplete-inventory','result.rs','if !*b.complete() {','if false {','harness_controls','dialect_tests::s7_nonstopping_lifecycle_and_retained_returns','assertion'),
 ('ignore-full-oracle-harness','result.rs','let harness_valid = matches!(v.harness(), HarnessValidity::Valid);','let harness_valid = true;','verdict','oracle_harness_invalid_is_retained','assertion'),
 ('ignore-final-identity','result.rs','if value != expected {','if false {','verdict','final_oracle_drift_is_serialized','assertion'),
 ('discard-partial-prefix','tests/fixtures/harness/adapter.rs','            completed_steps,','            completed_steps: vec![],','harness_controls','partial_steps_do_not_invent_activity','assertion'),
 ('invent-third-step-activity','result.rs','effective_achieved: if participated { raw_achieved } else { 0 },','effective_achieved: raw_achieved,','harness_controls','partial_steps_runner_gates_authored_third_step','assertion'),
]
# R5 controls use the same private accessor bodies as the actual shipped adapters.
_arithmetic=(ROOT/'crates/scopebase-testkit/tests/fixtures/harness/adapter.rs').read_text()
_start=_arithmetic.index('        if i.script().schema_id().as_str() != "tt02-u64-v1"')
_end=_arithmetic.index('            let b = input',_start)
_late_before=_arithmetic[_start:_end]
_late_after='''        if i.script().schema_id().as_str() != "tt02-u64-v1" { return Err(preflight_error(i)); }
        let mut values = vec![];
        let mut completed = vec![];
        for step in i.script().steps() {
            if step.inputs().len()!=1 || !step.parameters().is_empty() || !matches!(step.operation().as_str(),"checked-add"|"decimal-length") { return Err(preflight_error(i)); }
'''
_model=(ROOT/'crates/scopebase-testkit/tests/fixtures/harness/model_adapter.rs').read_text()
_bad_start=_model.index('        let invalid = || {')
_bad_end=_model.index('        let raw: Envelope',_bad_start)
MUTANTS.extend([
 ('r5-stage-alias','tests/fixtures/harness/adapter.rs','operation_error(\n        i,\n        CaseErrorCategory::UnsupportedSchema,','operation_error(\n        i,\n        CaseErrorCategory::InvalidOutput,','harness_controls','dialect_tests::s1_all_shipped_dialect_rejections_are_typed','assertion'),
 ('r5-late-preflight','tests/fixtures/harness/adapter.rs',_late_before,_late_after,'harness_controls','dialect_tests::s2_whole_script_preflight_precedes_first_read','second-step syntax'),
 ('r5-data-as-dialect','tests/fixtures/harness/model_adapter.rs',_model[_bad_start:_bad_end],'        let invalid = || super::adapter::preflight_error(i);\n','harness_controls','dialect_tests::s3_bad_data_is_attempted_invalid_output','assertion'),
 ('r5-ignore-actual-category','tests/fixtures/harness/model_oracle.rs','want["category"] == serde_json::to_value(err.category()).unwrap()','want["category"] == "refused"','harness_controls','dialect_tests::s5_model_oracle_compares_actual_category_and_independent_checks','assertion'),
 ('r5-global-stop','runner.rs','CaseErrorCategory::Cancelled|CaseErrorCategory::TimedOut','CaseErrorCategory::Cancelled|CaseErrorCategory::TimedOut|CaseErrorCategory::UnsupportedSchema','harness_controls','dialect_tests::s7_nonstopping_lifecycle_and_retained_returns','false omission premise'),
 ('r5-skip-intrinsic-invariant','observation.rs','if v.category==CaseErrorCategory::UnsupportedSchema&&','if false&&v.category==CaseErrorCategory::UnsupportedSchema&&','harness_controls','dialect_tests::s6_literal_receipt_and_intrinsic_controls','unwrap_err'),
 ('r5-vacuous-model-reject','tests/fixtures/harness/model_adapter.rs','if i.script().schema_id().as_str() != "tt02-refusal-v1" {','if true {','harness_controls','dialect_tests::s3_bad_data_is_attempted_invalid_output','assertion'),
 ('ignore-receipt-reason-bound','result.rs','bound(reason.len(), c.limits().diagnostic_bytes(), "case reason")?;','let _ = reason;','binding','lowered_names_reserve_mandatory_runner_evidence','unwrap_err'),
])
# R1 mutations are selected explicitly; the original28 controls keep their
# sealed earlier receipts and are not implicitly rerun for this correction.
_r1runner=(ROOT/'crates/scopebase-testkit/src/runner.rs').read_text()
_r1result=(ROOT/'crates/scopebase-testkit/src/result.rs').read_text()
_r1fixture=(ROOT/'crates/scopebase-testkit/src/fixture.rs').read_text()
_r1access=_r1fixture[_r1fixture.index('    pub fn new(\n',_r1fixture.index("impl<'a> FixtureAccess")):_r1fixture.index('    pub fn input(',_r1fixture.index("impl<'a> FixtureAccess"))]
_r1json=_r1result[_r1result.index('    pub fn to_json('):_r1result.index('    pub fn from_json(')]
_r1prefix=_r1result[_r1result.index('    if w.case_results.len() > c.schedule().len()'):_r1result.index('    if w.case_results.len() != c.schedule().len()')]
_r1fold=_r1result[_r1result.index('pub(crate) fn reconstruct('):]
MUTANTS.extend([
 ('r1-selected-structure','runner.rs','Obj::new(parse(bytes, limits.input_bytes(), &limits)?, fields)?','Obj::new(parse(bytes, limits.input_bytes(), &ceiling)?, fields)?','harness_controls','review_r1::a1_selected_structure_is_admitted_again','unwrap_err'),
 ('r1-selected-receipt','result.rs',_r1json,_r1json.replace('self.limits','ceiling'),'harness_controls','review_r1::a1_selected_receipt_cap_is_not_enlarged_by_the_ceiling','wider ceiling'),
 ('r1-selected-access','fixture.rs',_r1access,_r1access.replace('i.slot.check_bounds(l)?;','').replace('r.id.check_bounds(l)?;','').replace('effects.check_bounds(l)?;',''),'harness_controls','review_r1::a1_reused_access_and_measurement_values_use_selected_limits','selected input label'),
 ('r1-selected-descriptor','artifact.rs','        e.check_bounds(&self.limits)\n            .map_err(|_| be(BindingErrorKind::LimitExceeded, "selected artifact binding"))?;','','harness_controls','review_r1::a1_reused_access_and_measurement_values_use_selected_limits','selected artifact label'),
 ('r1-selected-observation','result.rs','CaseOutcome::Observed(v) => v.check_bounds(limits)?,','CaseOutcome::Observed(_) => (),','harness_controls','review_r1::a1_returned_outcomes_recheck_selected_bounds_before_collect','selected returned outcome bounds'),
 ('r1-selected-case-error','result.rs','CaseOutcome::OperationError(v) => v.check_bounds(limits)?,','CaseOutcome::OperationError(_) => (),','harness_controls','review_r1::a1_returned_outcomes_recheck_selected_bounds_before_collect','selected returned outcome bounds'),
 ('r1-vector-owned-copy','fixture.rs','Arc::new(bytes)','Arc::new(bytes.clone())','lib','fixture::tests::review_a2_vector_owner_preserves_pointer_and_capacity','verified Vec payload'),
 ('r1-vector-provider-tier','fixture.rs','if c.case_rules().iter().any(|r| *r.tier() != EvidenceTier::T0) {','if false {','harness_controls','review_r1::a3_authored_vector_tiers_cannot_be_retagged','builtin authored provider'),
 ('r1-vector-import-tier','fixture.rs','if *rule.tier() != EvidenceTier::T0 {','if false {','harness_controls','review_r1::a3_authored_vector_tiers_cannot_be_retagged','fixed authored ledger'),
 ('r1-typed-return-mirror','result.rs','&& (typed_return\n','&& (false\n','harness_controls','review_r1::b1_zero_effect_rule_cannot_lose_a_typed_return','typed return must enforce'),
 ('r1-expected-before-judge','runner.rs','crate::result::validate_expected(&c, key, r, &expected);','Ok::<(),HarnessError>(());','harness_controls','review_r1::b2_expected_binding_is_checked_before_judge_and_the_next_case','must not reach judge'),
 ('r1-trailing-row-prefix','result.rs',_r1fold,_r1fold.replace(_r1prefix,'').replace('            gates.tail = true;','            gates.tail = false;'),'harness_controls','review_r1::b3_omitted_rows_are_a_trailing_normal_work_boundary','missing row followed'),
 ('r1-hook-entry-interval','runner.rs','deadline.saturating_duration_since(started)','deadline.saturating_duration_since(now)','lib','runner::tests::review_b4_request_preparation_uses_the_actual_hook_entry','honest preparation delay'),
 ('r1-derived-payload-reservation','artifact.rs','self.reserve(encoded_size(value, self.limit)?)?;','let _ = value;','harness_controls','review_r1::b5_derived_diagnostics_reserve_payload_before_cloning','unreserved raw/derived'),
 ('r1-shared-truth-copy','fixture.rs','Arc::clone(&self.bundle.files[row.expected_file()]),','share_vector(self.bundle.files[row.expected_file()].as_ref().clone()),','lib','fixture::tests::review_b5_builtin_truth_shares_retained_vector_payload','must not make an unreserved owned copy'),
 ('r1-receipt-decode-peak','result.rs','.checked_mul(2)','.checked_mul(1)','harness_controls','review_r1::b5_receipt_decode_peak_is_reserved_before_parsing','parsed hex string and decoded byte payload'),
 ('r1-prepare-effect-copy','runner.rs','let keep = b.check_bounds(self.c.limits()).and_then(|_| self.retain(b));','let keep=Ok::<(),HarnessError>(());','lib','runner::tests::review_b5_prepare_mirror_reserves_before_copy_and_retains_custody','prepare mirror must reserve'),
])
MUTANTS.extend([
 ('r1-retirement-response-retention','runner.rs','response = if keep_response { Some(r) } else { None };','response = Some(r);','lib','runner::tests::review_b5_retirement_raw_response_obeys_remaining_payload','unretained retirement diagnostic must not remain owned'),
 ('r1-retirement-diagnostic-bounds','runner.rs','diagnostic: "retirement response invalid".into(),','diagnostic: e.to_string(),','lib','runner::tests::review_a1_retirement_error_diagnostic_fits_selected_limit','selected retirement diagnostics must be representable'),
])
def write(path,x):path.write_bytes(json.dumps(x,sort_keys=True,indent=2).encode()+b'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);ap.add_argument('--config',required=True);ap.add_argument('--build-wrapper',required=True);ap.add_argument('--start-at',type=int,default=0);ap.add_argument('--only',nargs='+');a=ap.parse_args();selected=[m for m in MUTANTS[a.start_at:]if not a.only or m[0]in a.only];assert selected and (not a.only or set(a.only)=={m[0]for m in selected}),'unknown/empty control selection';out=pathlib.Path(a.output).resolve();out.mkdir(mode=0o700);wrapper=pathlib.Path(a.build_wrapper).resolve();assert p.sha(wrapper)=='f112693933f18ae8483a52aa9811a0df54e5366505ba48a19b720a8a2b8e5f6f';config=pathlib.Path(a.config).resolve();write(out/'required.json',[{'id':m[0],'target':m[4],'test':m[5],'semantic_marker':m[6]}for m in selected]);source=out/'source';p.source_copy(ROOT/'crates/scopebase-testkit',source);(out/'Cargo.toml').write_text('[workspace]\nresolver="2"\nmembers=["source"]\n');(out/'tmp').mkdir();(out/'cargo-home').mkdir();tool=pathlib.Path('/home/user/.rustup/toolchains/1.88.0-x86_64-unknown-linux-gnu/bin');env={'PATH':str(tool)+':/usr/bin:/bin','HOME':os.environ['HOME'],'CARGO_HOME':str(out/'cargo-home'),'CARGO_TARGET_DIR':str(out/'target'),'RUSTC':str(tool/'rustc'),'RUSTDOC':str(tool/'rustdoc'),'CARGO_NET_OFFLINE':'true','CARGO_BUILD_JOBS':'2','TMPDIR':str(out/'tmp'),'LC_ALL':'C.UTF-8'};results=[];counter=0
 def command(name,args,expect=0):
  nonlocal counter
  counter+=1;r=p.run([wrapper,'--',tool/'cargo','--config',config,args[0],'--manifest-path',source/'Cargo.toml',*args[1:]],out,env,out/f'command-{counter:03d}',timeout=600);results.append({'id':name,**r});write(out/'checkpoint.json',{'status':'IN_PROGRESS','results':results})
  if r['exit_code']!=expect or r['reason_code']or r['cleanup']!='complete':raise RuntimeError((name,r))
  return r
 try:
  command('lock',['generate-lockfile','--offline']);seen=set()
  for identity,rel,before,after,target,test,marker in selected:
   file=source/(rel if rel.startswith('tests/')else'src/'+rel);original=file.read_bytes();text=original.decode();assert text.count(before)==1,(identity,text.count(before));args=['test','--offline','--locked',*(['--lib']if target=='lib'else['--test',target]),test,'--','--exact']
   if (target,test)not in seen:command(identity+'/baseline',args);seen.add((target,test))
   mutated=text.replace(before,after).encode();file.write_bytes(mutated);write(out/(identity+'.json'),{'file':str(file),'before_sha256':hashlib.sha256(original).hexdigest(),'after_sha256':hashlib.sha256(mutated).hexdigest(),'replacement':{'before':before,'after':after},'target':target,'test':test,'required_marker':marker})
   try:
    r=command(identity+'/mutant',args,101);stdout=pathlib.Path(r['logs']['stdout']['path']).read_text();stderr=pathlib.Path(r['logs']['stderr']['path']).read_text()
    if 'error[E'in stderr or 'could not compile'in stderr or f'test {test} ... FAILED'not in stdout or marker not in stdout:raise AssertionError('no intended semantic detection: '+identity)
   finally:file.write_bytes(original)
   command(identity+'/restored',args)
  write(out/'results.json',{'status':'PASS','required':[m[0]for m in selected],'earlier_controls_require_separate_evidence':[m[0]for m in MUTANTS if m not in selected],'results':results,'resources':'Each child group and pipe retired. Private mutation sources restored byte-exactly; retained outputs are evidence only.'})
 except Exception as e:write(out/'results.json',{'status':'FAIL','results':results,'exception':repr(e)});raise
if __name__=='__main__':main()
