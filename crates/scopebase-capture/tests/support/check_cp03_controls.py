#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run bounded CP03 production mutants in a disposable copy (Python 3.11+).

No network or dependencies are acquired. Supply an offline CARGO_HOME and
SCOPEBASE_BUILD_WRAPPER=/absolute/path/to/bin/scopebase-build when outside a
ScopeBase checkout. Each Cargo invocation separately leases that common slot;
do not wrap this script in an outer build lease. A compile/setup failure is
INVALID_CONTROL, never a semantic kill. The supplied source is never edited.
"""
from __future__ import annotations
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def mutations():
    result = []
    def add(name, file, old, new, target, *tests):
        result.append(dict(id=name, file='src/'+file+'.rs', old=old, new=new,
                           target=target, tests=list(tests)))
    counter = lambda name, old, new, *tests: add(name,'counter',old,new,'counter_deltas',*tests)
    loss = lambda name, old, new, *tests: add(name,'loss',old,new,'loss_units',*tests)
    for component in ['source.epoch().capture()', 'source.epoch().producer()',
                      'source.epoch().ordinal()', 'source.binding()', 'source.origin()',
                      'channel', 'policy', 'interval.start().clock()']:
        counter('omit-context-'+component.replace('()','').replace('.','-'),
                f'baseline.{component} == current.{component}', 'true',
                'source_context_precedes_arithmetic','bound_constructor_contract',
                'bound_current_pair_reuse_refuses','bound_baseline_pair_reuse_refuses')
    for endpoint in ['current','baseline']:
        for field in ['interval.start().ticks()', 'interval.end().ticks()', 'value']:
            counter('omit-pair-'+endpoint+'-'+field.replace('()','').replace('.','-'),
                    f'{endpoint}.{field} != bound.{endpoint}.{field}', 'false',
                    'bound_'+endpoint+'_pair_reuse_refuses')
    counter('missing-as-zero', 'return Ok(Delta::Unknown(DeltaUnknown::MissingBaseline));',
            'return Ok(Delta::Exact(current.value));', 'missing_baseline_is_unknown')
    counter('stored-baseline-substitution', 'return Ok(Delta::Unknown(DeltaUnknown::MissingBaseline));',
            'return if let Some(bound) = bound { sample_delta(Some(&bound.baseline), current, Some(bound)) } else { Ok(Delta::Unknown(DeltaUnknown::MissingBaseline)) };',
            'bound_missing_baseline_and_precedence')
    counter('missing-before-current-match', '    if let Some(bound) = bound {\n        if !same_context(&bound.current, current)',
            '    if baseline.is_none() { return Ok(Delta::Unknown(DeltaUnknown::MissingBaseline)); }\n    if let Some(bound) = bound {\n        if !same_context(&bound.current, current)',
            'bound_missing_baseline_and_precedence')
    counter('baseline-before-current-match', '    if let Some(bound) = bound {\n        if !same_context(&bound.current, current)',
            '    if let Some(b) = baseline { if !same_context(b, current) { return Err(ContractError::DomainMismatch); } }\n    if let Some(bound) = bound {\n        if !same_context(&bound.current, current)',
            'bound_missing_baseline_and_precedence')
    counter('monotonic-wrapping-sub', 'CounterPolicy::Monotonic => {\n            if c < b {\n                return Ok(Delta::Unknown(DeltaUnknown::ResetOrWrap));\n            }\n            Ok(Delta::Exact(Count::new(c - b)))\n        }',
            'CounterPolicy::Monotonic => Ok(Delta::Exact(Count::new(c.wrapping_sub(b)))),', 'monotonic_and_reset')
    counter('monotonic-saturating-sub', 'CounterPolicy::Monotonic => {\n            if c < b {\n                return Ok(Delta::Unknown(DeltaUnknown::ResetOrWrap));\n            }\n            Ok(Delta::Exact(Count::new(c - b)))\n        }',
            'CounterPolicy::Monotonic => Ok(Delta::Exact(Count::new(c.saturating_sub(b)))),', 'monotonic_and_reset')
    counter('cap-exactified', 'return Ok(Delta::AtLeast(Count::new(c - b)));',
            'return Ok(Delta::Exact(Count::new(c - b)));','saturation_is_lower_bound')
    counter('saturated-as-zero', 'return Ok(Delta::Unknown(DeltaUnknown::Saturated));',
            'return Ok(Delta::Exact(Count::new(0)));','saturation_is_lower_bound')
    counter('decreasing-from-cap-clamped', 'CounterPolicy::Saturating { maximum } => {\n            if c < b {',
            'CounterPolicy::Saturating { maximum } => {\n            if b == maximum && c < b { return Ok(Delta::Exact(Count::new(0))); }\n            if c < b {', 'saturation_is_lower_bound')
    counter('ignore-overlap', 'if current.interval.start().ticks() < baseline.interval.end().ticks() {',
            'if false {','ordered_read_intervals')
    counter('ignore-reversed-comparison', '    if current.interval.start().ticks() < baseline.interval.start().ticks() {\n        return Err(ContractError::InvalidSample);\n    }',
            '    if false { return Err(ContractError::InvalidSample); }','ordered_read_intervals')
    counter('allow-nonmodulo-bound', 'if !matches!(current.policy, CounterPolicy::Modulo { .. }) {',
            'if false {','bound_constructor_contract')
    counter('allow-reversed-bound', '        if current.interval.start().ticks() < baseline.interval.start().ticks() {\n            return Err(ContractError::InvalidSample);\n        }',
            '        if false { return Err(ContractError::InvalidSample); }','bound_constructor_contract')
    counter('reject-forward-overlap-bound', '        Ok(Self {\n            baseline: baseline.clone(),',
            '        if current.interval.start().ticks() < baseline.interval.end().ticks() { return Err(ContractError::InvalidSample); }\n        Ok(Self {\n            baseline: baseline.clone(),', 'bound_constructor_contract')
    counter('derive-maximum-from-residue', '            maximum,\n',
            '            maximum: Count::new((u128::from(current.value.get()) + (1u128 << 8) - u128::from(baseline.value.get())) as u64 % 256),\n', 'bound_constructor_contract')
    counter('unbounded-wrapped-difference', 'return Ok(Delta::Unknown(DeltaUnknown::UnboundedWrap));\n            };',
            'return Ok(Delta::Exact(Count::new(c.wrapping_sub(b))));\n            };',
            'modulo_bound_is_checked','independent_four_bit_population')
    counter('accept-contradictory-bound', 'if difference > u128::from(bound.maximum.get()) {',
            'if false {','modulo_bound_is_checked','independent_four_bit_population','independent_four_bit_trace_population')
    counter('reject-equal-advance-bound', 'if difference > u128::from(bound.maximum.get()) {',
            'if difference >= u128::from(bound.maximum.get()) {','independent_four_bit_population','independent_four_bit_trace_population')
    counter('one-extra-wrap', 'let difference = (u128::from(c) + modulus - u128::from(b)) % modulus;',
            'let difference = (u128::from(c) + modulus - u128::from(b)) % modulus + modulus;',
            'independent_four_bit_population','independent_four_bit_trace_population')
    counter('width64-wrong-modulus', 'let modulus = 1u128 << width;',
            'let modulus = if width == 64 { u128::from(u64::MAX) } else { 1u128 << width };','width64_uses_u128')
    counter('skip-saturation-configuration', 'CounterPolicy::Saturating { maximum: 0 } => return Err(ContractError::InvalidSample),',
            'CounterPolicy::Saturating { maximum: 0 } => {},','sample_constructor_ranges')
    counter('skip-width-configuration', 'CounterPolicy::Modulo { width } if !(1..=64).contains(&width) => {',
            'CounterPolicy::Modulo { width } if false => {','sample_constructor_ranges')
    counter('admit-bound-at-modulus', 'if u128::from(bound.maximum.get()) >= modulus {',
            'if u128::from(bound.maximum.get()) > modulus {','independent_four_bit_population','independent_four_bit_trace_population')
    counter('use-clamped-signed-difference', 'let difference = (u128::from(c) + modulus - u128::from(b)) % modulus;',
            'let difference = u128::from(c.saturating_sub(b));','independent_four_bit_population','independent_four_bit_trace_population')
    counter('skip-value-range', 'if !valid {','if false {','sample_constructor_ranges')
    loss('signal-invalid-cap-admitted','if cap == 0 || observed > cap {','if false {','capped_signal_is_not_exact_events')
    loss('signal-observed-erased','            observed,\n','            observed: 0,\n','capped_signal_is_not_exact_events')
    loss('fold-invalid-cap-admitted','if cap == 0 {','if false {','invalid_late_lane_is_not_hidden')
    loss('fold-invalid-lane-admitted','if value > cap {','if false {','invalid_late_lane_is_not_hidden')
    loss('fold-hides-late-lane','    for &value in values {',
         '    for &value in values {\n        if total == u16::from(cap) { return Ok(cap); }','invalid_late_lane_is_not_hidden')
    loss('fold-wraps','total = (total + u16::from(value)).min(u16::from(cap));',
         'total = u16::from((total as u8).wrapping_add(value));','k_lanes_cap_and_remain_independent','diagnostic_exhaustive_pairs')
    loss('fold-max-not-sum','total = (total + u16::from(value)).min(u16::from(cap));',
         'total = total.max(u16::from(value));','k_lanes_cap_and_remain_independent','diagnostic_exhaustive_pairs')
    loss('fold-hardcoded255','total = (total + u16::from(value)).min(u16::from(cap));',
         'total = (total + u16::from(value)).min(255);','k_lanes_cap_and_remain_independent','diagnostic_exhaustive_pairs')
    for name,expr in [('unknown-as-zero','if matches!(magnitude, LossMagnitude::Unknown) { LossMagnitude::Exact(Count::new(0)) } else { magnitude }'),
                      ('diagnostic255-as-exact-omissions','if kind == LossKind::Attribution && matches!(magnitude, LossMagnitude::Unknown) { LossMagnitude::Exact(Count::new(255)) } else { magnitude }'),
                      ('lower-bound-as-exact','if let LossMagnitude::AtLeast(n) = magnitude { LossMagnitude::Exact(n) } else { magnitude }')]:
        loss(name,'            magnitude,\n','            magnitude: '+expr+',\n','kinds_units_and_magnitudes_are_retained')
    for field,expr in [('kind','LossKind::Discovery'),('channel','ChannelId::new(0)'),('source','SourceRef::new(source.epoch().clone(), source.binding(), crate::domain::Origin::Replayed)')]:
        # source/channel occur in two constructors: select the whole loss-fact block.
        old='        Ok(Self {\n            source,\n            channel,\n            kind,\n            magnitude,\n        })'
        new=old.replace('            '+field+',','            '+field+': '+expr+',')
        loss('erase-loss-'+field,old,new,'kinds_units_and_magnitudes_are_retained')
    return result


def execute(argv, cwd, env, stem):
    """Own one process group; persist logs and retirement even on timeout."""
    stem=Path(stem); stem.parent.mkdir(parents=True,exist_ok=True)
    start=time.monotonic(); timed_out=False; retired=False
    with stem.with_suffix('.stdout').open('xb') as out, stem.with_suffix('.stderr').open('xb') as err:
        proc=subprocess.Popen([str(v) for v in argv],cwd=cwd,env=env,stdout=out,stderr=err,start_new_session=True)
        try:
            code=proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            timed_out=True;os.killpg(proc.pid,signal.SIGKILL);code=proc.wait(timeout=10)
        try: os.killpg(proc.pid,0)
        except ProcessLookupError: retired=True
    return dict(command=[str(v) for v in argv],cwd=str(cwd),exit_code=code,timeout=timed_out,
                retired=retired,duration_ms=round((time.monotonic()-start)*1000),
                stdout=str(stem.with_suffix('.stdout')),stderr=str(stem.with_suffix('.stderr')))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--cargo',type=Path,required=True)
    parser.add_argument('--rustc',type=Path,required=True)
    parser.add_argument('--feature-set',choices=['no-default','default','json'],required=True)
    parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args(argv)
    raw=args.source_root; source=raw.resolve(); output=args.output_dir
    if not raw.is_absolute() or not output.is_absolute() or output.exists() or 'donor-snapshots' in source.parts:
        parser.error('absolute non-donor source and new absolute output directory required')
    if output.resolve().is_relative_to(source) or any(p.is_symlink() for p in [output,*output.parents]):
        parser.error('output must be outside source with no symlink ancestors')
    for compiler in [args.cargo,args.rustc]:
        if not compiler.is_absolute() or not compiler.is_file(): parser.error('absolute existing compiler paths required')
    wrapper=os.environ.get('SCOPEBASE_BUILD_WRAPPER')
    if wrapper is None:
        wrapper=next((str(parent/'bin/scopebase-build') for parent in source.parents if (parent/'bin/scopebase-build').is_file()),None)
    if wrapper is None or not Path(wrapper).is_absolute() or not Path(wrapper).is_file():
        parser.error('SCOPEBASE_BUILD_WRAPPER must name the common build-slot wrapper')
    files={str(p.relative_to(source)):digest(p) for p in source.rglob('*') if p.is_file() and not set(p.relative_to(source).parts)&{'.git','target','__pycache__'}}
    if any(p.is_symlink() for p in source.rglob('*')): parser.error('source symlinks are unsupported')
    required=['Cargo.toml','src/counter.rs','src/loss.rs','tests/counter_deltas.rs','tests/loss_units.rs']
    if any(v not in files for v in required): parser.error('source must be the actual CP03 crate root')
    output.mkdir(parents=True,mode=0o700); subject=output/'subject';subject.mkdir()
    for name in files:
        dest=subject/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/name,dest)
    # Independent standalone workspace, with no changes to the input source.
    with (subject/'Cargo.toml').open('a') as f:f.write('\n[workspace]\n')
    for name in ['tmp','home','cargo-home']:(output/name).mkdir()
    inherited=os.environ.get('CARGO_HOME')
    cargo_home=output/'cargo-home'
    if inherited and (Path(inherited)/'config.toml').is_file(): shutil.copyfile(Path(inherited)/'config.toml',cargo_home/'config.toml')
    elif inherited: cargo_home=Path(inherited)
    env={'PATH':str(args.rustc.parent)+':/usr/bin:/bin','HOME':str(output/'home'),'TMPDIR':str(output/'tmp'),
         'CARGO_HOME':str(cargo_home),'CARGO_TARGET_DIR':str(output/'target'),'CARGO_NET_OFFLINE':'true',
         'RUSTC':str(args.rustc),'RUSTDOC':str(args.rustc.with_name('rustdoc')),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
    report=dict(schema_version=1,source_root=str(source),input_sha256=files,feature_set=args.feature_set,
                wrapper=wrapper,compiler_identity={},cargo_sha256=digest(args.cargo),rustc_sha256=digest(args.rustc),rows=[],status='INVALID_CONTROL')
    report_path=output/'report.json'
    def save():report_path.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    def command(arguments,stem):return execute([wrapper,'--',args.cargo,*arguments],subject,env,output/'logs'/stem)
    for name,path in [('cargo',args.cargo),('rustc',args.rustc)]:
        result=execute([path,'--version','--verbose'],subject,env,output/'logs'/(name+'-identity'));report['compiler_identity'][name]=result
        if result['exit_code']!=0:save();return 1
    lock=command(['generate-lockfile','--offline'],'lock')
    report['lock_generation']=lock
    if lock['exit_code']!=0:save();return 1
    report['lock_sha256']=digest(subject/'Cargo.lock')
    flags={'no-default':['--no-default-features'],'default':[],'json':['--no-default-features','--features','json']}[args.feature_set]
    def build(target,stem):
        r=command(['test','--locked','--offline','--test',target,'--no-run','--message-format=json',*flags],stem)
        executable=None
        if r['exit_code']==0 and not r['timeout'] and r['retired']:
            for line in Path(r['stdout']).read_text().splitlines():
                try:item=json.loads(line)
                except json.JSONDecodeError:continue
                if item.get('reason')=='compiler-artifact' and item.get('target',{}).get('name')==target and item.get('executable'):
                    executable=item['executable']
        return r,executable
    def tests(binary,names,stem,negative):
        records=[]
        for name in names:
            r=execute([binary,'--exact',name,'--nocapture'],subject,env,output/'logs'/(stem+'-'+name))
            out=Path(r['stdout']).read_text();err=Path(r['stderr']).read_text()
            reached=('running 1 test' in out and f'test {name} ... FAILED' in out and 'assertion `left == right` failed' in err)
            passed=r['exit_code']==0 and '1 passed; 0 failed' in out
            r['semantic_assertion_reached']=reached
            r['valid']=r['retired'] and not r['timeout'] and (r['exit_code']==101 and reached if negative else passed)
            records.append(r)
        return records
    baseline={}
    for target in ['counter_deltas','loss_units']:
        build_result,binary=build(target,'baseline-'+target)
        baseline[target]=dict(build=build_result)
        if binary is None:report['baseline']=baseline;save();return 1
        r=execute([binary],subject,env,output/'logs'/('baseline-test-'+target))
        baseline[target]['test']=r
        if r['exit_code']!=0:report['baseline']=baseline;save();return 1
    report['baseline']=baseline
    for mutation in mutations():
        row={k:v for k,v in mutation.items() if k not in ('old','new')};row['status']='INVALID_CONTROL';report['rows'].append(row)
        path=subject/mutation['file']; original=path.read_text()
        if original.count(mutation['old'])!=1:
            row['reason']='replacement must match exactly once';row['matches']=original.count(mutation['old']);save();continue
        changed=original.replace(mutation['old'],mutation['new'],1)
        diff=output/'diffs'/(mutation['id']+'.patch');diff.parent.mkdir(exist_ok=True)
        diff.write_text(''.join(difflib.unified_diff(original.splitlines(True),changed.splitlines(True),fromfile=mutation['file'],tofile=mutation['file'])))
        row.update(diff=str(diff),before_sha256=digest(path));path.write_text(changed);row['mutant_sha256']=digest(path)
        try:
            r,binary=build(mutation['target'],mutation['id']+'-build');row['build']=r
            if binary is not None:
                row['mutant_tests']=tests(binary,mutation['tests'],mutation['id']+'-mutant',True)
        finally:path.write_text(original)
        r,binary=build(mutation['target'],mutation['id']+'-restored-build');row['restored_build']=r
        if binary is not None:row['restored_tests']=tests(binary,mutation['tests'],mutation['id']+'-restored',False)
        row['restored_sha256']=digest(path)
        if (row.get('mutant_tests') and all(r['valid'] for r in row['mutant_tests']) and row.get('restored_tests') and all(r['valid'] for r in row['restored_tests']) and row['restored_sha256']==row['before_sha256']):row['status']='KILLED_SEMANTIC'
        save()
    report['source_unchanged']=all(digest(source/name)==sha for name,sha in files.items())
    report['status']='PASS' if report['source_unchanged'] and all(r['status']=='KILLED_SEMANTIC' for r in report['rows']) else 'INVALID_CONTROL'
    save();print(json.dumps(dict(status=report['status'],controls=len(report['rows']),report=str(report_path))))
    return 0 if report['status']=='PASS' else 1


if __name__=='__main__':sys.exit(main())
