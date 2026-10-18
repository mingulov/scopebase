#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute frozen SB02 host API experiments using admitted offline Cargo inputs."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import shutil
import sys
import tomllib
import common as p


def candidate_declaration(data, case):
    name=case['candidate']['name']
    deps=data.get('dependencies',{})
    matches=[d for key,d in deps.items() if (d.get('package',key) if isinstance(d,dict) else key)==name]
    if len(matches)!=1 or not isinstance(matches[0],dict):
        raise p.PolicyError('CANDIDATE_DECLARATION_MISMATCH')
    dep=matches[0]
    if dep.get('default-features',True)!=case['default_features'] or set(dep.get('features',[]))!=set(case['features']):
        raise p.PolicyError('CANDIDATE_FEATURE_MISMATCH')
    if case['candidate']['source']==p.REGISTRY:
        if dep.get('version')!='='+case['candidate']['version'] or any(k in dep for k in ('git','path','registry')):
            raise p.PolicyError('CANDIDATE_PIN_MISMATCH')
    elif case['candidate']['source']==p.BTF_SOURCE:
        if dep.get('git')!=p.BTF_URL or dep.get('rev')!=p.BTF_REV or any(k in dep for k in ('path','branch','tag','package')):
            raise p.PolicyError('SOURCE_MAPPING')
    else:
        raise p.PolicyError('SOURCE_MAPPING')
    return dep


def acquisition_lock(canonical_raw, staging, btf_entry=None):
    expected=tomllib.loads(canonical_raw)
    for lock in staging['inventory']['cargo_vendor']['acquisition_locks']:
        # stage_inputs has already verified both immutable raw hashes.
        acquired=tomllib.loads(Path(lock['manifest']).read_text())
        if btf_entry is not None:
            deps=acquired.get('dependencies',{}); dep=deps.get('btf-rs')
            if not isinstance(dep,dict) or 'path' not in dep:
                continue
            path=Path(dep['path'])
            if not path.is_absolute():
                path=Path(lock['manifest']).parent/path
            rel=Path(next(v['manifest'] for v in btf_entry['bundle']['packages'] if v['name']=='btf-rs'))
            bundle_root=path.resolve()
            for _ in rel.parent.parts: bundle_root=bundle_root.parent
            try:
                for entry in btf_entry['bundle']['files']:
                    observed=p.relative(bundle_root,entry['path'])
                    if entry['kind']=='file': p.check_hash(observed,entry['sha256'])
                    elif not observed.is_symlink() or observed.readlink().as_posix()!=entry['link_target']:
                        raise p.PolicyError('INPUT_CHANGED')
            except (p.InputError,p.PolicyError):
                continue
            normalized=json.loads(json.dumps(acquired))
            mapped=normalized['dependencies']['btf-rs']; del mapped['path']; mapped['git']=p.BTF_URL; mapped['rev']=p.BTF_REV
            if normalized!=expected: continue
        elif acquired!=expected:
            continue
        return Path(lock['lock'])
    raise p.PolicyError('ACQUISITION_LOCK_UNAVAILABLE','BLOCKED')


def prepare_case(ex,case,matrix_root,negative=False,manifest_override=None):
    original=p.relative(matrix_root,manifest_override or case['manifest'])
    raw=original.read_text(); data=tomllib.loads(raw)
    candidate_declaration(data,case)
    source=ex.output/'probes'/((case['id']+'-negative') if negative else case['id'])
    p.source_copy(original.parent,source)
    btf=next((r for r in ex.staging['packages'] if r['name']=='btf-rs' and r['source']==p.BTF_SOURCE),None) if case['candidate']['source']==p.BTF_SOURCE else None
    edges=p.staged_edges(ex.staging)
    if btf:
        effective=p.map_btf_manifest(raw,btf['root'])
        (source/'Cargo.toml').write_text(effective)
        edges.append((source/'Cargo.toml',btf['root']))
        ex.report['staged_inputs'].append({'kind':'probe-manifest-mapping','case':case['id'],
            'original_manifest_sha256':p.sha(original),'effective_manifest_sha256':p.sha(source/'Cargo.toml'),
            'upstream_source':p.BTF_SOURCE,'local_source':str(btf['root'])})
    p.inspect_manifest(source/'Cargo.toml',edges)
    trusted={source/'Cargo.toml':{'source':'fixture:probe-'+case['id'],'sha256':p.fixture_digest(original.parent),'edges':edges}}
    if negative:
        # Negative controls have new local package identities. Cargo independently
        # resolves them offline, then full admission proves setup before refusal.
        return source,trusted
    lock=acquisition_lock(raw,ex.staging,btf)
    shutil.copyfile(lock,source/'Cargo.lock')
    return source,trusted,p.sha(source/'Cargo.lock')


def verify_candidate(metadata,case,staging):
    candidate=case['candidate']
    packages=[v for v in metadata['packages'] if v['name']==candidate['name'] and v['version']==candidate['version']]
    if len(packages)!=1: raise p.PolicyError('CANDIDATE_IDENTITY_MISMATCH')
    package=packages[0]
    bound=next((r for r in staging['packages'] if (r['root']/'Cargo.toml').resolve()==Path(package['manifest_path']).resolve()),None)
    if bound is None or any(bound[k]!=candidate[k] for k in ('name','version','source','sha256')):
        raise p.PolicyError('CANDIDATE_IDENTITY_MISMATCH')
    node=next(n for n in metadata['resolve']['nodes'] if n['id']==package['id'])
    # Declaration equality is authoritative; actual additive resolved features
    # (including dependency-implied std/alloc) remain visible in the report.
    if not set(case['features']).issubset(node['features']):
        raise p.PolicyError('CANDIDATE_FEATURE_MISMATCH')
    return {'candidate_id':package['id'],'declared_features':case['features'],
            'resolved_candidate_features':node['features'],
            'additive_features':sorted(set(node['features'])-set(case['features']))}


def run_case(ex,case,matrix_root,positive_states):
    if case['availability']=='pending_acquisition':
        raise p.PolicyError('SOURCE_UNAVAILABLE','BLOCKED')
    source,trusted,lock_sha=ex.step(case['id']+'-prepare',lambda r:prepare_case(ex,case,matrix_root))
    for t in ex.matrix['toolchains']:
        stem=case['id']+'-'+t['id']; budget=p.CellBudget(stem); target=ex.output/'targets'/case['id']/t['id']
        try:
            def metadata(r):
                p.check_hash(source/'Cargo.lock',lock_sha,'LOCK_CHANGED')
                data=p.metadata_admission(ex,r,t,source/'Cargo.toml',target,case['allowed_dependencies'],trusted,budget=budget)
                r['observed']=verify_candidate(data,case,ex.staging)
            ex.step(stem+'-admit',metadata)
            ex.step(stem+'-check',lambda r:ex.command(r,t,source/'Cargo.toml',['check','--offline','--locked','--all-targets'],target,budget=budget))
            positive_states.add((case['id'],t['id']))
            def tests(r):
                result=ex.command(r,t,source/'Cargo.toml',['test','--offline','--locked','--lib','--tests'],target,budget=budget)
                output=p.stdout(result)
                missing=[name for name in case['assertions'] if not re.search(r'^test '+re.escape(name)+r' \.\.\. ok$',output,re.M)]
                if missing: raise p.PolicyError('ASSERTION_NOT_EXECUTED',detail={'missing':missing})
                r['expected']={**(r['expected'] or {}),'assertions':case['assertions']}
                r['observed']={'assertions_executed':case['assertions'],'tier':case['tier'],
                               'effectful_api_calls':'typed only; fixture source is the reviewed execution authority'}
            fit='GAP' if case['expected_fit'] in ('GAP','OBSERVE') else 'SATISFIED'
            ex.step(stem+'-test',tests,fit)
            ex.step(stem+'-doc',lambda r:ex.command(r,t,source/'Cargo.toml',['test','--offline','--locked','--doc'],target,budget=budget))
        except p.PolicyError:
            continue


def accept_refusal(result, lock, lock_sha, code, contains, source):
    if result['cleanup']!='complete':
        raise p.PolicyError('CLEANUP_UNRESOLVED','BLOCKED',result)
    if result['reason_code'] is not None:
        raise p.PolicyError(result['reason_code'],'BLOCKED',result)
    if result['exit_code'] is None or result['exit_code'] < 0:
        raise p.PolicyError('REFUSAL_INCOMPLETE','BLOCKED',result)
    p.check_hash(lock,lock_sha,'LOCK_CHANGED')
    if result['exit_code']==0 or not p.rust_refusal(p.stdout(result),code,contains,source):
        raise p.PolicyError('WRONG_COMPILE_REFUSAL',detail=result)


def run_refusal(ex,case,refusal,matrix_root,positive_states):
    # Use its own copied source and independent offline lock. Preserve public
    # positive build separately from the expected diagnostic result.
    negative=dict(case,id=case['id']+'-'+refusal['id'])
    source,trusted=ex.step(negative['id']+'-prepare',lambda r:prepare_case(ex,negative,matrix_root,True,refusal['manifest']))
    msrv=ex.matrix['toolchains'][0]; stem=negative['id']
    def refusal_lock(r):
        ex.command(r,msrv,source/'Cargo.toml',['generate-lockfile','--offline'],ex.output/'unused-target')
        return p.sha(source/'Cargo.lock')
    lock_sha=ex.step(stem+'-lock',refusal_lock)
    for t in ex.matrix['toolchains']:
        ident=stem+'-'+t['id']; budget=p.CellBudget(ident); target=ex.output/'targets'/stem/t['id']
        try:
            def setup(r):
                if (refusal['positive_case'],t['id']) not in positive_states:
                    raise p.PolicyError('POSITIVE_CONTROL_INCOMPLETE','BLOCKED')
                p.check_hash(source/'Cargo.lock',lock_sha,'LOCK_CHANGED')
                data=p.metadata_admission(ex,r,t,source/'Cargo.toml',target,case['allowed_dependencies'],trusted,budget=budget)
                r['observed']=verify_candidate(data,case,ex.staging)
                return data
            ex.step(ident+'-admit',setup)
            def check(r):
                p.check_hash(source/'Cargo.lock',lock_sha,'LOCK_CHANGED')
                argv=[Path(t['root'])/'bin/cargo','check','--offline','--locked','--all-targets','--message-format','json','--manifest-path',source/'Cargo.toml']
                timeout=budget.remaining()
                r['expected']={'cell':budget.ident,'wall_budget_seconds':budget.seconds}
                result=p.run(argv,source,p.clean_env(ex.output,t,target),ex.output/'logs'/r['id'],timeout=timeout)
                budget.complete(result)
                ex.attach(r,result); r['input_sha256']=p.tree_digest(source); r['lock_sha256']=p.sha(source/'Cargo.lock')
                accept_refusal(result,source/'Cargo.lock',lock_sha,refusal['diagnostic_code'],refusal['diagnostic_contains'],source)
                r['expected']={**(r['expected'] or {}),'code':refusal['diagnostic_code'],'contains':refusal['diagnostic_contains'],'positive_case':refusal['positive_case']}
                r['observed']={'intended_diagnostic':True,'positive_build':True}
            ex.step(ident+'-refusal',check,'GAP')
        except p.PolicyError: continue


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix',type=Path,required=True)
    parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--case',action='append',default=[])
    args=parser.parse_args(argv); ex=None
    try:
        path=args.matrix.resolve(); matrix=p.validate_matrix(path,'probe')
        all_cases=matrix['cases']; known={c['id'] for c in all_cases}
        if set(args.case)-known or len(set(args.case))!=len(args.case): raise p.InputError('UNKNOWN_OR_DUPLICATE_CASE')
        cases=[c for c in all_cases if not args.case or c['id'] in args.case]
        omitted=[ident for c in all_cases if c not in cases and c['required'] for ident in p.probe_case_row_ids(c,matrix['toolchains'])]
        sources=[path.parent,*[p.relative(path.parent,c['manifest'],False).parent for c in cases]]
        p.validate_report_target(args.report,sources)
        output=p.fresh_output(args.output_dir,sources)
        ex=p.Execution('dependency_probe',path,matrix,output,scope='selected_cases' if args.case else 'full',omitted=omitted)
        ex.reserve('inputs',phase='staging')
        for t in matrix['toolchains']:
            for suffix in ('','-rustc','-cargo'):
                ex.reserve('identity-'+t['id']+suffix,role='configuration',toolchain=t['id'],phase='identity'+suffix)
        for case in cases:
            ex.reserve(case['id']+'-source',required=case['required'],phase='source')
            ex.reserve(case['id']+'-prepare',required=case['required'],phase='prepare')
            for t in matrix['toolchains']:
                for phase in ('admit','check','test','doc'):
                    ex.reserve(case['id']+'-'+t['id']+'-'+phase,toolchain=t['id'],phase=phase,required=case['required'])
            for refusal in case['compile_refusals']:
                stem=case['id']+'-'+refusal['id']; ex.reserve(stem+'-prepare',phase='prepare',required=case['required']); ex.reserve(stem+'-lock',phase='lock',required=case['required'])
                for t in matrix['toolchains']:
                    for phase in ('admit','refusal'):
                        ex.reserve(stem+'-'+t['id']+'-'+phase,toolchain=t['id'],phase=phase,required=case['required'])
        ex.staging=ex.step('inputs',lambda r:p.stage_inputs(matrix['cargo_inputs'],output))
        ex.report['staged_inputs']=ex.staging['staged_inputs']
        for t in matrix['toolchains']: ex.report['toolchains'].append(ex.step('identity-'+t['id'],lambda r:p.toolchain_info(t,output,ex)))
        positives=set()
        for case in cases:
            try:
                def source(r):
                    if case['availability']=='pending_acquisition': raise p.PolicyError('SOURCE_UNAVAILABLE','BLOCKED')
                    manifest=p.relative(path.parent,case['manifest'])
                    candidate_declaration(tomllib.loads(manifest.read_text()),case)
                    r['input_sha256']=p.tree_digest(manifest.parent)
                    r['observed']={'available_storage_bytes':shutil.disk_usage(output).free,'manifest_sha256':p.sha(manifest)}
                ex.step(case['id']+'-source',source)
                run_case(ex,case,path.parent,positives)
            except p.PolicyError:
                continue
        for case in cases:
            for refusal in case['compile_refusals']:
                try: run_refusal(ex,case,refusal,path.parent,positives)
                except p.PolicyError:
                    continue
        return ex.finish(args.report)
    except p.InputError as e:
        print(str(e)[:1024],file=sys.stderr); return 2
    except (p.PolicyError,OSError,tomllib.TOMLDecodeError) as e:
        if ex: return ex.abort(e,args.report)
        print(str(e)[:1024],file=sys.stderr); return 3 if isinstance(e,p.PolicyError) and e.status=='BLOCKED' else 2
    except Exception as error:
        print('INTERNAL_ERROR: '+type(error).__name__,file=sys.stderr)
        if ex: return ex.abort(error,args.report)
        return 1


if __name__=='__main__':
    sys.exit(main())
