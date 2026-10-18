#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded CP04 corpus and actual-package semantic controls (Python 3.11+).

Only run executes code. The optional explicit build wrapper routes Cargo calls;
without it Cargo is direct. No ambient wrapper discovery or coordinator lease
is performed. Supply an absolute existing offline CARGO_HOME/config.toml.
"""
from __future__ import annotations
import argparse
import copy
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

MAX_BYTES=65536
ERRORS={'MissingProvenance','ConflictingProvenance','SaturatedCount','ArithmeticOverflow'}
REQUIRED=set('empty busy_missing equal_owners unequal_owners zero_known secondary_sum exact_max exact_max_zero sum_equals_max sum_overflow saturated_owner saturated_secondary missing_beats_saturated missing_beats_overflow conflict_beats_saturated conflict_beats_overflow overflow_before_saturated saturated_before_overflow zero_activity_owner owner_last'.split())
class InvalidCorpus(ValueError): pass

def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def reject(message): raise InvalidCorpus(message)
def keys(value,wanted):
    if type(value) is not dict or set(value)!=set(wanted): reject('object fields')
def decimal(value,lo,hi):
    if type(value) is not str or not re.fullmatch(r'0|[1-9][0-9]*|-[1-9][0-9]*',value) or len(value)>21:reject('decimal syntax')
    n=int(value)
    if not lo<=n<=hi:reject('decimal range')
    return n

def identity(value):
    if type(value)is not list or len(value)!=3:reject('identity tuple')
    return [decimal(value[0],0,2**32-1),decimal(value[1],0,2**64-1),decimal(value[2],-2**31,2**31-1)]
def duplicate_free(pairs):
    result={}
    for k,v in pairs:
        if k in result:reject('duplicate member')
        result[k]=v
    return result

def validate_bytes(data):
    if len(data)>MAX_BYTES:reject('byte limit')
    try:
        root=json.loads(data.decode('utf-8'),object_pairs_hook=duplicate_free,parse_constant=lambda _:reject('nonstandard constant'))
        keys(root,{'schema_version','kind','cases'})
        if type(root['schema_version'])is not int or root['schema_version']!=1 or type(root['kind'])is not str or root['kind']!='cp04-host-vectors':reject('schema')
        cases=root['cases']
        if type(cases)is not list or not 1<=len(cases)<=128:reject('case limit')
        seen=set()
        for case in cases:
            keys(case,{'id','lanes','expected'});name=case['id']
            if type(name)is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',name)or name in seen:reject('case ID')
            seen.add(name)
            if type(case['lanes'])is not list or len(case['lanes'])>8:reject('lane limit')
            for lane in case['lanes']:
                keys(lane,{'identity','count'})
                if lane['identity']is not None:identity(lane['identity'])
                if lane['count']!='saturated':decimal(lane['count'],0,2**64-1)
                elif type(lane['count'])is not str:reject('saturation scalar')
            expected=case['expected']
            if type(expected)is dict and set(expected)=={'error'}:
                if type(expected['error'])is not str or expected['error']not in ERRORS:reject('error vocabulary')
            else:
                keys(expected,{'identity','total'});identity(expected['identity']);decimal(expected['total'],0,2**64-1)
        if not REQUIRED<=seen:reject('missing required population')
        return root
    except (UnicodeError,json.JSONDecodeError,RecursionError,TypeError,OverflowError,ValueError)as exc:
        if isinstance(exc,InvalidCorpus):raise
        raise InvalidCorpus('invalid bounded JSON')from exc

def fixture(source,mirror=None):
    with (source/'fixtures/insertion-v1.json').open('rb')as f:data=f.read(MAX_BYTES+1)
    root=validate_bytes(data)
    if mirror is not None:
        with mirror.open('rb')as f:other=f.read(MAX_BYTES+1)
        if data!=other:reject('mirror differs')
    return root,data

def malformed_controls(root,data):
    mutations=[]
    def case(v,name):return next(c for c in v['cases']if c['id']==name)
    def change(name,fn):
        v=copy.deepcopy(root);fn(v);mutations.append((name,json.dumps(v).encode()))
    mutations.append(('duplicate-member',json.dumps(root).encode().replace(b'"schema_version": 1',b'"schema_version": 1, "schema_version": 1',1)))
    change('unknown-key',lambda v:v.update(extra=0))
    change('missing-key',lambda v:v.pop('kind'))
    change('missing-required-case',lambda v:v['cases'].remove(case(v,'owner_last')))
    change('duplicate-id',lambda v:v['cases'].append(copy.deepcopy(v['cases'][0])))
    change('bool-version',lambda v:v.update(schema_version=True))
    change('bool-count',lambda v:case(v,'busy_missing')['lanes'][0].update(count=True))
    change('numeric-overflow',lambda v:case(v,'busy_missing')['lanes'][0].update(count=str(2**64)))
    change('noncanonical',lambda v:case(v,'busy_missing')['lanes'][0].update(count='01'))
    change('negative-zero',lambda v:case(v,'busy_missing')['lanes'][0].update(count='-0'))
    change('lane-limit',lambda v:case(v,'busy_missing').update(lanes=case(v,'busy_missing')['lanes']*9))
    change('case-limit',lambda v:v.update(cases=v['cases']*7))
    change('injected-number',lambda v:case(v,'busy_missing')['lanes'][0].update(count='0); panic!("injected")'))
    change('injected-error',lambda v:v['cases'][0]['expected'].update(error='MissingProvenance; panic!()'))
    change('injected-id',lambda v:v['cases'][0].update(id='x\"; panic!()'))
    change('uid-overflow',lambda v:case(v,'zero_known')['lanes'][0]['identity'].__setitem__(0,str(2**32)))
    change('stack-overflow',lambda v:case(v,'zero_known')['lanes'][0]['identity'].__setitem__(2,str(2**31)))
    mutations.extend([('byte-limit',b' '*(MAX_BYTES+1)),('invalid-utf8',b'\xff'),('recursion',b'['*2000+b'0'+b']'*2000),('nonstandard-nan',b'{"schema_version":NaN}')])
    records=[]
    for name,bad in mutations:
        try:validate_bytes(bad)
        except InvalidCorpus:pass
        else:raise InvalidCorpus('malformed population admitted: '+name)
        validate_bytes(data)
        records.append({'id':name,'status':'REFUSED_BEFORE_GENERATION','generated':False,'cargo_calls':0,'restored':'VALID'})
    return records

def generated(root):
    header='// SPDX-License-Identifier: Apache-2.0\nuse scopebase_capture::{provenance::*,quantity::{Count,Events},ContractError};\n'
    def ident(value):
        n=identity(value);return '('+str(n[0])+'u32,'+str(n[1])+'u64,'+str(n[2])+'i32)'
    code=[header]
    for index,case in enumerate(root['cases']):
        ls=[]
        for lane in case['lanes']:
            mark='LaneIdentity::Secondary'if lane['identity']is None else 'LaneIdentity::InsertionOwner('+ident(lane['identity'])+')'
            ls.append('ProvenanceLane::<(u32,u64,i32),Events>::saturated('+mark+')'if lane['count']=='saturated'else 'ProvenanceLane::<(u32,u64,i32),Events>::new('+mark+',Count::new('+str(decimal(lane['count'],0,2**64-1))+'u64))')
        prefix='#[test] fn vector_'+str(index).zfill(3)+'(){let lanes:[ProvenanceLane<(u32,u64,i32),Events>;'+str(len(ls))+']=['+','.join(ls)+'];let result=fold_insertion_identity(&lanes);'
        expected=case['expected']
        if 'error'in expected:body='assert_eq!(result.err(),Some(ContractError::'+expected['error']+'));'
        else:body='assert_eq!(result.map(|v|(*v.identity(),v.total().get())),Ok(('+ident(expected['identity'])+','+str(decimal(expected['total'],0,2**64-1))+'u64)));'
        code.append(prefix+body+'}\n')
    return ''.join(code)

def execute(argv,cwd,env,stem,cargo_mode=None):
    """Own one child group, including cleanup/finalization on interruption."""
    stem=Path(stem);stem.parent.mkdir(parents=True,exist_ok=True)
    start=time.time();timed_out=False;interrupted=False;retired=False;pid=None;code=None
    with stem.with_suffix('.stdout').open('xb')as out,stem.with_suffix('.stderr').open('xb')as err:
        proc=subprocess.Popen([str(v)for v in argv],cwd=cwd,env=env,stdout=out,stderr=err,start_new_session=True);pid=proc.pid
        try:code=proc.wait(timeout=120)
        except subprocess.TimeoutExpired:timed_out=True
        except (KeyboardInterrupt,SystemExit):interrupted=True
        finally:
            deadline=time.monotonic()+10
            # Retire descendants even if their direct parent already exited.
            try:os.killpg(pid,0)
            except ProcessLookupError:retired=True
            if not retired:
                try:os.killpg(pid,signal.SIGKILL)
                except ProcessLookupError:pass
                try:code=proc.wait(timeout=max(.01,deadline-time.monotonic()))
                except subprocess.TimeoutExpired:pass
                while time.monotonic()<deadline:
                    try:os.killpg(pid,0)
                    except ProcessLookupError:retired=True;break
                    time.sleep(.01)
    return {'command':[str(v)for v in argv],'command_mode':cargo_mode,'cwd':str(cwd),'process_group':pid,'start_unix':start,'end_unix':time.time(),'exit_code':code,'timeout':timed_out,'interrupted':interrupted,'retired':retired,'stdout':str(stem.with_suffix('.stdout')),'stderr':str(stem.with_suffix('.stderr'))}

def clean(row):return row['retired']and not row['timeout']and not row['interrupted']
def no_symlinks(path):return not any(p.is_symlink()for p in [path,*path.parents])
def absolute_file(path,executable=False):return path.is_absolute()and no_symlinks(path)and path.is_file()and(not executable or os.access(path,os.X_OK))

def mutations():
    # Exact anchors intentionally fail closed. Tests/production source are never
    # edited in place; every semantic row includes actual compilation and twin.
    m=[]
    def add(name,file,old,new,*tests,target='insertion_provenance',scope='production'):
        m.append(dict(id=name,file=file,old=old,new=new,target=target,tests=list(tests),scope=scope))
    def prod(name,old,new,*tests):add(name,'src/provenance.rs',old,new,*tests)
    def model(name,old,new,*tests,target='insertion_provenance'):add(name,'tests/support/cp04_model.rs',old,new,*tests,target=target,scope='test-only producer model')
    prod('first-lane','let owner = owner.ok_or(ContractError::MissingProvenance)?;','let _owner = owner.ok_or(ContractError::MissingProvenance)?; let owner = 0;','secondary_counts_are_conserved')
    prod('last-secondary','let owner = owner.ok_or(ContractError::MissingProvenance)?;','let _owner = owner.ok_or(ContractError::MissingProvenance)?; let owner = lanes.len()-1;','migration_keeps_inserting_identity')
    model('zero-as-missing','if lane.marked {','if lane.marked && lane.identity.0 != 0 {','zero_identity_is_known')
    prod('owner-deduplication','if owner.is_some() {\n                return Err(ContractError::ConflictingProvenance);\n            }','if let Some(previous) = owner { if lanes[previous].identity == lane.identity { continue; } return Err(ContractError::ConflictingProvenance); }','two_equal_owners_still_conflict')
    model('race-loser-mark','// CP04_CONTROL_RACE: only the successful inserter marks its lane.','self.lanes[loser].marked = true; // wrong losing insertion mark','race_loser_never_marks')
    model('hit-refresh','// CP04_CONTROL_HIT: identity and marker are untouched by a hit.','for lane in &mut self.lanes { if lane.marked { lane.identity.0 = display as u32; } }','migration_under_change_keeps_insertion_identity')
    prod('owner-only-tally','for lane in lanes {','for lane in lanes { if matches!(lane.identity, LaneIdentity::Secondary) { continue; }','secondary_counts_are_conserved')
    for name,method in [('saturating-total','saturating_add'),('wrapping-total','wrapping_add')]:
        prod(name,'total = total.checked_add(count)?;','total = Count::new(total.get().'+method+'(count.get()));','explicit_saturation_and_exact_max_are_distinct')
    prod('ignored-saturated','let count = lane.count.ok_or(ContractError::SaturatedCount)?;','let count = lane.count.unwrap_or(Count::new(0));','explicit_saturation_and_exact_max_are_distinct')
    model('raw-max-treated-exact','if raw == u64::MAX {','if false {','explicit_saturation_and_exact_max_are_distinct')
    prod('generic-max-refused','total = total.checked_add(count)?;','if count.get()==u64::MAX { return Err(ContractError::SaturatedCount); } total = total.checked_add(count)?;','explicit_saturation_and_exact_max_are_distinct')
    count_loop='    let mut total = Count::new(0);\n    for lane in lanes {\n        let count = lane.count.ok_or(ContractError::SaturatedCount)?;\n        total = total.checked_add(count)?;\n    }\n'
    prod('arithmetic-before-ownership','    let mut owner: Option<usize> = None;','    { let mut sum = Count::new(0); for lane in lanes { sum = sum.checked_add(lane.count.ok_or(ContractError::SaturatedCount)?)?; } }\n    let mut owner: Option<usize> = None;','owner_errors_precede_count_errors')
    prod('global-saturation-prescan','    let mut total = Count::new(0);','    if lanes.iter().any(|v|v.count.is_none()) { return Err(ContractError::SaturatedCount); }\n    let mut total = Count::new(0);','count_errors_follow_lane_order')
    prod('eager-clone','    let mut owner: Option<usize> = None;','    for lane in lanes { if let LaneIdentity::InsertionOwner(identity)=&lane.identity { let _=identity.clone(); } }\n    let mut owner: Option<usize> = None;','payload_clone_and_equality_contract')
    # Safe output-redaction sensitivity, per controller ruling. This fixed
    # secret is independently carried by the test identity; no arbitrary-I
    # extraction or unsafe code is manufactured by the control.
    prod('debug-disclosure','f.write_str("Known(<redacted>)")','f.write_str("Known(986543210123456789)")','generic_traits_and_redacted_debug')
    model('lazy-loss-in-full-table','*lane = lane.saturating_add(1); // CP04_CONTROL_SEPARATE_STORAGE','if _gate.insert_noexist(GateKey::Diagnostic) { let value=_gate.entries.get_mut(&GateKey::Diagnostic).unwrap(); *value=value.saturating_add(1); } // wrong lazy storage','full_table_signal_survives_repeated_failure','historical_full_identity_and_who_maps',target='full_map_loss_contract')
    # Lazy loss also reads the attempted gate entry, absent-as-zero. Both edits
    # are one semantic mutation; actual bounded insert runs into full storage.
    m[-1]['extra']={'old':'scopebase_capture::loss::fold_capped_signals(&self.slots, 255).unwrap()','new':'_gate.entries.get(&GateKey::Diagnostic).copied().unwrap_or(0)'}
    return m

def run(args,source,root,data,files):
    output=args.output_dir;output.mkdir(parents=True,mode=0o700)
    wrapper=args.build_wrapper;mode='wrapped'if wrapper else'direct'
    report={'schema_version':1,'status':'INVALID_CONTROL','command_mode':mode,'build_wrapper':None if wrapper is None else{'path':str(wrapper),'sha256':digest(wrapper)},'coordinator_lease':'helper neither acquires nor verifies an outer lease','source_root':str(source),'input_sha256':files,'input_index_sha256':hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest(),'corpus_sha256':hashlib.sha256(data).hexdigest(),'feature_set':args.feature_set,'rows':[],'commands':[],'compiler_identity':{},'fixture_input_controls':[]}
    def save():(output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    save()
    try:
        report['fixture_input_controls']=malformed_controls(root,data)
        subject=output/'subject';subject.mkdir()
        for name in files:
            dest=subject/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/name,dest)
        report['copied_sha256']={name:digest(subject/name)for name in files}
        # Make a standalone disposable package, never an ancestor workspace.
        manifest=subject/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n[[test]]\nname = "cp04_vectors"\npath = "tests/cp04_vectors.rs"\n[[test]]\nname = "cp04_debug_bound"\npath = "tests/cp04_debug_bound.rs"\n')
        (subject/'tests/cp04_vectors.rs').write_text(generated(root))
        (subject/'tests/cp04_debug_bound.rs').write_text('use scopebase_capture::provenance::ObservedIdentity;\nstruct NoDebug;\n#[test] fn no_debug_bound(){let _=format!("{:?}",ObservedIdentity::Known(NoDebug));}\n')
        for name in ['tmp','home','cargo-home']:(output/name).mkdir()
        inherited=Path(os.environ['CARGO_HOME']);shutil.copyfile(inherited/'config.toml',output/'cargo-home/config.toml')
        report['offline_inputs']={'source_cargo_home':str(inherited),'source_config_sha256':digest(inherited/'config.toml'),'config':str(output/'cargo-home/config.toml'),'config_sha256':digest(output/'cargo-home/config.toml')}
        env={'PATH':str(args.rustc.parent)+':/usr/bin:/bin','HOME':str(output/'home'),'TMPDIR':str(output/'tmp'),'CARGO_HOME':str(output/'cargo-home'),'CARGO_TARGET_DIR':str(output/'target'),'CARGO_NET_OFFLINE':'true','RUSTC':str(args.rustc),'RUSTDOC':str(args.rustc.with_name('rustdoc')),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
        report['environment']=env;report['inherited_wrapper_ignored']=os.environ.get('SCOPEBASE_BUILD_WRAPPER')
        for name,path in [('cargo',args.cargo),('rustc',args.rustc),('rustdoc',args.rustc.with_name('rustdoc'))]:
            row=execute([path,'--version','--verbose'],subject,env,output/'logs'/(name+'-identity'));row['path']=str(path);row['sha256']=digest(path);report['compiler_identity'][name]=row
            if not clean(row)or row['exit_code']!=0:raise RuntimeError('compiler identity failed')
        def command(arguments,stem):
            argv=([wrapper,'--']if wrapper else[])+[args.cargo,*arguments,'--manifest-path',subject/'Cargo.toml'];row=execute(argv,subject,env,output/'logs'/stem,mode);report['commands'].append(row);save()
            if not clean(row):raise RuntimeError('unretired/interrupted/timed-out command')
            return row
        lock=command(['generate-lockfile','--offline'],'lock')
        if lock['exit_code']!=0:raise RuntimeError('offline lock failed')
        report['lock_sha256']=digest(subject/'Cargo.lock')
        flags={'no-default':['--no-default-features'],'default':[],'json':['--no-default-features','--features','json']}[args.feature_set]
        md=command(['metadata','--locked','--offline','--format-version','1',*flags],'metadata')
        if md['exit_code']!=0:raise RuntimeError('metadata failed')
        metadata=json.loads(Path(md['stdout']).read_text());selected=[v for v in metadata['packages']if v['name']=='scopebase-capture']
        if len(selected)!=1 or Path(selected[0]['manifest_path']).resolve()!=manifest.resolve()or selected[0]['version']!='0.1.0':raise RuntimeError('wrong metadata subject')
        selected_features=next(v['features']for v in metadata['resolve']['nodes']if v['id']==selected[0]['id']);wanted={'no-default':set(),'default':{'default'},'json':{'json'}}[args.feature_set]
        if set(selected_features)!=wanted:raise RuntimeError('wrong subject features')
        report['subject']={'manifest':str(manifest),'manifest_sha256':digest(manifest),'version':'0.1.0','features':selected_features}
        target=subject/'tests/cp04_vectors.rs';target.write_text(generated(root));report['generated_target_sha256']=digest(target);report['case_index']=[{'test':'vector_'+str(i).zfill(3),'id':v['id']}for i,v in enumerate(root['cases'])]
        def build(target,stem):
            row=command(['test','--locked','--offline','--test',target,'--no-run','--message-format=json',*flags],stem);binary=None
            if row['exit_code']==0:
                for line in Path(row['stdout']).read_text().splitlines():
                    item=json.loads(line)
                    if item.get('reason')=='compiler-artifact'and item.get('target',{}).get('name')==target and item.get('executable'):binary=item['executable']
            return row,binary
        def tests(binary,names,stem,negative):
            rows=[]
            for name in names:
                row=execute([binary,'--exact',name,'--nocapture'],subject,env,output/'logs'/(stem+'-'+name));out=Path(row['stdout']).read_text();err=Path(row['stderr']).read_text()
                reached='running 1 test'in out and f'test {name} ... FAILED'in out and 'assertion `left == right` failed'in err
                if not clean(row):
                    report['execution_incomplete']=row;save();raise RuntimeError('test process custody incomplete')
                row['semantic_assertion_reached']=reached;row['valid']=clean(row)and(row['exit_code']==101 and reached if negative else row['exit_code']==0 and '1 passed; 0 failed'in out);rows.append(row)
            return rows
        report['baseline']={}
        for name in ['insertion_provenance','full_map_loss_contract','cp04_vectors']:
            b,binary=build(name,'baseline-'+name);entry={'build':b};report['baseline'][name]=entry
            if binary is None:raise RuntimeError('baseline did not compile')
            row=execute([binary],subject,env,output/'logs'/('baseline-tests-'+name));entry['tests']=row
            if not clean(row)or row['exit_code']!=0:raise RuntimeError('baseline failed')
        for mutation in mutations():
            row={k:v for k,v in mutation.items()if k not in ('old','new','extra')};row['status']='INVALID_CONTROL';report['rows'].append(row);path=subject/mutation['file'];original=path.read_text();changed=original
            pairs=[(mutation['old'],mutation['new'])]
            if 'extra'in mutation:pairs.append((mutation['extra']['old'],mutation['extra']['new']))
            for old,new in pairs:
                if changed.count(old)!=1:raise RuntimeError('mutation anchor mismatch '+mutation['id']+': '+str(changed.count(old)))
                changed=changed.replace(old,new,1)
            diff=output/'diffs'/(mutation['id']+'.patch');diff.parent.mkdir(exist_ok=True);diff.write_text(''.join(difflib.unified_diff(original.splitlines(True),changed.splitlines(True),fromfile=mutation['file'],tofile=mutation['file'])))
            row.update(diff=str(diff),before_sha256=digest(path));path.write_text(changed);row['mutant_sha256']=digest(path)
            try:
                b,binary=build(mutation['target'],mutation['id']+'-build');row['build']=b
                if binary:row['mutant_tests']=tests(binary,mutation['tests'],mutation['id']+'-mutant',True)
            finally:path.write_text(original)
            b,binary=build(mutation['target'],mutation['id']+'-restored-build');row['restored_build']=b
            if binary:row['restored_tests']=tests(binary,mutation['tests'],mutation['id']+'-restored',False)
            row['restored_sha256']=digest(path)
            if row.get('mutant_tests')and all(v['valid']for v in row['mutant_tests'])and row.get('restored_tests')and all(v['valid']for v in row['restored_tests'])and row['restored_sha256']==row['before_sha256']:row['status']='KILLED_SEMANTIC'
            save()
        # Unwanted I:Debug bound is a compiler refusal control, distinct from
        # the safe output-redaction semantic mutation above.
        path=subject/'src/provenance.rs';original=path.read_text();old='impl<I> fmt::Debug for ObservedIdentity<I>'
        if original.count(old)!=1:raise RuntimeError('Debug-bound anchor mismatch')
        path.write_text(original.replace(old,'impl<I: fmt::Debug> fmt::Debug for ObservedIdentity<I>',1))
        # A standalone non-Debug observation makes E0277 meaningful.
        control_target=subject/'tests/cp04_debug_bound.rs';control_target.write_text('use scopebase_capture::provenance::ObservedIdentity;\nstruct NoDebug;\n#[test] fn no_debug_bound(){let _=format!("{:?}",ObservedIdentity::Known(NoDebug));}\n')
        try:
            row=command(['test','--locked','--offline','--test','cp04_debug_bound','--no-run','--message-format=json',*flags],'debug-bound-refusal');codes=[]
            for line in Path(row['stdout']).read_text().splitlines():
                v=json.loads(line);msg=v.get('message',{});code=(msg.get('code')or{}).get('code')
                if code:codes.append(code)
            if row['exit_code']!=101 or 'E0277'not in codes:raise RuntimeError('Debug-bound compile refusal missing')
            report['debug_bound_control']={'scope':'compile refusal, not semantic kill','refusal':row,'codes':codes}
        finally:path.write_text(original)
        b,binary=build('cp04_debug_bound','debug-bound-restored-build')
        if binary is None:raise RuntimeError('Debug-bound restored compile failed')
        rr=tests(binary,['no_debug_bound'],'debug-bound-restored',False);report['debug_bound_control']['restored']=rr
        if not all(v['valid']for v in rr):raise RuntimeError('Debug-bound restored failed')
        report['source_unchanged']=all(digest(source/name)==sha for name,sha in files.items())
        report['status']='PASS'if report['source_unchanged']and all(v['status']=='KILLED_SEMANTIC'for v in report['rows'])else'INVALID_CONTROL'
    except (Exception,KeyboardInterrupt,SystemExit)as exc:
        report['failure']=type(exc).__name__+': '+str(exc)
    finally:save()
    print(json.dumps({'status':report['status'],'controls':len(report['rows']),'report':str(output/'report.json')}));return 0 if report['status']=='PASS'else 1

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='mode',required=True)
    for mode in ['sync-mirror','check-fixture','run']:
        child=sub.add_parser(mode);child.add_argument('--source-root',type=Path,required=True);child.add_argument('--root-mirror',type=Path,required=mode=='sync-mirror')
        if mode=='run':
            child.add_argument('--cargo',type=Path,required=True);child.add_argument('--rustc',type=Path,required=True);child.add_argument('--feature-set',choices=['no-default','default','json'],required=True);child.add_argument('--output-dir',type=Path,required=True);child.add_argument('--build-wrapper',type=Path)
    args=parser.parse_args(argv);raw=args.source_root;source=raw.resolve()
    if not raw.is_absolute()or not no_symlinks(raw)or not source.is_dir()or 'donor-snapshots'in source.parts:parser.error('absolute non-donor source with no symlinks required')
    if any(p.is_symlink()for p in source.rglob('*')):parser.error('source symlinks unsupported')
    if args.root_mirror is not None and(not args.root_mirror.is_absolute()or not no_symlinks(args.root_mirror)or 'donor-snapshots'in args.root_mirror.parts):parser.error('absolute non-donor mirror with no symlinks required')
    try:
        root,data=fixture(source,None if args.mode=='sync-mirror'else args.root_mirror)
        if args.mode=='sync-mirror':
            if args.root_mirror==source/'fixtures/insertion-v1.json':parser.error('mirror must differ from authoritative corpus')
            args.root_mirror.parent.mkdir(parents=True,exist_ok=True);args.root_mirror.write_bytes(data)
        if args.mode!='run':print(json.dumps({'status':'VALID_FIXTURE','mode':args.mode,'corpus_sha256':hashlib.sha256(data).hexdigest(),'execution_evidence':False}));return 0
        output=args.output_dir
        if not output.is_absolute()or output.exists()or not no_symlinks(output)or output.resolve().is_relative_to(source)or source.is_relative_to(output.resolve()):parser.error('fresh absolute output outside source with no symlinks required')
        for compiler in [args.cargo,args.rustc,args.rustc.with_name('rustdoc')]:
            if not absolute_file(compiler,True):parser.error('absolute existing executable compiler files required')
        if args.build_wrapper is not None and not absolute_file(args.build_wrapper,True):parser.error('invalid explicit build wrapper')
        cargo_home=os.environ.get('CARGO_HOME')
        if not cargo_home or not Path(cargo_home).is_absolute()or not absolute_file(Path(cargo_home)/'config.toml'):parser.error('explicit existing offline CARGO_HOME/config.toml required')
        files={str(p.relative_to(source)):digest(p)for p in source.rglob('*')if p.is_file()and not set(p.relative_to(source).parts)&{'.git','target','__pycache__'}}
        for name in ['Cargo.toml','src/provenance.rs','tests/insertion_provenance.rs','tests/full_map_loss_contract.rs','tests/support/cp04_model.rs','fixtures/insertion-v1.json']:
            if name not in files:parser.error('actual CP04 package required')
        return run(args,source,root,data,files)
    except (OSError,InvalidCorpus)as exc:parser.error(str(exc))
if __name__=='__main__':sys.exit(main())
