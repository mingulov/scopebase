#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run CP05 semantic/compiler controls and two actual API clients (Python 3.11+).

Direct pinned Cargo/rustc is the standalone default. Coordination is enabled
only by --build-wrapper; there is no repository or ambient wrapper discovery.
Every compiler, Cargo and compiled-binary child uses that route. An explicit
offline CARGO_HOME/config.toml supplies the caller's already staged inputs.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode=True
_process_spec=importlib.util.spec_from_file_location('cp05_bounded_process',Path(__file__).with_name('cp05_bounded_process.py'))
process=importlib.util.module_from_spec(_process_spec)
_process_spec.loader.exec_module(process)

def digest(path):
    return process.sha(path)


def no_symlinks(path):
    return not any(p.is_symlink() for p in (path, *path.parents))


def absolute_file(path, executable=False):
    return (path.is_absolute() and ".." not in path.parts and no_symlinks(path)
            and path.is_file() and (not executable or os.access(path, os.X_OK)))


def held_leases():
    """Describe inherited lock descriptors without acquiring a second lease."""
    result = []
    if Path('/proc/self/fd').is_dir():
        for name in os.listdir('/proc/self/fd'):
            try:
                target = os.readlink('/proc/self/fd/' + name)
                if target.endswith('.lock'):
                    st = os.fstat(int(name))
                    result.append(dict(fd=int(name), path=target, device=st.st_dev, inode=st.st_ino))
            except OSError:
                pass
    return result


# Executed as the wrapper's direct child, while its inherited lease is live.
# Recording descriptor identity does not infer coordination in direct mode.
LEASE_CHILD = '''import json,os,sys
from pathlib import Path
rows=[]
for name in os.listdir('/proc/self/fd'):
 try:
  target=os.readlink('/proc/self/fd/'+name)
  if target.endswith('.lock'):
   s=os.fstat(int(name));rows.append(dict(fd=int(name),path=target,device=s.st_dev,inode=s.st_ino,pid=os.getpid()))
 except OSError:pass
Path(sys.argv[1]).write_text(json.dumps(rows,sort_keys=True)+'\\n')
os.execvpe(sys.argv[2],sys.argv[2:],os.environ)
'''


def execute(argv, cwd, env, stem, wrapper, *, record=None, checkpoint=None, timeout=2400):
    """Reserve before launch, attach collector facts before postprocessing.

    The exact accepted bounded collector retains all post-spawn collection,
    wait/group/close/stat/hash errors. This adapter adds lease metadata without
    erasing its primary error, process identity or independent cleanup outcome.
    """
    raw = [str(v) for v in argv]
    lease_file = stem.with_suffix('.lease.json')
    command = ([str(wrapper), '--timeout', '1800', '--', sys.executable, '-c',
                LEASE_CHILD, str(lease_file), *raw] if wrapper else raw)
    row={} if record is None else record
    row.update(command=command,product_command=raw,cwd=str(cwd),process_group=None,
               start_unix=time.time(),exit_code=None,reason_code=None,
               cleanup='not_started',logs={},errors=[],execution_status='NOT_LAUNCHED',
               command_mode='wrapped' if wrapper else 'direct',
               stdout=str(stem.with_suffix('.stdout')),stderr=str(stem.with_suffix('.stderr')))
    def error(stage,exception):
        row['errors'].append(dict(stage=stage,exception=type(exception).__name__,message=str(exception)[:512],errno=getattr(exception,'errno',None)))
        if row['reason_code'] is None:row['reason_code']='INTERNAL_ERROR'
    def persist(stage):
        if checkpoint is not None:
            try:checkpoint()
            except BaseException as exc:error(stage,exc);return False
        return True
    if not persist('checkpoint-before-launch'):
        row['reason_code']='SETUP_FAILURE';return row
    try:
        result=process.run(command,cwd,env,stem,timeout=timeout)
    except BaseException as exc:
        row['reason_code']='SETUP_FAILURE';error('setup',exc)
    else:
        # No lease parsing, hashing or log inspection may precede attachment.
        row.update(result);row['execution_status']='EXECUTED'
        persist('checkpoint-after-collection')
        try:
            if lease_file.exists():
                with lease_file.open('rb') as stream:data=stream.read(16385)
                if len(data)>16384:raise ValueError('lease record exceeds 16384 bytes')
                leases=json.loads(data)
                if not isinstance(leases,list):raise ValueError('lease record must be an array')
                row['live_lease_identity']=leases
        except BaseException as exc:error('lease-record',exc)
        try:
            if wrapper and row['exit_code']==75 and 'command not launched' in Path(row['stderr']).read_text(errors='replace'):
                row['execution_status']='NOT_RUN_LOCK_REFUSAL'
        except BaseException as exc:error('lock-refusal-record',exc)
    row.update(end_unix=time.time(),retired=row['cleanup']=='complete',
               timeout=row['reason_code']=='TIMEOUT',interrupted=row['reason_code']=='INTERRUPTED')
    for name in ['stdout','stderr']:row[name+'_sha256']=row['logs'].get(name,{}).get('sha256')
    persist('checkpoint-after-postprocess')
    return row


def process_complete(row):
    return row['reason_code'] is None and row['cleanup']=='complete'


RELATION = 'self.epoch == other.epoch && self.generation == other.generation && self.raw == other.raw'


def mutations():
    """Fixed selectors/expected assertion text are chosen before mutant runs."""
    rows = []
    def add(name, file, test, assertion, old, new, *extra):
        rows.append(dict(id=name, file=file, test=test, assertion=assertion,
                         changes=[(old,new),*extra], scope='production' if file=='src/generation.rs' else 'test-only adapter'))
    def p(name,test,assertion,old,new):
        add(name,'src/generation.rs',test,assertion,old,new)
    def a(name,test,assertion,old,new,*extra):
        add(name,'tests/support/generation_models.rs',test,assertion,old,new,*extra)
    p('P01-erase-epoch','full_key_match_requires_every_component','CP05:full-key matches capture','self.epoch == other.epoch','true')
    p('P02-erase-raw','full_key_match_requires_every_component','CP05:full-key matches device','self.raw == other.raw','true')
    p('P03-erase-generation','late_completion_does_not_match_successor','CP05:P03 successor stays live','self.generation == other.generation','true')
    p('P04-wrap-generation','generation_max_refuses','CP05:P04 overflow refusal',r'let generation = self\s*\.generation\s*\.checked_add\(1\)\s*\.ok_or\(ContractError::ArithmeticOverflow\)\?;', 'let generation = self.generation.wrapping_add(1);')
    rows[-1]['regex'] = True
    p('P05-require-always-ok','full_key_match_requires_every_component','CP05:require mismatch capture','if submitted.matches(current) {','if true {')
    p('P06-clone-before-overflow','generation_max_refuses','CP05:P06 overflow clone count','let generation = self','let _ = self.raw.clone();\n        let generation = self')
    p('P07-raw-eq-before-metadata','payload_panics_do_not_change_wrapper_fields','CP05:P07/P08 exact raw equality calls',RELATION,'self.raw == other.raw && self.epoch == other.epoch && self.generation == other.generation')
    p('P08-repeat-raw-eq','payload_panics_do_not_change_wrapper_fields','CP05:P07/P08 exact raw equality calls','self.raw == other.raw','{ let first = self.raw == other.raw; let second = self.raw == other.raw; first && second }')
    p('P09-debug-fixed-secret','payload_traits_and_debug_preserve_boundaries','CP05:P09 raw Debug redaction','"<redacted>"','"CP05_RAW_SECRET_7ea419d2"')
    p('B01-local-policy-in-constructor','generation_zero_and_exact_max_are_valid','CP05:generic zero remains valid',
      'Self {\n            epoch,\n            raw,\n            generation,\n        }',
      'Self { epoch, raw, generation: generation.max(1) }')
    return_marker='// CP05_RETURN_BIND: retain the submission binding across reuse.'
    a('A01-return-time-binding','k_destroy_return_after_realloc_retires_nothing','CP05:stale completion refuses successor',return_marker,'let binding = self.current(raw).cloned();')
    a('A02-raw-only-completion','k_destroy_return_after_realloc_retires_nothing','CP05:stale completion refuses successor','require_generation(&bound, key).is_err()','bound.raw() != key.raw()')
    a('A03-unbound-promotion','k_destroy_entry_unmapped_then_live_refuses','CP05:unbound destroy remains unknown',return_marker,'let binding = binding.or_else(|| self.current(raw).cloned());')
    a('A04-stored-index-binding','compaction_does_not_rebind_pending_identity','CP05:stable binding survives compaction',
      'let binding = self.current(raw).cloned(); // CP05_DESTROY_BIND',
      'let binding = self.records.iter().position(|r|!r.retired && *r.key.raw()==raw).map(|pos|ObjectKey::new(epoch(),raw,pos as u64));',
      (return_marker,'let binding = binding.and_then(|index|self.records.get(index.generation() as usize).map(|r|r.key.clone()));'))
    a('A05-double-retirement','k_overlapping_destroy_second_return_goes_stale','CP05:one proved retirement','self.stale += 1; // CP05_STALE','self.stale += 1; self.proved += 1; // wrong double retirement')
    a('A06-pending-capacity-bypass','k_pending_table_bound_refuses','CP05:pending capacity refusal',r'if self.pending.contains_key\(&token\) \|\| self.pending.len\(\) >= self.cap \{\s*return false;\s*\} // CP05_ALLOC_CAP','if self.pending.contains_key(&token) { return false; }')
    rows[-1]['regex'] = True
    live_cap=r'if self.live_len\(\) >= self.cap \{\s*return false;\s*\} // CP05_LIVE_CAP'
    a('A07-live-capacity-bypass','k_d4_live_cap_refuses_new_generations','CP05:third live capacity refusal',live_cap,'// Wrong: no live admission bound.')
    rows[-1]['regex']=True
    a('A08-live-eviction','k_d4_live_cap_refuses_new_generations','CP05:third live capacity refusal',live_cap,'if self.live_len() >= self.cap && !self.records.is_empty() { self.records.remove(0); }')
    rows[-1]['regex']=True
    a('A09-wrong-fifo','k_d4_retired_history_is_fifo_bounded','CP05:FIFO retained ids','self.records.iter().position(|r| r.retired).unwrap(); // CP05_FIFO','self.records.iter().rposition(|r| r.retired).unwrap(); // wrong FIFO')
    a('A10-old-id-reuse','k_alloc_after_proved_retire_assigns_fresh_id','CP05:fresh stable ids','let id = self.next_id;','let id = 1;')
    a('A11-forced-as-proved','k_alloc_for_live_base_forces_retire_as_ambiguous','CP05:forced boundary ambiguous','old.ambiguous = true; // CP05_FORCED','old.ambiguous = false; // wrong proved boundary')
    a('A12-eager-allocation','k_alloc_pair_assigns_generation_with_provenance','CP05:allocation entry emits no key','// CP05_ALLOC_ENTRY: generation assignment waits for the successful pair.','self.allocate(0, true);')
    a('A13-return-provenance','k_alloc_pair_assigns_generation_with_provenance','CP05:entry provenance retained','provenance.driver = driver.into(); // CP05_PROVENANCE','provenance.driver = driver.into(); provenance.origin = "return-owner".into();')
    config_bind=r'let Some\(bound\) = binding else \{\s*return false;\s*\}; // CP05_CONFIG_UNBOUND'
    a('A14-config-return-time-binding','k_config_return_after_realloc_unlinks','CP05:stale config unlinked',config_bind,'let Some(bound) = self.current(raw).cloned() else { return false; };')
    rows[-1]['regex']=True
    a('A15-config-unbound-promotion','k_config_entry_unmapped_then_live_unlinks','CP05:unbound config unlinked',config_bind,'let Some(bound) = binding.or_else(||self.current(raw).cloned()) else { return false; };')
    rows[-1]['regex']=True
    a('A16-first-seen-as-proved','k_config_after_retire_admits_fresh_never_merges','CP05:first-seen uncertainty at admission','if !creation_observed {','if false {')
    a('A17-per-config-uncertainty','k_config_after_retire_admits_fresh_never_merges','CP05:first-seen uncertainty counted once','record.configs += 1; // CP05_CONFIG_EFFECT','record.configs += 1; if !record.creation_observed { self.unknown_creation += 1; }')
    a('A18-erased-history-qualification','m_test_retired_history_bounded','CP05:history qualification sticky','self.partial = true; // CP05_MAPPING_EVICTION','self.partial = false; // wrong erased qualification')
    continuity=r'(pub fn continuity\(&self, key: &ObjectKey<u64>\) -> Outcome \{[\s\S]*?else \{\s*)Outcome::UnknownContinuity'
    a('A19-eviction-as-certainty','m_test_retired_history_bounded','CP05:mapping eviction uncertainty',continuity,r'\g<1>Outcome::Matched')
    rows[-1]['regex']=True
    a('A20-unknown-default-key','unknown_ids_are_nonjoinable','CP05:second unknown observation admitted','// CP05_UNKNOWN: unknown observations never mint a shared key.','let identity = Some(identity.unwrap_or_else(||ObjectKey::new(epoch(),0,0)));')
    a('A21-known-duplicates-allowed','unknown_ids_are_nonjoinable','CP05:known duplicate refuses','if self.known.iter().any(|k| k.matches(&key)) {','if false && self.known.iter().any(|k| k.matches(&key)) {')
    a('A22-merge-closed-mappings','m_test_reused_generation_two_samples','CP05:closed mapping generations retained','self.durations.push(end - rec.start); // CP05_MAPPING_SAMPLES','self.durations.clear(); self.durations.push(end - rec.start);')
    a('A23-token-only-namespace','m_test_pairing_key_namespaces','CP05:namespace identity differs',r'self.device == other.device\s*&& self.namespace == other.namespace\s*&& self.token == other.token','self.token == other.token')
    rows[-1]['regex']=True
    a('A24-local-zero-admitted','m_test_generation_positive','CP05:local positive-only lineage','generation >= 1','true')
    a('A25-duplicate-token-overwrite','literal_limits_duplicates_domains_and_overlaps','CP05:duplicate token flag',r'if self.pending.contains_key\(&token\) \{\s*return Transition \{\s*duplicate: true,\s*\.\.Transition::default\(\)\s*\};\s*\} // CP05_DUPLICATE','// Wrong: allow overwriting the first binding.')
    rows[-1]['regex']=True
    a('A26-false-report-after-insertion','k_d4_live_cap_refuses_new_generations','CP05:refused third admission preserves live count',live_cap,
      'let report_refusal = self.live_len() >= self.cap;',
      (r'(config_revision: 0,\s*configs: 0,\s*\}\);\s*)true',r'\g<1>!report_refusal'))
    rows[-1]['regex']=True
    a('A27-forced-old-id-reuse','k_alloc_for_live_base_forces_retire_as_ambiguous','CP05:forced reuse assigns distinct keys','let id = self.next_id;','let id = if self.forced > 0 { self.next_id - 1 } else { self.next_id };')
    a('A28-compaction-evicts-live','k_d4_retired_history_is_fifo_bounded','CP05:retired eviction preserves live identity','self.records.iter().position(|r| r.retired).unwrap(); // CP05_FIFO','self.records.iter().position(|_| true).unwrap(); // wrong live victim')
    return rows


def change(text, old, new, regex=False):
    if regex:
        result, count = re.subn(old,new,text)
    else:
        count = text.count(old)
        result = text.replace(old,new)
    if count != 1:
        raise RuntimeError('mutation anchor must occur once: ' + repr(old) + ': ' + str(count))
    return result


def run(args, source, files):
    output = args.output_dir
    output.mkdir(parents=True,mode=0o700)
    report = dict(schema_version=1,status='INCOMPLETE',source_root=str(source),input_sha256=files,
                  input_index_sha256=hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest(),
                  feature_set=args.feature_set,command_mode='wrapped' if args.build_wrapper else 'direct',
                  build_wrapper=None if args.build_wrapper is None else dict(path=str(args.build_wrapper),sha256=digest(args.build_wrapper)),
                  inherited_leases=held_leases(),commands=[],rows=[],clients=[],compiler_controls=[])
    def save():
        (output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    save()
    try:
        subject=output/'subject';subject.mkdir()
        for name in files:
            dest=subject/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/name,dest)
        report['copied_sha256']={name:digest(subject/name) for name in files}
        manifest=subject/'Cargo.toml'
        addition='\n[workspace]\n'
        for name in ['generation_no_debug','generation_rc_send','generation_send_ok']:
            addition+='[[example]]\nname = "cp05_'+name+'"\npath = "tests/ui/'+name+'.rs"\n'
        addition+='[[example]]\nname = "cp05_generation_private_fields"\npath = "tests/cp05_private_fields.rs"\n'
        private_fixture=subject/'tests/cp05_private_fields.rs'
        private_fixture.write_text('use scopebase_capture::{domain::{CaptureId,Epoch,ProducerId},generation::ObjectKey};\nfn main() {\nlet epoch=Epoch::new(CaptureId::new([1;16]).unwrap(),ProducerId::new([2;16]).unwrap(),0);\nlet _key = ObjectKey { epoch, raw: 7u64, generation: 0 }; // CP05_UI_PRIVATE\n}\n')
        original_manifest=manifest.read_text();manifest.write_text(original_manifest+addition)
        report['standalone_manifest_adaptation']=dict(original_sha256=files['Cargo.toml'],added=addition,adapted_sha256=digest(manifest))
        for name in ['tmp','home','cargo-home']:(output/name).mkdir()
        inherited=Path(os.environ['CARGO_HOME']);shutil.copyfile(inherited/'config.toml',output/'cargo-home/config.toml')
        report['offline_inputs']=dict(source_cargo_home=str(inherited),source_config_sha256=digest(inherited/'config.toml'),copied_config_sha256=digest(output/'cargo-home/config.toml'))
        env=dict(PATH=str(args.rustc.parent)+':/usr/bin:/bin',HOME=str(output/'home'),TMPDIR=str(output/'tmp'),CARGO_HOME=str(output/'cargo-home'),CARGO_TARGET_DIR=str(output/'target'),CARGO_NET_OFFLINE='true',RUSTC=str(args.rustc),RUSTDOC=str(args.rustc.with_name('rustdoc')),LANG='C.UTF-8',LC_ALL='C.UTF-8')
        report['environment']=env
        def environment_for(root):
            return env if root==subject else dict(env,CARGO_TARGET_DIR=str(root/'target'))
        def command(argv,stem,cwd=subject,extra_env=None):
            selected_env=env if extra_env is None else extra_env
            row=dict(id=stem,command=list(map(str,argv)),cwd=str(cwd),process_group=None,
                     exit_code=None,reason_code=None,cleanup='not_started',logs={},errors=[])
            report['commands'].append(row);save()
            execute(argv,cwd,selected_env,output/'logs'/stem,args.build_wrapper,record=row,checkpoint=save)
            row['environment']=selected_env
            save()
            if not process_complete(row):raise RuntimeError('nonqualifying command/process outcome: '+json.dumps(row))
            return row
        def ok(row):
            if row['exit_code']!=0:raise RuntimeError('required command failed: '+str(row))
            return row
        process_checks=ok(command([sys.executable,subject/'tests/support/test_cp05_process.py','--output-dir',output/'process-checks'],'process-failure-checks'))
        process_report=output/'process-checks/report.json'
        process_results=json.loads(process_report.read_text())
        if process_results['status']!='PASS' or process_results['tests_run']!=12:raise RuntimeError('required process failure checks incomplete')
        report['process_failure_checks']=dict(command=process_checks,report=str(process_report),report_sha256=digest(process_report),tests=12,collector_sha256=digest(subject/'tests/support/cp05_bounded_process.py'),max_log_bytes_per_stream=process.MAX_LOG)
        report['compiler_identity']={}
        for name,path in [('cargo',args.cargo),('rustc',args.rustc),('rustdoc',args.rustc.with_name('rustdoc'))]:
            row=ok(command([path,'--version','--verbose'],name+'-identity'))
            report['compiler_identity'][name]=dict(path=str(path),sha256=digest(path),command=row)
        flags={'no-default':['--no-default-features'],'default':[],'json':['--no-default-features','--features','json']}[args.feature_set]
        def cargo(arguments,stem,root=subject,flags_at_end=True):
            return command([args.cargo,*arguments,'--manifest-path',root/'Cargo.toml',*(flags if flags_at_end else [])],stem,root,environment_for(root))
        ok(cargo(['generate-lockfile','--offline'],'subject-lock',flags_at_end=False))
        report['subject_lock_sha256']=digest(subject/'Cargo.lock')
        def metadata(root,stem,selected_flags):
            row=ok(command([args.cargo,'metadata','--locked','--offline','--format-version','1','--manifest-path',root/'Cargo.toml',*selected_flags],stem,root,environment_for(root)))
            md=json.loads(Path(row['stdout']).read_text());packages=[p for p in md['packages'] if p['name']=='scopebase-capture']
            if len(packages)!=1 or packages[0]['version']!='0.1.0':raise RuntimeError('resolved subject/version mismatch')
            p=packages[0];features=next(n['features'] for n in md['resolve']['nodes'] if n['id']==p['id'])
            wanted={'no-default':set(),'default':{'default'},'json':{'json'}}[args.feature_set]
            if set(features)!=wanted:raise RuntimeError('resolved subject features mismatch '+repr(features))
            if Path(md['target_directory']).resolve()!=Path(environment_for(root)['CARGO_TARGET_DIR']).resolve():raise RuntimeError('metadata target directory mismatch')
            return dict(manifest=p['manifest_path'],package_id=p['id'],version=p['version'],features=features,target_directory=md['target_directory'],metadata_sha256=digest(row['stdout']),command=row)
        report['subject']=metadata(subject,'subject-metadata',flags)
        if Path(report['subject']['manifest']).resolve()!=manifest.resolve():raise RuntimeError('wrong copied subject manifest')
        def build(stem):
            row=cargo(['test','--offline','--locked','--test','generation_histories','--no-run','--message-format=json'],stem)
            binary=None
            if row['exit_code']==0:
                for line in Path(row['stdout']).read_text().splitlines():
                    item=json.loads(line)
                    if item.get('reason')=='compiler-artifact' and item.get('target',{}).get('name')=='generation_histories' and item.get('executable'):binary=Path(item['executable'])
            if binary is None:raise RuntimeError('generation target setup/build failed: '+str(row))
            return row,binary
        def semantic(binary,test,stem,negative,assertion):
            row=command([binary,'--exact',test,'--nocapture'],stem)
            out=Path(row['stdout']).read_text();err=Path(row['stderr']).read_text()
            selected='running 1 test' in out and '0 filtered out' not in out
            if negative:
                valid=(row['exit_code']==101 and selected and f'test {test} ... FAILED' in out and assertion in err and 'panicked at' in err)
            else:
                valid=(row['exit_code']==0 and selected and '1 passed; 0 failed' in out)
            row.update(expected_assertion=assertion,semantic_assertion_reached=negative and valid,valid=valid)
            if not valid:raise RuntimeError('semantic control/twin invalid: '+str(row))
            return row
        build_row,binary=build('baseline-build')
        row=ok(command([binary,'--nocapture'],'baseline-tests'))
        text=Path(row['stdout']).read_text()
        if '28 passed; 0 failed' not in text or 'scripts=55987 actions=324726' not in text:raise RuntimeError('baseline required population incomplete')
        report['baseline']=dict(build=build_row,tests=row,binary_sha256=digest(binary),scripts=55987,actions=324726)
        # Expected controls, spans, trait categories and assertions are frozen
        # from supplied fixtures/source before invoking any altered subject.
        report['control_manifest']=[{k:v for k,v in m.items() if k!='changes'} for m in mutations()]
        report['compiler_manifest']=[]
        for file,marker,trait in [('generation_no_debug.rs','CP05_UI_DEBUG','Debug'),('generation_rc_send.rs','CP05_UI_SEND','Send'),('generation_send_ok.rs','CP05_UI_SEND','Send')]:
            path=subject/'tests/ui'/file;lines=[i for i,line in enumerate(path.read_text().splitlines(),1) if marker in line]
            if len(lines)!=1:raise RuntimeError('fixed UI marker missing')
            report['compiler_manifest'].append(dict(file='tests/ui/'+file,line=lines[0],trait=trait,error_code='E0277',sha256=digest(path)))
        report['compiler_manifest'].append(dict(file='tests/cp05_private_fields.rs',line=4,trait='private',error_code='E0451',sha256=digest(private_fixture)))
        save()
        for mutation in mutations():
            row={k:v for k,v in mutation.items() if k not in ('changes','regex')};row['status']='INVALID_CONTROL';report['rows'].append(row)
            path=subject/mutation['file'];original=path.read_text();changed=original
            for old,new in mutation['changes']:changed=change(changed,old,new,mutation.get('regex',False))
            diff=output/'diffs'/(mutation['id']+'.patch');diff.parent.mkdir(exist_ok=True)
            diff.write_text(''.join(difflib.unified_diff(original.splitlines(True),changed.splitlines(True),fromfile=mutation['file'],tofile=mutation['file'])))
            row.update(before_sha256=digest(path),diff=str(diff),diff_sha256=digest(diff))
            path.write_text(changed);row['mutant_sha256']=digest(path)
            try:
                row['build'],binary=build(mutation['id']+'-build')
                row['mutant']=semantic(binary,mutation['test'],mutation['id']+'-mutant',True,mutation['assertion'])
            finally:path.write_text(original)
            row['restored_build'],binary=build(mutation['id']+'-restored-build')
            row['restored']=semantic(binary,mutation['test'],mutation['id']+'-restored',False,mutation['assertion'])
            row['restored_sha256']=digest(path)
            if row['restored_sha256']!=row['before_sha256']:raise RuntimeError('restored bytes differ')
            row['status']='KILLED_SEMANTIC';save()
        def ui(fixture,stem,negative):
            spec=next(v for v in report['compiler_manifest'] if v['file'].endswith(fixture+'.rs') or (fixture=='generation_private_fields' and v['file']=='tests/cp05_private_fields.rs'))
            row=cargo(['check','--offline','--locked','--example','cp05_'+fixture,'--message-format=json'],stem)
            found=[]
            for line in Path(row['stdout']).read_text().splitlines():
                item=json.loads(line);msg=item.get('message',{});code=(msg.get('code') or {}).get('code')
                if code==spec['error_code'] and spec['trait'] in json.dumps(msg):
                    for span in msg.get('spans',[]):
                        if span.get('is_primary') and span['file_name'].replace('\\','/').endswith(spec['file']) and span['line_start']==spec['line']:
                            found.append(dict(code=code,trait=spec['trait'],file=span['file_name'],line=span['line_start']))
            valid=(row['exit_code']==101 and bool(found)) if negative else row['exit_code']==0
            row.update(expected=spec,matched_primary_diagnostics=found,valid=valid)
            if not valid:raise RuntimeError('fixed compiler site/category failed '+str(row))
            return row
        report['compiler_controls'].append(dict(id='no-debug-positive',result=ui('generation_no_debug','ui-no-debug-positive',False)))
        path=subject/'src/generation.rs';original=path.read_text();before=digest(path)
        path.write_text(change(original,'impl<K> fmt::Debug for ObjectKey<K>','impl<K: fmt::Debug> fmt::Debug for ObjectKey<K>'))
        unwanted=dict(id='unwanted-debug-bound',before_sha256=before,mutant_sha256=digest(path),scope='compiler refusal, not disclosure')
        try:unwanted['negative']=ui('generation_no_debug','ui-debug-bound-negative',True)
        finally:path.write_text(original)
        unwanted['restored']=ui('generation_no_debug','ui-debug-bound-restored',False);unwanted['restored_sha256']=digest(path)
        report['compiler_controls'].append(unwanted)
        report['compiler_controls'].append(dict(id='rc-send-refused',result=ui('generation_rc_send','ui-rc-send-negative',True),twin=ui('generation_send_ok','ui-u64-send-positive',False)))
        report['compiler_controls'].append(dict(id='private-fields-refused',result=ui('generation_private_fields','ui-private-fields-negative',True),twin='no-debug-positive uses public validating/move-only constructor'))
        # Clients depend on the actual supplied subject, not the adapted copy.
        # Separate manifests, locks, metadata and programs establish each route.
        for name,expected in [('transform_generations','CP05 transform client: stale=1 unbound=1 configured=1 retired=1 successor=2'),('mapping_generations','CP05 mapping client: unknown_events=2 known=2 durations=50,60,70 partial=true live_bytes=4096')]:
            client=output/'clients'/name;client.mkdir(parents=True)
            code=source/'examples'/(name+'.rs');shutil.copyfile(code,client/'main.rs')
            dep='scopebase-capture = { path = '+json.dumps(str(source))+', version = "=0.1.0", default-features = '+('true' if args.feature_set=='default' else 'false')+', features = '+('["json"]' if args.feature_set=='json' else '[]')+' }'
            (client/'Cargo.toml').write_text('[package]\nname = "cp05-'+name.replace('_','-')+'"\nversion = "0.0.0"\nedition = "2021"\n[workspace]\n[[bin]]\nname = "client"\npath = "main.rs"\n[dependencies]\n'+dep+'\n')
            entry=dict(id=name,source=str(code),source_sha256=digest(code),copied_sha256=digest(client/'main.rs'),manifest=str(client/'Cargo.toml'),manifest_sha256=digest(client/'Cargo.toml'),expected_stdout=expected)
            report['clients'].append(entry)
            entry['lock']=ok(cargo(['generate-lockfile','--offline'],name+'-lock',client,False));entry['lock_sha256']=digest(client/'Cargo.lock')
            entry['resolved_subject']=metadata(client,name+'-metadata',[])
            if Path(entry['resolved_subject']['manifest']).resolve()!=(source/'Cargo.toml').resolve():raise RuntimeError('client resolved a different subject')
            row=ok(cargo(['build','--offline','--locked','--message-format=json'],name+'-build',client,False));entry['build']=row
            binaries=[Path(v['executable']) for v in (json.loads(line) for line in Path(row['stdout']).read_text().splitlines()) if v.get('reason')=='compiler-artifact' and v.get('target',{}).get('name')=='client' and v.get('executable')]
            if len(binaries)!=1:raise RuntimeError('client binary artifact missing')
            if not binaries[0].resolve().is_relative_to((client/'target').resolve()):raise RuntimeError('client artifact outside its independent target')
            entry['binary_path']=str(binaries[0]);entry['binary_sha256']=digest(binaries[0]);entry['run']=ok(command([binaries[0]],name+'-run',client,environment_for(client)))
            if Path(entry['run']['stdout']).read_text().strip()!=expected:raise RuntimeError('client literal outcome mismatch')
            save()
        if len({c['binary_path'] for c in report['clients']})!=2:raise RuntimeError('client artifact paths overlap')
        for entry in report['clients']:
            if digest(entry['binary_path'])!=entry['binary_sha256']:raise RuntimeError('client artifact overwritten')
        report['independent_client_artifacts_retained']=True
        report['source_unchanged']=all(digest(source/name)==sha for name,sha in files.items())
        report['restored_subject_unchanged']=all(digest(subject/name)==sha for name,sha in files.items() if name!='Cargo.toml')
        if not report['source_unchanged'] or not report['restored_subject_unchanged']:raise RuntimeError('input/restored source changed')
        report['status']='PASS'
    except (Exception,KeyboardInterrupt,SystemExit) as exc:
        report['failure']=type(exc).__name__+': '+str(exc)
    finally:save()
    print(json.dumps(dict(status=report['status'],controls=len(report['rows']),clients=len(report['clients']),report=str(output/'report.json'))))
    return 0 if report['status']=='PASS' else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='mode',required=True);p=sub.add_parser('run')
    p.add_argument('--source-root',type=Path,required=True);p.add_argument('--cargo',type=Path,required=True);p.add_argument('--rustc',type=Path,required=True)
    p.add_argument('--feature-set',choices=['no-default','default','json'],required=True);p.add_argument('--output-dir',type=Path,required=True);p.add_argument('--build-wrapper',type=Path)
    args=parser.parse_args();source=args.source_root
    if not source.is_absolute() or '..' in source.parts or not no_symlinks(source) or not source.is_dir() or 'donor-snapshots' in source.parts:parser.error('absolute non-donor source without symlinks required')
    if any(p.is_symlink() for p in source.rglob('*')):parser.error('source symlinks unsupported')
    output=args.output_dir
    if not output.is_absolute() or '..' in output.parts or output.exists() or not no_symlinks(output) or output.resolve().is_relative_to(source.resolve()) or source.resolve().is_relative_to(output.resolve()):parser.error('fresh absolute output outside source without symlinks required')
    for tool in [args.cargo,args.rustc,args.rustc.with_name('rustdoc')]:
        if not absolute_file(tool,True):parser.error('absolute existing executable tools required')
    if args.build_wrapper is not None and not absolute_file(args.build_wrapper,True):parser.error('invalid explicit build wrapper')
    cache=os.environ.get('CARGO_HOME')
    if not cache or not absolute_file(Path(cache)/'config.toml'):parser.error('explicit offline CARGO_HOME/config.toml required')
    files={str(p.relative_to(source)):digest(p) for p in source.rglob('*') if p.is_file() and not set(p.relative_to(source).parts)&{'.git','target','__pycache__'}}
    for name in ['Cargo.toml','src/generation.rs','tests/generation_histories.rs','tests/support/generation_models.rs','tests/support/generation_oracle.rs','examples/transform_generations.rs','examples/mapping_generations.rs']:
        if name not in files:parser.error('actual CP05 subject required: '+name)
    return run(args,source,files)


if __name__=='__main__':
    sys.exit(main())
