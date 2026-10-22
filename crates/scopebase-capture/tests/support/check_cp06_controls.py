#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run CP06 semantic/compiler controls and two actual API clients (Python 3.11+).

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
for role,pid in [('holder',os.getppid()),('inherited_child',os.getpid())]:
 try: names=os.listdir('/proc/'+str(pid)+'/fd')
 except OSError:names=[]
 for name in names:
  try:
   p='/proc/'+str(pid)+'/fd/'+name;target=os.readlink(p)
   if target.endswith('.lock'):
    st=os.stat(p);rows.append(dict(role=role,pid=pid,fd=int(name),path=target,device=st.st_dev,inode=st.st_ino,fdinfo=Path('/proc/'+str(pid)+'/fdinfo/'+name).read_text(),profile_environment={k:os.environ.get(k) for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG','CARGO_BUILD_JOBS','CARGO_INCREMENTAL']}))
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
    row.update(command=command,product_command=raw,cwd=str(cwd),environment=dict(env),profile_selection={k:env.get(k) for k in ("CARGO_PROFILE_DEV_DEBUG","CARGO_PROFILE_TEST_DEBUG","CARGO_BUILD_JOBS","CARGO_INCREMENTAL")},process_group=None,
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


def profile_environment(caller):
    """Choose the portable Cargo default or the explicitly bound paired zero.

    Refuse partial/nonzero/unbound overrides before creating output or launching.
    Every subject and independently resolved client receives this exact mapping.
    """
    pair = ('CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG')
    present = [k in caller for k in pair]
    if any(present) and (not all(present) or any(caller[k] != '0' for k in pair)):
        raise ValueError('profile requires both DEV_DEBUG=0 and TEST_DEBUG=0, or both absent')
    for k,v in caller.items():
        if k.startswith('CARGO_PROFILE_') and k not in pair:
            raise ValueError('unbound profile override: '+k)
        if (k in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTDOCFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_RUSTFLAGS','CARGO_BUILD_TARGET') and v):
            raise ValueError('unbound compiler override: '+k)
    for key,want in [('CARGO_BUILD_JOBS','1'),('CARGO_INCREMENTAL','0')]:
        if caller.get(key,want) != want:raise ValueError('unbound '+key)
    return {'CARGO_BUILD_JOBS':'1','CARGO_INCREMENTAL':'0',**({k:caller[k] for k in pair} if all(present) else {})}


def verify_profile_contract():
    positives=[{},dict(CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0')]
    for caller in positives:
        selected=profile_environment(caller)
        for variant in ('subject','client-a','client-b'):
            child=dict(PATH='/usr/bin:/bin',**selected)
            assert all(child.get(k)==caller.get(k) for k in ('CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'))
            assert child['CARGO_BUILD_JOBS']=='1' and child['CARGO_INCREMENTAL']=='0'
    refused=[dict(CARGO_PROFILE_DEV_DEBUG='0'),dict(CARGO_PROFILE_TEST_DEBUG='0'),dict(CARGO_PROFILE_DEV_DEBUG='1',CARGO_PROFILE_TEST_DEBUG='0'),dict(CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='2'),dict(CARGO_PROFILE_DEV_OPT_LEVEL='3'),dict(CARGO_BUILD_JOBS='2'),dict(CARGO_INCREMENTAL='1'),dict(RUSTFLAGS='-C debuginfo=2')]
    for caller in refused:
        try:profile_environment(caller)
        except ValueError:pass
        else:raise AssertionError('CP06:profile override not refused before launch')
    return dict(positive_variants=6,prelaunch_refusals=len(refused),both_absent='portable Cargo default',paired_zero='forwarded explicitly')


def mutations():
    rows=[]
    def add(id,file,target,test,assertion,old,new):
        rows.append(dict(id=id,file=file,target=target,test=test,assertion=assertion,old=old,new=new))
    def view(id,test,assertion,old,new):add(id,'src/view.rs','report_views',test,assertion,old,new)
    flags='(self.claims.binary_search_by_key(&id,|s|s.claim).is_ok_and(|i|self.claims[i].consumed_loss),overlay.partial_claims.binary_search(&id).is_ok())'
    view('V01-permanent-query-taint','partial_snapshot_does_not_poison_later_view','CP06:plain stays pristine',flags,'{let loss=self.claims.binary_search_by_key(&id,|s|s.claim).is_ok_and(|i|self.claims[i].consumed_loss);let partial=overlay.partial_claims.binary_search(&id).is_ok();thread_local!{static TAINT:std::cell::Cell<bool>=const{std::cell::Cell::new(false)}}let partial=if id==ClaimId::new(1){TAINT.with(|t|{let n=t.get()||partial;t.set(n);n})}else{partial};(loss,partial)}')
    view('V02-clear-consumed','consumed_loss_stays_in_epoch','CP06:consumed stays','self.claims[i].consumed_loss),overlay','self.claims[i].consumed_loss && !overlay.partial_claims.is_empty()),overlay')
    view('V03-broadcast-loss','independent_fact_claim_survives_relationship_loss','CP06:independent claim survives','self.claims.binary_search_by_key(&id,|s|s.claim).is_ok_and(|i|self.claims[i].consumed_loss)','self.claims.iter().any(|s|s.consumed_loss)')
    view('V05-atleast0-zero','loss_magnitudes_and_signal_units_remain_distinct','CP06:magnitude truth','(RetainedMagnitude::AtLeast(n.get()),true)','(RetainedMagnitude::AtLeast(n.get()),n.get()!=0)')
    view('V05-unknown-zero','loss_magnitudes_and_signal_units_remain_distinct','CP06:magnitude truth','LossMagnitude::Unknown=>(RetainedMagnitude::Unknown,true)','LossMagnitude::Unknown=>(RetainedMagnitude::Unknown,false)')
    add('V07-signal-as-events','src/view.rs','lib','view::tests::erased_record_retains_all_tags','CP06:literal retained tags/order/occurrences','self.record(fact.source(),fact.channel(),UnitTag::DiagnosticSignals','self.record(fact.source(),fact.channel(),UnitTag::Events')
    add('V07-erased-unit','src/view.rs','lib','view::tests::erased_record_retains_all_tags','CP06:literal retained tags/order/occurrences','channel,unit,observation,affected:owned','channel,unit:UnitTag::Events,observation,affected:owned')
    add('A01-early-commit','src/view.rs','lib','view::tests::reserve_failures_preserve_all_logical_state','CP06:reserve refuses before publication','a.reserve(&mut self.facts,1,"fact_append")?;','self.claims=claims.clone();a.reserve(&mut self.facts,1,"fact_append")?;')
    view('V04-silent-eviction','capacity_refusal_preserves_ledger','CP06:expected refusal','if self.facts.len().checked_add(1)','if self.facts.len()==self.limits.loss_facts && !self.facts.is_empty(){self.facts.remove(0);}if self.facts.len().checked_add(1)')
    add('A01-snapshot-early-reserve','src/view.rs','lib','view::tests::snapshot_semantic_refusals_precede_reserves','CP06:no snapshot reserve before final reasons','validate(selected,self.limits.claims)?;','validate(selected,self.limits.claims)?;let mut early=Vec::<ClaimAssessment>::new();a.reserve(&mut early,selected.len(),"output_rows")?;')
    add('A01-overlay-early-reserve','src/view.rs','lib','view::tests::overlay_constructor_reserve_order','CP06:no overlay reserve before validation','validate(ids,max)?;let mut partial_claims=Vec::new();a.reserve(&mut partial_claims,ids.len(),"overlay_owned_copy")?;','let mut partial_claims=Vec::new();a.reserve(&mut partial_claims,ids.len(),"overlay_owned_copy")?;validate(ids,max)?;')
    add('A01-overlay-wrong-error','src/view.rs','lib','view::tests::overlay_constructor_reserve_order','CP06:overlay reserve maps capacity','result.map_err(|_|ContractError::CapacityExceeded)','result.map_err(|_|ContractError::ArithmeticOverflow)')
    def feed(id,test,assertion,old,new):add(id,'src/feeds.rs','feed_integrity',test,assertion,old,new)
    feed('F01-missing-as-zero','zero_feed_is_not_missing','CP06:missing is not zero','received.resize(ids.len(),false)','received.resize(ids.len(),true)')
    feed('F02-duplicate-replaces','second_feed_refuses','CP06:first feed stands','if self.received[index]{return Err(ContractError::DuplicateFeed);}','if self.received[index]{return Ok(());}')
    feed('F03-undeclared-admitted','required_declarations_are_bounded','CP06:undeclared refuses','let index=self.required.binary_search(&fact.channel()).map_err(|_|ContractError::InvalidId)?;','let index=match self.required.binary_search(&fact.channel()){Ok(i)=>i,Err(_)=>return Ok(())};')
    feed('F04-ordinal-only','feed_error_order_and_atomicity','CP06:feed full epoch first','fact.source().epoch()!=&self.epoch','fact.source().epoch().ordinal()!=self.epoch.ordinal()')
    feed('F05-finish-seals','finish_is_observational','CP06:finish leaves valid feed open','if fact.source().epoch()!=&self.epoch','if self.finished.load(std::sync::atomic::Ordering::Relaxed){return Err(ContractError::InvalidSample);}if fact.source().epoch()!=&self.epoch')
    rows[-1]['extra']=[('pub struct FeedRegistry{epoch:Epoch','pub struct FeedRegistry{finished:std::sync::atomic::AtomicBool,epoch:Epoch'),('Ok(Self{epoch,required,received})','Ok(Self{finished:std::sync::atomic::AtomicBool::new(false),epoch,required,received})'),('pub fn finish(&self)->Result<(),ContractError>{','pub fn finish(&self)->Result<(),ContractError>{self.finished.store(true,std::sync::atomic::Ordering::Relaxed);')]
    add('A01-feed-early-reserve','src/feeds.rs','lib','feeds::tests::constructor_reserves_and_sorted_bit_association','CP06:no feed reserve before validation','if ids.len()>max{return Err(ContractError::CapacityExceeded);}','let mut early=Vec::<ChannelId>::new();a.reserve(&mut early,ids.len(),"feed_required_ids")?;if ids.len()>max{return Err(ContractError::CapacityExceeded);}')
    add('A01-feed-wrong-error','src/feeds.rs','lib','feeds::tests::constructor_reserves_and_sorted_bit_association','CP06:feed reserve maps capacity','result.map_err(|_|ContractError::CapacityExceeded)','result.map_err(|_|ContractError::ArithmeticOverflow)')
    for file,module in [('src/view.rs','view'),('src/feeds.rs','feeds')]:
        add('A01-'+module+'-normal-reserve-map',file,'lib',module+'::tests::ordinary_reserve_error_uses_the_same_capacity_mapping','CP06:normal reserve maps capacity','result.map_err(|_|ContractError::CapacityExceeded)','result.map_err(|_|ContractError::ArithmeticOverflow)')
    add('A01-feed-wrong-bit','src/feeds.rs','lib','feeds::tests::constructor_reserves_and_sorted_bit_association','CP06:sorted id-to-bit association','self.received[index]=true','self.received[0]=true')
    view('V06-output-selected-order','selected_overlay_and_output_bounds','CP06:selected order','Ok(out)','{ out.sort_by_key(|a| a.claim()); Ok(out) }')
    view('V08-ordinal-only-epoch','ledger_checks_full_epoch_before_duplicates','CP06:ledger full epoch first','if source.epoch()!=&self.epoch{','if source.epoch().ordinal()!=self.epoch.ordinal(){')
    view('V09-skip-reason-budget','snapshot_refuses_combined_reasons_as_whole','CP06:combined reasons refuse whole','if usize::from(loss)+usize::from(partial)>self.limits.reasons_per_claim{','if false{')
    add('W01-merge-misses-overlap','src/view.rs','lib','view::tests::forward_merge_keeps_sorted_survivors_and_overlaps','CP06:merge applies overlap damage','merged.consumed_loss|=damaging;','merged.consumed_loss|=false;')
    add('C03-token-only-routing','examples/transport_corrections.rs','example','transport_corrections','CP06:complete client key routes','if e.key.matches(target){','if e.key.raw().token==target.raw().token{')
    def correction(id,test,assertion,old,new):add(id,'src/correction.rs','corrections',test,assertion,old,new)
    correction('C01-stale-admitted','correction_is_exact_next_revision','CP06:stale refuses','if self.revision!=correction.from','if false')
    correction('C01-gap-admitted','correction_is_exact_next_revision','CP06:premature refuses','if self.revision!=correction.from','if self.revision.0>correction.from.0')
    correction('C02-ordinal-only','foreign_epoch_precedes_stale','CP06:correction full epoch first','self.epoch!=correction.epoch','self.epoch.ordinal()!=correction.epoch.ordinal()')
    correction('C05-foreign-forget','foreign_epoch_payload_drop_journal','CP06:foreign refusal drops replacement only','return Err((self,ContractError::DomainMismatch));','{ std::mem::forget(correction); return Err((self, ContractError::DomainMismatch)); }')
    correction('C06-wrapping-next-revision','revision_overflow_is_explicit','CP06:checked next revision','from.0.checked_add(1).ok_or(ContractError::ArithmeticOverflow)?','from.0.wrapping_add(1)')
    add('U02-wrong-Bytes-tag','src/quantity.rs','lib','quantity::cp06_tests::seven_private_unit_tags','CP06:Bytes tag','UnitTag::$name','if stringify!($name)=="Bytes"{UnitTag::Events}else{UnitTag::$name}')
    add('C04-partial-outcome','examples/transport_corrections.rs','example','transport_corrections','CP06:both original holders corrected','fn replacement()->Verdict{Verdict{outcome:"Tainted",by_seq:Some(1),op:0}}','fn replacement()->Verdict{Verdict{outcome:"Tainted",by_seq:Some(1),op:17}}')
    add('C04-drop-export','examples/transport_corrections.rs','example','transport_corrections','CP06:both original holders corrected','route(&mut export,Some(&target)).unwrap(); // CP06_EXPORT_UPDATE','// CP06_EXPORT_UPDATE omitted')
    add('C04-drop-tail','examples/transport_corrections.rs','example','transport_corrections','CP06:both original holders corrected','route(&mut report,Some(&target)).unwrap(); // CP06_REPORT_UPDATE','// CP06_REPORT_UPDATE omitted')
    return rows


def change(text,old,new):
    # Formatting may insert trailing commas; freeze a unique punctuation-aware
    # token range while ignoring only whitespace and comma formatting.
    pattern=r'[\s,]*'.join(re.escape(c) for c in re.sub(r'[\s,]+','',old))
    result,count=re.subn(pattern,lambda _:new,text)
    if count!=1:raise RuntimeError('mutation anchor count: '+str(count)+' '+old)
    return result


def run(args,source,files,profile):
    output=args.output_dir;output.mkdir(parents=True,mode=0o700)
    report=dict(schema_version=1,status='INCOMPLETE',input_sha256=files,source_root=str(source),feature_set=args.feature_set,profile_environment=profile,profile_contract=verify_profile_contract(),commands=[],controls=[],compiler_controls=[],clients=[],inherited_leases=held_leases())
    report['build_wrapper']=dict(path=str(args.build_wrapper),sha256=digest(args.build_wrapper)) if args.build_wrapper else None
    def save():(output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    save()
    try:
        subject=output/'subject';subject.mkdir()
        for name in files:
            dest=subject/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/name,dest)
        manifest=subject/'Cargo.toml';original_manifest=manifest.read_text();addition='\n[workspace]\n'
        ui_files=sorted((subject/'tests/ui').glob('cp06_*.rs'))
        for path in ui_files:addition+='[[example]]\nname = "'+path.stem+'"\npath = "tests/ui/'+path.name+'"\n'
        manifest.write_text(original_manifest+addition)
        report['manifest_adaptation']=dict(original_sha256=files['Cargo.toml'],added=addition,adapted_sha256=digest(manifest))
        for name in ['home','tmp','cargo-home']:(output/name).mkdir()
        config=Path(os.environ['CARGO_HOME'])/'config.toml';shutil.copyfile(config,output/'cargo-home/config.toml')
        report['offline_config']=dict(source=str(config),sha256=digest(config),copied_sha256=digest(output/'cargo-home/config.toml'))
        env=dict(PATH=str(args.rustc.parent)+':/usr/bin:/bin',HOME=str(output/'home'),TMPDIR=str(output/'tmp'),CARGO_HOME=str(output/'cargo-home'),CARGO_TARGET_DIR=str(output/'target'),CARGO_NET_OFFLINE='true',RUSTC=str(args.rustc),RUSTDOC=str(args.rustc.with_name('rustdoc')),LANG='C.UTF-8',LC_ALL='C.UTF-8',**profile)
        report['environment']=env
        flags={'no-default':['--no-default-features'],'default':[],'json':['--no-default-features','--features','json']}[args.feature_set]
        def command(argv,stem,root=subject,selected_env=None):
            selected_env=env if selected_env is None else selected_env
            # Portable helper bounds its own outputs. The admitted focused route
            # additionally checks the controller's six-GiB total before launch.
            used=sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
            if os.environ.get('SCOPEBASE_CP06_FOCUSED_OUTPUT_ROOT'):
                focused=Path(os.environ['SCOPEBASE_CP06_FOCUSED_OUTPUT_ROOT'])
                roots=[focused]
                if os.environ.get('SCOPEBASE_CP06_FOCUSED_WORKTREE_ROOT'):roots.append(Path(os.environ['SCOPEBASE_CP06_FOCUSED_WORKTREE_ROOT']))
                total=sum(p.stat().st_size for root in roots for p in root.rglob('*') if p.is_file())
                if total>=6*1024**3:raise RuntimeError('focused six-GiB total budget reached; preserve custody')
            else:total=None
            if used>=2*1024**3 or shutil.disk_usage(output).free<4*1024**3:raise RuntimeError('output budget/free-space floor reached; preserve custody')
            row=dict(id=stem,environment=dict(selected_env),focused_total_bytes=total,prelaunch_output_bytes=used,prelaunch_free_bytes=shutil.disk_usage(output).free)
            report['commands'].append(row);save()
            execute(argv,root,selected_env,output/'logs'/stem,args.build_wrapper,record=row,checkpoint=save)
            if not process_complete(row):raise RuntimeError('nonqualifying command custody: '+stem)
            save();return row
        def ok(row):
            if row['exit_code']!=0:raise RuntimeError('required command failed: '+row['id'])
            return row
        def cargo(arguments,stem,root=subject,features=True):
            e=env if root==subject else dict(env,CARGO_TARGET_DIR=str(root/'target'))
            return command([args.cargo,*arguments,'--manifest-path',root/'Cargo.toml',*(flags if features else [])],stem,root,e)
        report['profile_forwarding_probes']=[]
        for variant in ['both-absent','paired-zero']:
            probe_env={k:v for k,v in env.items() if k not in ('CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG')}
            if variant=='paired-zero':probe_env.update(CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0')
            for route in ['subject','client-a','client-b']:
                row=ok(command([sys.executable,'-c','import os,json;print(json.dumps({k:os.environ.get(k) for k in ["CARGO_PROFILE_DEV_DEBUG","CARGO_PROFILE_TEST_DEBUG","CARGO_BUILD_JOBS","CARGO_INCREMENTAL"]},sort_keys=True))'],'profile-'+variant+'-'+route,selected_env=probe_env))
                observed=json.loads(Path(row['stdout']).read_text())
                expected={k:probe_env.get(k) for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG','CARGO_BUILD_JOBS','CARGO_INCREMENTAL']}
                if observed!=expected:raise RuntimeError('child profile forwarding mismatch')
                report['profile_forwarding_probes'].append(dict(variant=variant,route=route,expected=expected,observed=observed,command=row,scope='Python environment forwarding only; no compiler-default qualification'))
        for name,path in [('cargo',args.cargo),('rustc',args.rustc),('rustdoc',args.rustc.with_name('rustdoc'))]:
            row=ok(command([path,'--version','--verbose'],name+'-identity'));report[name]=dict(path=str(path),sha256=digest(path),command=row)
        checks=ok(command([sys.executable,subject/'tests/support/test_cp05_process.py','--output-dir',output/'process-checks'],'accepted-process-failure-checks'))
        check_report=output/'process-checks/report.json';check_data=json.loads(check_report.read_text())
        if check_data['status']!='PASS' or check_data['tests_run']!=12:raise RuntimeError('accepted process failure checks incomplete')
        report['process_checks']=dict(command=checks,report_sha256=digest(check_report),collector_sha256=digest(subject/'tests/support/cp05_bounded_process.py'),tests=12)
        adapter_checks=subject/'tests/support/cp06_adapter_process_tests.py'
        accepted_tests=(subject/'tests/support/test_cp05_process.py').read_text()
        adapter_checks.write_text(change(accepted_tests,'import check_cp05_controls as helper','import check_cp06_controls as helper'))
        adapter_env=dict(env,PYTHONPATH=str(subject/'tests/support'))
        adapter_row=ok(command([sys.executable,adapter_checks,'--output-dir',output/'cp06-adapter-process-checks'],'cp06-adapter-process-failure-checks',selected_env=adapter_env))
        adapter_report=output/'cp06-adapter-process-checks/report.json';adapter_data=json.loads(adapter_report.read_text())
        if adapter_data['status']!='PASS' or adapter_data['tests_run']!=12:raise RuntimeError('CP06 adapter process failure checks incomplete')
        report['adapter_process_checks']=dict(command=adapter_row,generated_fixture=str(adapter_checks),generated_sha256=digest(adapter_checks),original_sha256=digest(subject/'tests/support/test_cp05_process.py'),only_adaptation='import check_cp05_controls as helper -> import check_cp06_controls as helper',report_sha256=digest(adapter_report),tests=12)
        ok(cargo(['generate-lockfile','--offline'],'subject-lock',features=False));report['subject_lock_sha256']=digest(subject/'Cargo.lock')
        def metadata(root,stem,feature_flags):
            e=env if root==subject else dict(env,CARGO_TARGET_DIR=str(root/'target'))
            row=ok(command([args.cargo,'metadata','--locked','--offline','--format-version','1','--manifest-path',root/'Cargo.toml',*feature_flags],stem,root,e))
            md=json.loads(Path(row['stdout']).read_text());ps=[p for p in md['packages'] if p['name']=='scopebase-capture']
            if len(ps)!=1 or ps[0]['version']!='0.1.0':raise RuntimeError('resolved subject/version mismatch')
            p=ps[0];features=next(n['features'] for n in md['resolve']['nodes'] if n['id']==p['id']);wanted={'no-default':set(),'default':{'default'},'json':{'json'}}[args.feature_set]
            if set(features)!=wanted:raise RuntimeError('subject feature mismatch')
            return dict(manifest=p['manifest_path'],version=p['version'],features=features,package_id=p['id'],metadata_sha256=digest(row['stdout']),target=md['target_directory'])
        report['subject']=metadata(subject,'subject-metadata',flags)
        if Path(report['subject']['manifest']).resolve()!=manifest.resolve():raise RuntimeError('wrong copied subject')
        def retained_artifact(row,target,stem):
            binaries=[]
            for line in Path(row['stdout']).read_text().splitlines():
                try:item=json.loads(line)
                except ValueError:continue
                if item.get('reason')=='compiler-artifact' and item.get('target',{}).get('name')==target and item.get('executable'):binaries.append(Path(item['executable']))
            if row['exit_code']!=0 or len(binaries)!=1:raise RuntimeError('build/setup failed, not semantic RED: '+stem)
            path=output/'binaries'/stem;path.parent.mkdir(exist_ok=True);shutil.copyfile(binaries[0],path);path.chmod(0o700)
            row['retained_executable']=dict(path=str(path),sha256=digest(path),original=str(binaries[0]));save();return path
        def build(target,stem):
            if target=='lib':arguments=['test','--lib','--no-run'];name='scopebase_capture'
            elif target=='example':raise AssertionError('example build needs named target')
            else:arguments=['test','--test',target,'--no-run'];name=target
            row=cargo([*arguments,'--offline','--locked','--message-format=json','-vv'],stem)
            return row,retained_artifact(row,name,stem)
        def semantic(binary,test,stem,negative,assertion,example=False):
            row=command([binary,*([] if example else ['--exact',test,'--nocapture'])],stem)
            out=Path(row['stdout']).read_text();err=Path(row['stderr']).read_text()
            reached=(row['exit_code']==101 and assertion in err and 'panicked at' in err and (example or ('running 1 test' in out and '1 failed' in out)))
            valid=reached if negative else row['exit_code']==0 and (example or '1 passed; 0 failed' in out)
            row.update(valid=valid,intended_semantic_assertion=assertion,semantic_assertion_reached=negative and reached)
            if not valid:raise RuntimeError('invalid semantic control/twin: '+stem)
            save();return row
        report['baseline']=[]
        for target in ['lib','report_views','feed_integrity','corrections','cp06_donor_subsets']:
            built,binary=build(target,'baseline-'+target+'-build');row=ok(command([binary,'--nocapture'],'baseline-'+target+'-run'));text=Path(row['stdout']).read_text()
            if '0 failed' not in text or 'running 0 tests' in text:raise RuntimeError('empty/failing baseline '+target)
            report['baseline'].append(dict(target=target,build=built,run=row))
        report['finite_populations']=dict(view_scripts=9331,view_actions=44790,feed_scripts=1364,feed_actions=5008,revision_scripts=781,revision_actions=2930)
        fixed_manifest=[('report_views','occurrence_journal_all_9331_scripts'),('feed_integrity','inventory_all_1364_scripts'),('corrections','revision_journal_all_781_scripts')]
        cases_text=(subject/'tests/support/cp06_cases.rs').read_text()
        manifest_section=cases_text.split('REQUIRED_JOURNAL_TESTS')[1].split('];')[0]
        manifest_pairs=re.findall(r'\(\s*"([A-Za-z_0-9]+)"\s*,\s*"([A-Za-z_0-9]+)"\s*\)',manifest_section)
        if manifest_pairs!=fixed_manifest:raise RuntimeError('required manifest drift: '+repr(manifest_pairs))
        def manifest_missing_texts(texts):
            missing=[]
            for target,name in fixed_manifest:
                if ('test '+name+' ... ok') not in texts[target]:missing.append(target+'::'+name)
            return missing
        baseline_texts={}
        for entry in report['baseline']:baseline_texts[entry['target']]=Path(entry['run']['stdout']).read_text()
        if manifest_missing_texts(baseline_texts):raise RuntimeError('required journal manifest incomplete: '+repr(manifest_missing_texts(baseline_texts)))
        report['required_manifest']=dict(fixed=fixed_manifest,source='tests/support/cp06_cases.rs::REQUIRED_JOURNAL_TESTS',bound_to_baseline=True,extras_allowed=True,status='BOUND')
        omit_path=subject/'tests/report_views.rs'
        omit_original=omit_path.read_text()
        omit_changed=change(omit_original,'#[test]\nfn occurrence_journal_all_9331_scripts','#[ignore]\n#[test]\nfn occurrence_journal_all_9331_scripts')
        omission=dict(id='omitted-required-journal',target='report_views',test='occurrence_journal_all_9331_scripts',assertion='CP06:required journal manifest complete',status='INVALID_CONTROL')
        report['omission_control']=omission;save()
        omit_path.write_text(omit_changed)
        try:
            _o_build,_o_binary=build('report_views','omission-mutant-build')
            _o_text=Path(command([_o_binary,'--nocapture'],'omission-mutant-run')['stdout']).read_text()
            if ('test occurrence_journal_all_9331_scripts ... ok') in _o_text:raise RuntimeError('omission not detected')
            if ('test occurrence_journal_all_9331_scripts ... ignored') not in _o_text:raise RuntimeError('omission marker absent')
            omission['mutant']=dict(detected=True,ignored_marker=True)
        finally:omit_path.write_text(omit_original)
        _r_build,_r_binary=build('report_views','omission-restored-build')
        _r_text=Path(command([_r_binary,'--nocapture'],'omission-restored-run')['stdout']).read_text()
        if ('test occurrence_journal_all_9331_scripts ... ok') not in _r_text:raise RuntimeError('restored twin missing required journal')
        omission['restored']=dict(manifest_complete=True)
        omission['restored_sha256']=digest(omit_path)
        if omission['restored_sha256']!=hashlib.sha256(omit_original.encode()).hexdigest():raise RuntimeError('restoration mismatch')
        omission['status']='KILLED_SEMANTIC';save()
        report['frozen_mutations']=[{k:v for k,v in m.items()} for m in mutations()];save()
        for m in mutations():
            path=subject/m['file'];original=path.read_text();changed=change(original,m['old'],m['new'])
            for old,new in m.get('extra',[]):changed=change(changed,old,new)
            diff=output/'diffs'/(m['id']+'.patch');diff.parent.mkdir(exist_ok=True);diff.write_text(''.join(difflib.unified_diff(original.splitlines(True),changed.splitlines(True),fromfile=m['file'],tofile=m['file'])))
            entry=dict(id=m['id'],status='INVALID_CONTROL',before_sha256=digest(path),diff_sha256=digest(diff),diff=str(diff));report['controls'].append(entry);path.write_text(changed);entry['mutant_sha256']=digest(path);save()
            def subject_build(stem):
                if m['target']!='example':return build(m['target'],stem)
                row=cargo(['build','--example',m['test'],'--offline','--locked','--message-format=json','-vv'],stem);return row,retained_artifact(row,m['test'],stem)
            try:
                entry['build'],binary=subject_build(m['id']+'-build');entry['mutant']=semantic(binary,m['test'],m['id']+'-mutant',True,m['assertion'],m['target']=='example')
            finally:path.write_text(original)
            entry['restored_build'],binary=subject_build(m['id']+'-restored-build');entry['restored']=semantic(binary,m['test'],m['id']+'-restored',False,m['assertion'],m['target']=='example');entry['restored_sha256']=digest(path)
            if entry['restored_sha256']!=entry['before_sha256']:raise RuntimeError('restoration mismatch')
            entry['status']='KILLED_SEMANTIC';save()
        def ui(name,stem,expected=None):
            path=subject/'tests/ui'/(name+'.rs')
            triggers={'cp06_unit_foreign_impl':'impl Unit for Foreign','cp06_unit_private_module':'use scopebase_capture::quantity::private','cp06_unit_private_tag':'use scopebase_capture::quantity::UnitTag;','cp06_unit_private_token':'use scopebase_capture::quantity::UnitTagAccess;','cp06_unit_private_helper':'use scopebase_capture::quantity::unit_tag;','cp06_unit_inferred_gate':'U::unit_tag(impossible())','cp06_payload_rc_send':'needs_send::<Versioned<Rc<()>>>()','cp06_correction_private_fields':'epoch,','cp06_payload_no_bounds':'let v = Versioned::new','cp06_unit_dyn':'Option<&dyn Unit>'}
            trigger=triggers.get(name)
            expected_lines=[i for i,line in enumerate(path.read_text().splitlines(),1) if trigger and trigger in line]
            if expected is not None and len(expected_lines)!=1:raise RuntimeError('expected primary trigger not unique '+name)
            row=cargo(['check','--example',name,'--offline','--locked','--message-format=json'],stem)
            diagnostics=[]
            for line in Path(row['stdout']).read_text().splitlines():
                try:item=json.loads(line)
                except ValueError:continue
                msg=item.get('message',{});code=(msg.get('code') or {}).get('code')
                for span in msg.get('spans',[]):
                    if msg.get('level')=='error' and span.get('is_primary') and Path(span.get('file_name','')).name==path.name:
                        diagnostics.append(dict(code=code,message=msg.get('message'),file=span['file_name'],line=span['line_start'],column=span['column_start']))
            if expected is None:valid=row['exit_code']==0
            else:
                code,needle=expected;valid=row['exit_code']==101 and any(d['code']==code and needle in d['message'] and d['line']==expected_lines[0] for d in diagnostics)
            row.update(valid=valid,expected_primary=expected,expected_primary_lines=expected_lines,primary_diagnostics=diagnostics,fixture_sha256=digest(path))
            if not valid:raise RuntimeError('unintended compiler result '+stem)
            save();return row
        for name in ['cp06_unit_generic','cp06_unit_dyn','cp06_payload_no_bounds','cp06_payload_send_ok']:
            report['compiler_controls'].append(dict(id=name,result=ui(name,name+'-positive')))
        negatives=[('cp06_unit_foreign_impl',('E0277','Sealed')),('cp06_unit_private_module',('E0603','private')),('cp06_unit_private_tag',('E0603','private')),('cp06_unit_private_token',('E0603','private')),('cp06_unit_private_helper',('E0603','private')),('cp06_unit_inferred_gate',(None,'private')),('cp06_payload_rc_send',('E0277','cannot be sent')),('cp06_correction_private_fields',('E0451','private'))]
        report['frozen_compiler_negatives']=negatives;save()
        for name,expected in negatives:report['compiler_controls'].append(dict(id=name,result=ui(name,name+'-negative',expected),positive_twin='cp06_unit_generic/cp06_unit_dyn/cp06_payload_no_bounds/cp06_payload_send_ok'))
        # Extra payload bound: the previously successful exact same fixture must
        # refuse at its actual external call; remove it for a restored positive.
        p=subject/'src/correction.rs';original=p.read_text();p.write_text(change(original,'impl<T> Versioned<T>','impl<T:Clone> Versioned<T>'))
        try:negative=ui('cp06_payload_no_bounds','payload-extra-Clone-bound-negative',('E0277','Clone'))
        finally:p.write_text(original)
        restored=ui('cp06_payload_no_bounds','payload-extra-Clone-bound-restored');report['compiler_controls'].append(dict(id='unnecessary-Clone-bound',negative=negative,restored=restored))
        p.write_text(original+'\nunsafe impl<T> Send for Versioned<T> {}\n')
        try:unsafe=ui('cp06_payload_rc_send','unsafe-Rc-Send-accepted-control')
        finally:p.write_text(original)
        strict=ui('cp06_payload_rc_send','safe-Rc-Send-refusal-restored',('E0277','cannot be sent'));report['compiler_controls'].append(dict(id='unsafe-Send-widening',accepted_bad_control=unsafe,restored_refusal=strict))
        p=subject/'src/quantity.rs';original=p.read_text()
        widened=change(original,'pub(crate) enum UnitTag','pub enum UnitTag')
        widened=change(widened,'pub(crate) struct UnitTagAccess','pub struct UnitTagAccess')
        p.write_text(widened)
        try:bad=ui('cp06_unit_inferred_gate','widened-private-gate-accepted-control')
        finally:p.write_text(original)
        strict=ui('cp06_unit_inferred_gate','private-inferred-gate-restored',(None,'private'))
        report['compiler_controls'].append(dict(id='D9-widened-gate',accepted_bad_control=bad,restored_refusal=strict))
        p.write_text(change(original,'where Self: Sized;',';'))
        try:bad=ui('cp06_unit_dyn','removed-Self-Sized-dyn-negative',('E0038','dyn compatible'))
        finally:p.write_text(original)
        strict=ui('cp06_unit_dyn','dyn-restored-positive')
        report['compiler_controls'].append(dict(id='D9-static-method-dyn-boundary',negative=bad,restored_positive=strict))
        for name in ['fact_views','transport_corrections']:
            client=output/'clients'/name;client.mkdir(parents=True);code=source/'examples'/(name+'.rs');shutil.copyfile(code,client/'main.rs')
            dep='scopebase-capture = { path = '+json.dumps(str(source))+', version = "=0.1.0", default-features = '+('true' if args.feature_set=='default' else 'false')+', features = '+('["json"]' if args.feature_set=='json' else '[]')+' }'
            (client/'Cargo.toml').write_text('[package]\nname = "cp06-'+name.replace('_','-')+'"\nversion = "0.0.0"\nedition = "2021"\n[workspace]\n[[bin]]\nname = "client"\npath = "main.rs"\n[dependencies]\n'+dep+'\n')
            entry=dict(id=name,source_sha256=digest(code),copied_sha256=digest(client/'main.rs'),manifest_sha256=digest(client/'Cargo.toml'));report['clients'].append(entry)
            entry['lock']=ok(cargo(['generate-lockfile','--offline'],name+'-lock',client,False));entry['lock_sha256']=digest(client/'Cargo.lock');entry['subject']=metadata(client,name+'-metadata',[])
            if Path(entry['subject']['manifest']).resolve()!=(source/'Cargo.toml').resolve():raise RuntimeError('client used another subject')
            entry['build']=ok(cargo(['build','--offline','--locked','--message-format=json','-vv'],name+'-build',client,False));binary=retained_artifact(entry['build'],'client',name+'-client')
            e=dict(env,CARGO_TARGET_DIR=str(client/'target'));entry['run']=ok(command([binary],name+'-run',client,e));entry['environment']=e;entry['binary_sha256']=digest(binary);save()
        if len(report['clients'])!=2:raise RuntimeError('missing independent client')
        report['source_unchanged']=all(digest(source/n)==h for n,h in files.items());report['restored_subject_unchanged']=all(digest(subject/n)==h for n,h in files.items() if n!='Cargo.toml')
        if not report['source_unchanged'] or not report['restored_subject_unchanged']:raise RuntimeError('source/restored-copy changed')
        report['status']='PASS';save();return 0
    except BaseException as exc:
        report['failure']=dict(type=type(exc).__name__,message=str(exc));report['status']='INCOMPLETE';save();print(json.dumps(report['failure']),file=sys.stderr);return 1


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True);p=sub.add_parser('run')
    for flag in ['source-root','cargo','rustc','output-dir']:p.add_argument('--'+flag,type=Path,required=True)
    p.add_argument('--feature-set',choices=['no-default','default','json'],required=True);p.add_argument('--build-wrapper',type=Path)
    args=parser.parse_args()
    try:
        profile=profile_environment(os.environ)
        for path in [args.source_root,args.output_dir,args.cargo,args.rustc]:
            if not path.is_absolute() or '..' in path.parts or not no_symlinks(path):raise ValueError('require absolute non-symlink paths')
        for path in [args.cargo,args.rustc,args.rustc.with_name('rustdoc')]:
            if not absolute_file(path,True):raise ValueError('require existing pinned tool '+str(path))
        if args.build_wrapper and not absolute_file(args.build_wrapper,True):raise ValueError('invalid explicit build wrapper')
        if args.output_dir.exists() or args.output_dir.is_relative_to(args.source_root):raise ValueError('require fresh output outside source root')
        if os.environ.get('CARGO_NET_OFFLINE')!='true':raise ValueError('CARGO_NET_OFFLINE=true required')
        config=Path(os.environ['CARGO_HOME'])/'config.toml'
        if not absolute_file(config):raise ValueError('require supplied offline Cargo config')
        if not args.source_root.is_dir():raise ValueError('source root missing')
        import tomllib
        names=tomllib.loads((args.source_root/'Cargo.toml').read_text())['package']['include']
        needed=['src/view.rs','src/feeds.rs','src/correction.rs','tests/report_views.rs','tests/feed_integrity.rs','tests/corrections.rs','tests/cp06_donor_subsets.rs','tests/support/cp06_cases.rs','tests/support/check_cp06_controls.py','examples/fact_views.rs','examples/transport_corrections.rs']+[str(p.relative_to(args.source_root)) for p in (args.source_root/'tests/ui').glob('cp06_*.rs')]
        if any(n not in names for n in needed):raise ValueError('CP06 delivery allowlist incomplete')
        files={}
        for name in names:
            path=args.source_root/name
            if not absolute_file(path):raise ValueError('missing/symlink delivery member '+name)
            files[name]=digest(path)
        if files.get('tests/support/cp05_bounded_process.py')!='81e371cec788e07df9139695f8f52b07fa653b1b93d36bbf8fd41ce2d8ef5bdd':raise ValueError('accepted collector hash changed')
        if files.get('tests/support/test_cp05_process.py')!='0b0ee460e827cfb8125a1307ba3126f2875a8faf2f15ff6c3153e716a7dd9138':raise ValueError('accepted failure checks hash changed')
        return run(args,args.source_root,files,profile)
    except (ValueError,OSError,KeyError) as exc:print(json.dumps(dict(status='REFUSED_PRELAUNCH',reason=str(exc))),file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
