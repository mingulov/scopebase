#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Direct Linux BP02 runner, optionally executing explicitly bound prebuilt tests.

Guest transport/lifecycle is deliberately external. A resource receipt coordinates
ownership; every actual library operation still acquires native authority itself.
"""
import sys
sys.dont_write_bytecode = True
import argparse,hashlib,json,os,subprocess,shutil,stat
from collections import Counter
from pathlib import Path

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def resource_identity(resource):
    if (resource.get('kind')!='ROOT_BP02_RESOURCE_ADMISSION' or resource.get('schema_version')!=1
            or resource.get('status')!='ADMITTED_FOR_STAGING_AND_REVIEWED_BP02_TEST_EXECUTION'):
        raise ValueError('owned resource admission is not reviewed for BP02 execution')
    owner=resource['owner'];kernel=resource['kernel']
    return {'kind':resource['kind'],'schema_version':resource['schema_version'],'status':resource['status'],
            'owner_token':owner['token'],'owner_root':owner['root'],'owner_host':owner['host'],
            'kernel_release':kernel['release'],'kernel_sha256':kernel['kernel_sha256'],
            'config_sha256':kernel['config_sha256'],'gnu_build_id':kernel['gnu_build_id'],
            'resource_sha256':resource['resource_sha256']}

def validate_prebuilt_bindings(spec,package,resource_path,resource,compiler,feature):
    bindings=spec['bindings'];checks={}
    for label,actual,expected in [
        ('owned resource digest',sha(resource_path),bindings['owned_resource_sha256']),
        ('owned resource identity',resource_identity(resource),bindings['owned_resource_identity']),
        ('compiler',compiler,bindings['compiler']),
        ('feature',feature,bindings['feature']),
        ('manifest',sha(package/'Cargo.toml'),bindings['manifest_sha256']),
    ]:
        if actual!=expected:raise ValueError(f'prebuilt {label} mismatch: requested/admitted input differs from prepared spec')
        checks[label.replace(' ','_')]='PASS'
    return checks

def validate_guard_outcomes(states):
    if not isinstance(states,list) or len(states)!=42:
        raise ValueError('guarded mapping ledger must contain exactly42 owned cleanup outcomes')
    if not all(state['cleanup_status']=='PASS' and state['stage']=='munmap'
            and state['primary_errno']is None and state['cleanup_errno']is None
            and state['extent']==8192 and type(state['base'])is int and state['base']>0 for state in states):
        raise ValueError('guarded mapping cleanup failed or unresolved')

MOUNT_CASES=['full-root','fake','online-leaf','symlink-leaf','symlink-root','subtree','full-root',
             'replace-root','full-root','fork','nested']

def cleanup_reported_root(stdout,pid,reaped,env):
    root=Path(env.get('TMPDIR','/tmp'))/('scopebase-bp02-'+str(pid))
    roots=[line.split('=',1)[1] for line in stdout.splitlines() if line.startswith('OWNED_TEMP_ROOT=')]
    identities=[line.split('=',1)[1] for line in stdout.splitlines() if line.startswith('OWNED_TEMP_ROOT_ID=')]
    row={'expected_temp_root':str(root),'root_report_count':len(roots),'identity_report_count':len(identities),
         'reported_identity':None,'observed_identity':None,'cleanup_status':'UNRESOLVED',
         'owned_temp_removed':False,'custody_unresolved':True}
    if not reaped:return row
    try:
        if len(identities)==1:
            parts=identities[0].split(':')
            if len(parts)==2 and all(p.isascii() and p.isdecimal() for p in parts):
                row['reported_identity']=[int(p) for p in parts]
        try:metadata=root.lstat()
        except FileNotFoundError:
            if not roots and not identities:row.update(cleanup_status='ABSENT',custody_unresolved=False)
            else:row['cleanup_error']='reported owned root is unavailable'
            return row
        row['observed_identity']=[metadata.st_dev,metadata.st_ino]
        if (len(roots)!=1 or len(identities)!=1 or Path(roots[0])!=root
                or not stat.S_ISDIR(metadata.st_mode) or row['reported_identity']!=row['observed_identity']):
            row['cleanup_error']='owned root report/path/type/dev/inode mismatch'
            row['unresolved_temp_root']=str(root)
            return row
        # Only the exact expected child-PID path may be removed. The report is
        # trusted-fixture corroboration, not general or race-proof authority.
        try:
            shutil.rmtree(root)
            try:root.lstat()
            except FileNotFoundError:row.update(cleanup_status='PASS',owned_temp_removed=True,custody_unresolved=False)
            else:raise OSError('owned temporary root still exists')
        except Exception as exc:row.update(cleanup_status='FAILED',cleanup_error=repr(exc),unresolved_temp_root=str(root))
    except Exception as exc:row.update(cleanup_error=repr(exc),unresolved_temp_root=str(root))
    return row

def validate_mount_children(children,env):
    cases=[]
    for child in children:
        assert child['schema_version']==1 and type(child['schema_version'])is int
        case=bytes.fromhex(child['case_hex']).decode('ascii');cases.append(case)
        assert case in MOUNT_CASES and type(child['child_pid'])is int and child['child_pid']>0
        assert child['child_reaped']is True and child['child_success']is True and child['child_exit']==0
        assert child['custody_unresolved']is False
        root=Path(env.get('TMPDIR','/tmp'))/('scopebase-bp02-'+str(child['child_pid']))
        assert bytes.fromhex(child['expected_temp_root_hex'])==os.fsencode(root)
        assert child['report_error_hex']is None and child['cleanup_error_hex']is None and child['child_error_hex']is None
        if case in ('fork','nested'):
            assert child['root_required']is False and child['cleanup_status']=='NOT_REQUIRED'
            assert child['root_report_count']==child['identity_report_count']==0
            assert child['reported_identity']is None and child['observed_identity']is None
            assert child['owned_temp_removed']is False
            internal=[]
            for line in bytes.fromhex(child['child_stdout_hex']).decode(errors='replace').splitlines():
                if line.startswith('BP02_INTERNAL_CHILD_CUSTODY='):
                    internal.append(json.loads(line.split('=',1)[1]))
            child['internal_children']=internal
            assert len(internal)==1,'N8 internal-child custody missing/duplicated'
            state=internal[0]
            assert state['schema_version']==1 and state['child_reaped']is True and state['child_success']is True
            assert state['custody_unresolved']is False and state['child_pid']==state['returned_pid']
            assert state['errno']is None and state['status']==0
            assert type(state['attempts'])is int and 1<=state['attempts']<=8 and state['attempts']==state['retries']+1
        else:
            assert child['root_required']is True and child['cleanup_status']=='PASS' and child['owned_temp_removed']is True
            assert child['root_report_count']==child['identity_report_count']==1
            identity=child['reported_identity'];assert isinstance(identity,list) and len(identity)==2
            assert all(type(n)is int and n>=0 for n in identity) and identity==child['observed_identity']
        assert b'PASS' in bytes.fromhex(child['child_stdout_hex'])
    assert Counter(cases)==Counter(MOUNT_CASES),'missing/duplicate fixture child cases'
    return True

def run_mount_cases(command,env,out,rows):
    row={'case':'N6-N8','command':list(map(str,command)),'exit':None,'status':'FAILED',
         'child_reaped':False,'fixture_children':[],'cleanup_status':'UNRESOLVED','custody_unresolved':True}
    child=None;stdout=''
    try:
        child=subprocess.Popen(row['command'],env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        stdout,_=child.communicate();row.update(exit=child.returncode,child_reaped=True)
    except Exception as exc:row['execution_error']=repr(exc)
    finally:
        if child is not None and not row['child_reaped']:
            try:child.kill();stdout,_=child.communicate();row.update(exit=child.returncode,child_reaped=True)
            except Exception as exc:row['reap_error']=repr(exc)
        errors=[]
        for line in stdout.splitlines():
            if 'BP02_CHILD_CUSTODY=' in line:
                try:row['fixture_children'].append(json.loads(line.split('BP02_CHILD_CUSTODY=',1)[1]))
                except Exception as exc:errors.append(repr(exc))
        row['fixture_parse_errors']=errors
        row['primary_output_tail']=stdout[-4096:]
        try:
            validate_mount_children(row['fixture_children'],env)
            row.update(fixture_custody_validation='PASS',cleanup_status='PASS',custody_unresolved=False)
        except Exception as exc:
            row['fixture_custody_validation']='FAILED';row['fixture_custody_error']=repr(exc)
        try:
            log=out/'N6-N8.log';log.write_text(stdout);row['log_sha256']=sha(log)
        except Exception as exc:row['log_error']=repr(exc)
        row['semantic_status']='PASS' if row['exit']==0 and '3 passed; 0 failed' in stdout else 'FAILED_PRIMARY_CHILD_OR_SETUP'
        if (row['child_reaped'] and row['semantic_status']=='PASS' and row.get('fixture_custody_validation')=='PASS'
                and not errors and 'log_error'not in row):row['status']='PASS'
        rows.append(row)
    if row['status']!='PASS':raise RuntimeError('N6-N8 primary/fixture/cleanup/log failure retained in receipt')
    return stdout

def run_symlink_case(label,binary,expected_failure,env,out,rows):
    command=[str(binary),'symlink-root','--owned-namespace']
    row={'case':label,'command':command,'exit':None,'status':'FAILED',
         'semantic_status':'NOT_RUN','child_reaped':False,
         'cleanup_status':'NOT_RUN','owned_temp_removed':False,'custody_unresolved':True,
         'root_report_count':0,'identity_report_count':0,'reported_identity':None,'observed_identity':None}
    child=None;stdout='';error=None
    try:
        child=subprocess.Popen(command,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        stdout,_=child.communicate();row['exit']=child.returncode;row['child_reaped']=True
        if expected_failure:
            valid=child.returncode>0 and 'false source accepted symlink-root' in stdout and 'panicked at' in stdout
            row['semantic_status']='EXPECTED_SEMANTIC_FAILURE' if valid else 'FAILED_SEMANTIC_ASSERTION'
        else:
            valid=child.returncode==0 and 'PASS source symlink-root' in stdout
            row['semantic_status']='PASS' if valid else 'FAILED_POSITIVE'
    except Exception as exc:
        error=exc;row['execution_error']=repr(exc);row['semantic_status']='SETUP_FAILED'
    finally:
        if child is not None and not row['child_reaped']:
            try:
                child.kill();stdout,_=child.communicate();row['exit']=child.returncode;row['child_reaped']=True
            except Exception as exc:row['reap_error']=repr(exc)
        row['primary_child_output']=stdout
        if child is None:
            row.update(cleanup_status='NOT_STARTED',custody_unresolved=False)
        elif not row['child_reaped']:
            row['cleanup_status']='UNRESOLVED_CHILD'
        else:row.update(cleanup_reported_root(stdout,child.pid,row['child_reaped'],env))
        # Persistence can fail independently of child/root retirement. Always
        # finish cleanup and retain its row even if the results filesystem fails.
        try:
            log=out/(label+'.log');log.write_text(stdout);row['log_sha256']=sha(log)
        except Exception as exc:
            row['log_error']=repr(exc)
        if row['cleanup_status']!='PASS':row['status']='CLEANUP_OR_CUSTODY_FAILED'
        elif 'log_error' in row:row['status']='LOG_PERSISTENCE_FAILED'
        else:row['status']=row['semantic_status']
        rows.append(row)
    if row['cleanup_status']!='PASS':raise RuntimeError(f'{label}: cleanup/custody failure retained in receipt') from error
    if 'log_error' in row:raise RuntimeError(f'{label}: log persistence failure retained in receipt')
    if row['semantic_status'] not in ('PASS','EXPECTED_SEMANTIC_FAILURE'):
        raise RuntimeError(f'{label}: semantic assertion or setup failure retained in receipt') from error
    return row

def main():
    p=argparse.ArgumentParser();p.add_argument('--package',required=True,type=Path);p.add_argument('--out',required=True,type=Path);p.add_argument('--toolchain',required=True,choices=['1.88.0','1.98.1']);p.add_argument('--feature',choices=['default','no-default'],help='required requested mode for --prebuilt');p.add_argument('--toolchain-root',type=Path);p.add_argument('--cargo-home',type=Path);p.add_argument('--build-wrapper',type=Path);p.add_argument('--owned-resource',required=True,type=Path);p.add_argument('--owned-namespace',action='store_true');p.add_argument('--prebuilt',type=Path);p.add_argument('--prepare-only',action='store_true');args=p.parse_args();args.package=args.package.resolve();args.out=args.out.resolve();assert not args.out.exists();args.out.mkdir(parents=True)
    resource=json.loads(args.owned_resource.read_text());rows=[];receipt={'status':'FAILED','resource_sha256':sha(args.owned_resource),'resource':resource,'mode':'native-map','toolchain':args.toolchain,'commands':rows,'required_cells':['N1','N2','N3','N4','N5','N6','N7','N8','N9','R1-original-task'],'route':'prebuilt-direct' if args.prebuilt else str(args.build_wrapper or 'explicit-direct-children')}
    def run(command,name,env=None,positive=None,heavy=False):
        command=list(map(str,command));actual=([str(args.build_wrapper),'--'] if heavy and args.build_wrapper else [])+command;r=subprocess.run(actual,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        row={'case':name,'command':actual,'exit':r.returncode,'status':'FAILED','primary_output_tail':r.stdout[-4096:]}
        try:
            log=args.out/(name+'.log');log.write_text(r.stdout);row['log_sha256']=sha(log)
        except Exception as exc:row['log_error']=repr(exc)
        try:row['guard_outcomes']=[json.loads(line.split('BP02_GUARD_CUSTODY=',1)[1]) for line in r.stdout.splitlines() if name=='N1-N5-N9' and 'BP02_GUARD_CUSTODY=' in line]
        except Exception as exc:row['guard_parse_error']=repr(exc)
        if positive and positive not in r.stdout:row['population_error']='missing positive test population'
        if name=='N1-N5-N9':
            try:validate_guard_outcomes(row.get('guard_outcomes'))
            except (ValueError,KeyError,TypeError) as exc:row['guard_custody_error']=repr(exc)
        if r.returncode==0 and all(key not in row for key in ['log_error','guard_parse_error','population_error','guard_custody_error']):row['status']='PASS'
        rows.append(row)
        assert row['status']=='PASS',f'{name}: primary/log/guard failure retained: {r.stdout[-4000:]}'
        return r.stdout
    try:
        admitted_identity=resource_identity(resource)
        receipt['resource_identity']=admitted_identity
        if args.prebuilt:
            assert not args.prepare_only
            if args.feature is None:raise ValueError('--prebuilt requires explicit --feature')
            spec=json.loads(args.prebuilt.read_text());receipt['prebuilt_sha256']=sha(args.prebuilt);receipt['bindings']=spec['bindings']
            receipt['requested_feature']=args.feature
            receipt['binding_checks']=validate_prebuilt_bindings(spec,args.package,args.owned_resource,resource,args.toolchain,args.feature)
            bins={}
            for name,row in spec['binaries'].items():
                path=Path(row['path']);assert path.is_absolute() and sha(path)==row['sha256'];bins[name]=path
        else:
            if args.feature is not None:raise ValueError('--feature is only for --prebuilt')
            assert args.toolchain_root and args.cargo_home and args.toolchain_root.is_absolute() and args.cargo_home.is_absolute()
            tools=args.toolchain_root/'bin';base_env={**os.environ,'CARGO_HOME':str(args.cargo_home),'RUSTC':str(tools/'rustc'),'RUSTDOC':str(tools/'rustdoc')}
            run([tools/'rustc','--version'],'compiler',base_env,positive='rustc '+args.toolchain+' ',heavy=True)
            from run_consumers import inspect
            import tomllib
            receipt['manifest']=inspect(args.package);prepared=[];receipt['tools']={name:{'path':str(tools/name),'sha256':sha(tools/name)}for name in ['cargo','rustc','rustdoc']}
            metadata=json.loads(run([tools/'cargo','metadata','--manifest-path',args.package/'Cargo.toml','--locked','--offline','--format-version=1'],'metadata',base_env,heavy=True))
            original_lock=Path(metadata['workspace_root'])/'Cargo.lock';original_rows={x['name']:(x['version'],x.get('source'),x.get('checksum')) for x in tomllib.loads(original_lock.read_text())['package'] if x.get('source')}
            for mode in ['default','no-default']:
                extra=['--no-default-features'] if mode=='no-default' else [];target=args.out/'targets'/mode;env={**base_env,'CARGO_TARGET_DIR':str(target)}
                features=run([tools/'cargo','tree','--manifest-path',args.package/'Cargo.toml','--locked','--offline','-e','features']+extra,mode+'-features',env,heavy=True)
                command=[tools/'cargo','test','--manifest-path',args.package/'Cargo.toml','--locked','--offline','--lib','--tests','--no-run','--message-format=json']+extra
                out=run(command,mode+'-build-tests',env,heavy=True);built={}
                for line in out.splitlines():
                    try:row=json.loads(line)
                    except ValueError:continue
                    if row.get('reason')=='compiler-artifact' and row.get('executable'):
                        name='lib' if 'lib' in row['target']['kind'] else row['target']['name'];built[name]=Path(row['executable'])
                run([tools/'cargo','build','--manifest-path',args.package/'Cargo.toml','--locked','--offline','--examples']+extra,mode+'-build-fixture',env,heavy=True);built['fixture']=target/'debug/examples/bp02_live_fixture'
                control=args.out/('symlink-control-'+mode);shutil.copytree(args.package,control,ignore=shutil.ignore_patterns('target','__pycache__','.git'))
                source=control/'src/maps/provenance.rs';old='ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS';text=source.read_text();assert text.count(old)==1;before=sha(source);source.write_text(text.replace(old,'ResolveFlags::NO_MAGICLINKS',1));after=sha(source)
                manifest=control/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n');inspect(control);shutil.copyfile(original_lock,control/'Cargo.lock')
                # Resolve only the private control workspace; every selected
                # registry row must retain the original subject's exact pin.
                control_env={**env,'CARGO_TARGET_DIR':str(args.out/'control-targets'/mode)}
                run([tools/'cargo','metadata','--manifest-path',manifest,'--offline','--format-version=1'],mode+'-control-metadata',control_env,heavy=True)
                for row in tomllib.loads((control/'Cargo.lock').read_text())['package']:
                    if row.get('source'):assert original_rows.get(row['name'])==(row['version'],row.get('source'),row.get('checksum')),'control changed dependency resolution'
                run([tools/'cargo','build','--manifest-path',manifest,'--locked','--offline','--example','bp02_live_fixture']+extra,mode+'-build-control',control_env,heavy=True);built['symlink_mutant']=args.out/'control-targets'/mode/'debug/examples/bp02_live_fixture'
                additional_controls={}
                for control_name in ['leaf','cached-stat']:
                    control=args.out/(control_name+'-control-'+mode);shutil.copytree(args.package,control,ignore=shutil.ignore_patterns('target','__pycache__','.git'));source=control/'src/maps/provenance.rs';text=source.read_text();control_before=sha(source)
                    if control_name=='leaf':
                        old_leaf='.union(ResolveFlags::NO_SYMLINKS)';assert text.count(old_leaf)==1;text=text.replace(old_leaf,'',1)
                    else:
                        start=text.index("impl ProbeIo for OriginalProbe");start=text.index('    fn open(',start);end=text.index('    fn stat(',start);method=text[start:end];body=method[method.index('{')+1:method.rfind('}')]
                        replacement='    fn open(&self)->Result<OwnedFd,OperationError>{ CONTROL_CACHED_STAT.with(|cache|{if cache.borrow().is_none(){let fd=(||{'+body+'})()?;*cache.borrow_mut()=Some(fd);}cache.borrow().as_ref().unwrap().try_clone().map_err(|e|native::os_error(e.raw_os_error().unwrap_or(5),S::Admission))}) }\n'
                        text=text[:start]+replacement+text[end:];text+='\nthread_local!{static CONTROL_CACHED_STAT:std::cell::RefCell<Option<OwnedFd>>=const{std::cell::RefCell::new(None)};}\n'
                    source.write_text(text);manifest=control/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n');inspect(control);shutil.copyfile(original_lock,control/'Cargo.lock');control_env={**env,'CARGO_TARGET_DIR':str(args.out/'control-targets'/(control_name+'-'+mode))}
                    run([tools/'cargo','metadata','--manifest-path',manifest,'--offline','--format-version=1'],mode+'-'+control_name+'-metadata',control_env,heavy=True)
                    for row in tomllib.loads((control/'Cargo.lock').read_text())['package']:
                        if row.get('source'):assert original_rows.get(row['name'])==(row['version'],row.get('source'),row.get('checksum')),'control changed dependency resolution'
                    output=run([tools/'cargo','test','--manifest-path',manifest,'--locked','--offline','--lib','--no-run','--message-format=json']+extra,mode+'-'+control_name+'-build',control_env,heavy=True);executable=None
                    for line in output.splitlines():
                        try:row=json.loads(line)
                        except ValueError:continue
                        if row.get('reason')=='compiler-artifact'and row.get('executable'):executable=Path(row['executable'])
                    assert executable;built[control_name+'_mutant']=executable;additional_controls[control_name]={'source_before_sha256':control_before,'source_after_sha256':sha(source),'allowed_test':'maps::provenance::tests::authentic_sysfs_leaf_symlink_refuses' if control_name=='leaf'else'maps::provenance::tests::owned_task_probe_dead_and_living_twins'}
                assert set(built)>={'lib','maps_live','maps_mounts','fixture','symlink_mutant'}
                spec={'bindings':{'feature':mode,'manifest_sha256':sha(args.package/'Cargo.toml'),'lock_sha256':sha(original_lock),'compiler':args.toolchain,'owned_resource_sha256':sha(args.owned_resource),'owned_resource_identity':admitted_identity,'feature_tree_sha256':hashlib.sha256(features.encode()).hexdigest(),'tools':receipt['tools'],'additional_controls':additional_controls,'control_patch':{'path':'src/maps/provenance.rs','before_sha256':before,'after_sha256':after,'old':old,'new':'ResolveFlags::NO_MAGICLINKS'}},'binaries':{name:{'path':str(path),'sha256':sha(path)} for name,path in built.items()}}
                spec_path=args.out/(mode+'-prebuilt.json');spec_path.write_text(json.dumps(spec,indent=2)+'\n');prepared.append(spec_path)
            receipt['prepared_specs']=[{'path':str(p),'sha256':sha(p)} for p in prepared]
            if args.prepare_only:
                receipt['status']='PREPARED_NOT_RUN';receipt['runtime_cells']='NOT_RUN';print(json.dumps({'status':receipt['status'],'specs':list(map(str,prepared))}));return
            for spec_path in prepared:
                command=[sys.executable,Path(__file__).resolve(),'--package',args.package,'--out',args.out/('live-'+spec_path.stem),'--toolchain',args.toolchain,'--feature',spec_path.stem.removesuffix('-prebuilt'),'--owned-resource',args.owned_resource,'--prebuilt',spec_path]
                if args.owned_namespace:command+=['--owned-namespace']
                run(command,spec_path.stem+'-live')
            receipt['status']='PASS';return
        receipt['possible']=Path('/sys/devices/system/cpu/possible').read_text();receipt['online']=Path('/sys/devices/system/cpu/online').read_text()
        env={**os.environ,'SCOPEBASE_BP02_FIXTURE':str(bins['fixture'])}
        run([bins['maps_live'],'--ignored','--test-threads=1','--nocapture'],'N1-N5-N9',env,positive='8 passed; 0 failed')
        control_env={**env,'SCOPEBASE_BP02_SHORT_LOGICAL_BOUNDARY':'1'}
        command=[str(bins['maps_live']),'--ignored','--exact','n9_raw_guard','--test-threads=1','--nocapture'];r=subprocess.run(command,env=control_env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        log=args.out/'N9-logical-short-control.log';log.write_text(r.stdout);assert r.returncode>0 and 'raw logical-boundary sentinel' in r.stdout and 'test n9_raw_guard ...' in r.stdout and 'FAILED' in r.stdout,'control must fail intended sentinel assertion'
        rows.append({'case':'N9-logical-short-control','command':command,'exit':r.returncode,'log_sha256':sha(log),'status':'EXPECTED_SEMANTIC_FAILURE'})
        run([bins['maps_live'],'--ignored','--exact','n9_raw_guard','--test-threads=1','--nocapture'],'N9-restored',env,positive='1 passed; 0 failed')
        run([bins['lib'],'--ignored','--exact','maps::native::call_order_live_tests::bloom_and_argument_call_order','--test-threads=1','--nocapture'],'N4-call-order',env,positive='1 passed; 0 failed')
        run([bins['lib'],'--ignored','--exact','maps::provenance::tests::owned_task_probe_dead_and_living_twins','--test-threads=1','--nocapture'],'R1-original-task',env,positive='1 passed; 0 failed')
        if not args.owned_namespace:raise RuntimeError('BLOCKED_ENVIRONMENT required N6-N8 needs explicit --owned-namespace')
        run_mount_cases(['unshare','--mount','--pid','--fork','--mount-proc','--propagation','private',bins['maps_mounts'],'--ignored','--test-threads=1','--nocapture'],env,args.out,rows)
        run([bins['lib'],'--ignored','--exact','maps::native::live_tests::source_replaced_after_precheck_suppresses_output','--test-threads=1','--nocapture'],'N7-postcheck',env,positive='1 passed; 0 failed')
        # Root-symlink mutant removes only the root NO_SYMLINKS bit. Its
        # target is a full authentic sysfs root; native extent remains authentic.
        for label,binary,expected_failure in [('N6-no-symlink-control',bins['symlink_mutant'],True),('N6-symlink-restored',bins['fixture'],False)]:
            run_symlink_case(label,binary,expected_failure,env,args.out,rows)
        for name,test,marker in [('leaf','maps::provenance::tests::authentic_sysfs_leaf_symlink_refuses','authentic symlink leaf accepted'),('cached-stat','maps::provenance::tests::owned_task_probe_dead_and_living_twins','each original anchor probe must perform a new open description')]:
            run([bins['lib'],'--ignored','--exact',test,'--test-threads=1','--nocapture'],'N6-R1-'+name+'-positive',env,positive='1 passed; 0 failed')
            command=[str(bins[name+'_mutant']),'--ignored','--exact',test,'--test-threads=1','--nocapture'];r=subprocess.run(command,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);log=args.out/(name+'-control.log');log.write_text(r.stdout);assert r.returncode>0 and marker in r.stdout and 'FAILED'in r.stdout and 'panicked at'in r.stdout,'control must fail intended '+name+' assertion'
            rows.append({'case':name+'-control','command':command,'exit':r.returncode,'log_sha256':sha(log),'status':'EXPECTED_SEMANTIC_FAILURE'})
            run([bins['lib'],'--ignored','--exact',test,'--test-threads=1','--nocapture'],'N6-R1-'+name+'-restored',env,positive='1 passed; 0 failed')
        receipt['status']='PASS'
    except Exception as exc:
        receipt['error']=repr(exc)
        raise
    finally:(args.out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'status':receipt['status'],'receipt':str(args.out/'receipt.json')}))
if __name__=='__main__':main()
