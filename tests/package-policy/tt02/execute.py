#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit TT02 source/archive/four-client matrix; each Cargo call owns one slot.

Run from the repository with a new private --output and the accepted vendor
--config. This task driver never changes generic helpers or main policy/lock.
"""
from __future__ import annotations
import argparse,hashlib,json,os,pathlib,shutil,sys,tomllib
ROOT=pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools/build'))
import common as p
sys.path.insert(0,str(ROOT/'tools/qualification'))
import bind_consumer as binder

def write(path,value):path.write_bytes(json.dumps(value,sort_keys=True,indent=2).encode()+b'\n')
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def selected_sources(project,corpus,archive,client):
 files={'subject-archive':archive,'client-case-source':project/'src/main.rs','client-oracle-source':project/'src/main.rs','client-control-source':project/'src/main.rs','client-fixture-manifest':corpus/('receipt-failed.json'if client=='tt02-receipt'else'bundle.json')}
 roles={'subject-archive':'subject_archive','client-case-source':'case_source','client-oracle-source':'oracle_source','client-control-source':'control_source','client-fixture-manifest':'fixture_manifest'}
 return [{'id':i,'revision':1,'role':roles[i],'length':str(f.stat().st_size),'sha256':p.sha(f)}for i,f in sorted(files.items())],files

def expected_packages(member,grant,features):
 literal=json.loads((ROOT/'tests/package-policy/tt02/expected-features.json').read_bytes());selected={r['name']:r['features']for r in literal['packages']}
 records=[{'name':v['name'],'version':v['version'],'source':v['source'],'source_sha256':v['sha256'],'features':selected[v['name']]}for v in member['minimal_dependencies']]
 records.append({'name':'scopebase-testkit','version':'0.1.0','source':'fixture:tt02','source_sha256':grant['sha256'],'features':features})
 return sorted(records,key=lambda r:(r['name'],r['version'],r['source']))

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);ap.add_argument('--config',required=True);ap.add_argument('--prepare-only',action='store_true');ap.add_argument('--resume',action='store_true');ap.add_argument('--build-wrapper',required=True);a=ap.parse_args();out=pathlib.Path(a.output).resolve();out.mkdir(mode=0o700,exist_ok=a.resume);config=pathlib.Path(a.config).resolve();wrapper=pathlib.Path(a.build_wrapper).resolve();assert p.sha(wrapper)=='f112693933f18ae8483a52aa9811a0df54e5366505ba48a19b720a8a2b8e5f6f', 'controller wrapper binding'
 if out.is_relative_to(ROOT):raise ValueError('output must be outside the task worktree')
 tools=['1.88.0','1.98.1'];modes=['minimal','default'];clients=['tt01-inventory','tt01-selection','tt02-run','tt02-receipt'];results=json.loads((out/'results.json').read_bytes())['results']if a.resume else[];prior={r['id']:r for r in results if r['exit_code']==0 and not r['reason_code']and r['cleanup']=='complete'};write(out/'build-route.json',{'wrapper':str(wrapper),'sha256':p.sha(wrapper),'shared_lock':'/run/user/1000/scopebase-locks/build.lock','prior_domain':'/home/user/.cache/scopebase/locks/build.lock'if a.resume else None})
 required=[f'{kind}/{t}/{mode}/{check}'for kind in ['source','archive']for t in tools for mode in modes for check in ['tests','doc',*clients,'tt02-run-bound','tt02-receipt-bound']]
 write(out/'required.json',required)
 source=out/'source'/'subject';source.parent.mkdir(exist_ok=a.resume);grant=p.original_grant(ROOT/'crates/scopebase-testkit','fixture:tt02',[]);p.copied_mapping(grant,source)if a.resume else p.source_copy(ROOT/'crates/scopebase-testkit',source);(source.parent/'Cargo.toml').write_text('[workspace]\nresolver="2"\nmembers=["subject"]\n')
 dependency_member=json.loads((ROOT/'tests/package-policy/tt02/member.json').read_bytes());allowed={(v['name'],v['version'],v['source']):v for v in dependency_member['allowed_dependencies']};toolrecords={}
 def env(t,target):
  tool=pathlib.Path('/home/user/.rustup/toolchains')/(t+'-x86_64-unknown-linux-gnu')
  return {'PATH':str(tool/'bin')+':/usr/bin:/bin','HOME':os.environ['HOME'],'CARGO_HOME':str(out/'cargo-home'),'CARGO_TARGET_DIR':str(target),'CARGO_NET_OFFLINE':'true','CARGO_BUILD_JOBS':'2','RUSTC':str(tool/'bin/rustc'),'RUSTDOC':str(tool/'bin/rustdoc'),'TMPDIR':str(out/'tmp'),'LC_ALL':'C.UTF-8'}
 (out/'tmp').mkdir(exist_ok=a.resume);(out/'cargo-home').mkdir(exist_ok=a.resume);logcounter=max([int(f.name.split('-')[1].split('.')[0])for f in out.glob('command-*.stdout')],default=0)
 def command(name,t,manifest,args,target,expect=0):
  nonlocal logcounter
  if name in prior:
   old=prior[name]
   for log in old['logs'].values():assert p.sha(log['path'])==log['sha256'],'changed retained command log'
   return old
  logcounter+=1;tool=pathlib.Path('/home/user/.rustup/toolchains')/(t+'-x86_64-unknown-linux-gnu')
  argv=[wrapper,'--',tool/'bin/cargo','--config',config,*args,'--manifest-path',manifest]
  result=p.run(argv,out,env(t,target),out/f'command-{logcounter:03d}',timeout=600)
  results.append({'id':name,**result});write(out/'checkpoint.json',{'required':required,'results':results,'status':'IN_PROGRESS'})
  if result['exit_code']!=expect or result['reason_code'] or result['cleanup']!='complete':raise RuntimeError((name,result))
  return result
 def binary(name,path,args,t,target,expect=0):
  nonlocal logcounter
  if name in prior:
   old=prior[name];assert p.sha(path)==old['executable_sha256'],'changed retained executable'
   for log in old['logs'].values():assert p.sha(log['path'])==log['sha256'],'changed retained command log'
   return old
  logcounter+=1;before=p.sha(path);result=p.run([path,*args],out,env(t,target),out/f'command-{logcounter:03d}',timeout=60);after=p.sha(path);results.append({'id':name,'executable_sha256':before,**result});write(out/'checkpoint.json',{'required':required,'results':results,'status':'IN_PROGRESS'})
  if before!=after or result['exit_code']!=expect or result['reason_code'] or result['cleanup']!='complete':raise RuntimeError((name,result))
  return result
 try:
  command('lock','1.88.0',source/'Cargo.toml',['generate-lockfile','--offline'],out/'targets/package')
  shutil.copy(source.parent/'Cargo.lock',source/'Cargo.lock');identity=p.copied_mapping(grant,source)
  listing=command('package-list','1.88.0',source/'Cargo.toml',['package','--list','--offline','--locked','--allow-dirty'],out/'targets/package')
  package_files=p.stdout(listing).splitlines();p.package_files(package_files,dependency_member['package_files']);write(out/'package-files.json',package_files)
  command('package','1.88.0',source/'Cargo.toml',['package','--no-verify','--offline','--locked','--allow-dirty'],out/'targets/package')
  archive=out/'targets/package/package/scopebase-testkit-0.1.0.crate';unpacked=(out/'archive/scopebase-testkit-0.1.0')if a.resume else p.safe_unpack(archive,out/'archive','scopebase-testkit-0.1.0');archive_identity=p.archive_mapping(identity,source,unpacked,archive,package_files)
  (out/'archive/Cargo.toml').write_text('[workspace]\nresolver="2"\nmembers=["scopebase-testkit-0.1.0"]\n');command('archive-lock','1.88.0',unpacked/'Cargo.toml',['generate-lockfile','--offline'],out/'targets/package');write(out/'origin-mapping.json',archive_identity);write(out/'archive.json',{'path':str(archive),'sha256':p.sha(archive),'files':p.tree_records(unpacked)})
  if a.prepare_only:
   write(out/'results.json',{'required':required,'results':results,'status':'PREPARED_NOT_QUALIFIED'});return
  for t in tools:
   tool=pathlib.Path('/home/user/.rustup/toolchains')/(t+'-x86_64-unknown-linux-gnu');toolrecords[t]={n:p.sha(tool/'bin'/n)for n in ['rustc','cargo','rustdoc']};toolrecords[t]['versions']={}
   for n in ['rustc','cargo','rustdoc']:
    log=out/('identity-'+t.replace('.','_')+'-'+n)
    if a.resume and log.with_suffix('.stdout').exists():toolrecords[t]['versions'][n]={'retained_stdout':str(log.with_suffix('.stdout')),'sha256':p.sha(log.with_suffix('.stdout'))}
    else:toolrecords[t]['versions'][n]=p.run([tool/'bin'/n,'-Vv'],out,env(t,out/'targets/identity'),log,timeout=30)
   for kind,subject in [('source',source),('archive',unpacked)]:
    for mode in modes:
     stem=f'{kind}/{t}/{mode}';target=out/'targets'/kind/t/mode;features=['--no-default-features']if mode=='minimal'else[]
     command(stem+'/tests',t,subject/'Cargo.toml',['test','--offline','--locked','--lib','--tests',*features],target)
     command(stem+'/doc',t,subject/'Cargo.toml',['test','--offline','--locked','--doc',*features],target)
     for client in clients:
      project=out/'clients'/kind/t/mode/client;(project/'src').mkdir(parents=True,exist_ok=a.resume);shutil.copy(ROOT/f'tests/package-policy/fixtures/clients/{client}.rs',project/'src/main.rs');(project/'Cargo.toml').write_text('[workspace]\n[package]\nname="'+client+'"\nversion="0.1.0"\nedition="2021"\n[dependencies]\nscopebase-testkit={path='+json.dumps(str(subject))+',default-features='+('false'if mode=='minimal'else'true')+'}\n')
      command(stem+'/'+client+'/lock',t,project/'Cargo.toml',['generate-lockfile','--offline'],target)
      metaresult=command(stem+'/'+client+'/metadata',t,project/'Cargo.toml',['metadata','--offline','--locked','--format-version','1','--filter-platform','x86_64-unknown-linux-gnu'],target);metadata=json.loads(p.stdout(metaresult));write(project/'metadata.json',metadata)
      nodes={n['id']:n for n in metadata['resolve']['nodes']};records=[];sources={}
      for package in metadata['packages']:
       if package['id']not in nodes or package['name']==client:continue
       if package['name']=='scopebase-testkit':src='fixture:tt02';sha=grant['sha256']
       else:
        key=(package['name'],package['version'],package['source']);admitted=allowed.get(key)
        if admitted is None:raise ValueError('unadmitted dependency '+str(key))
        src=package['source'];sha=admitted['sha256']
       sources[package['id']]={'source':src,'source_sha256':sha};records.append({'name':package['name'],'version':package['version'],'source':src,'source_sha256':sha,'features':sorted(nodes[package['id']]['features'])})
      corpus=subject/'tests/fixtures/harness';pre_source=p.fixture_digest(project/'src')
      if client.startswith('tt02'):
       selected,selected_files=selected_sources(project,corpus,archive,client)
       recipe={'schema_version':1,'subject':{'name':'scopebase-testkit','version':'0.1.0','source_sha256':grant['sha256'],'archive_sha256':p.sha(archive)},'generated_lock_sha256':p.sha(project/'Cargo.lock'),'resolved_packages':expected_packages(dependency_member,grant,['default']if mode=='default'else[]),'backend':None,'host':'x86_64-unknown-linux-gnu','target':'x86_64-unknown-linux-gnu','compiler':{n+'_sha256':toolrecords[t][n]for n in ['rustc','cargo','rustdoc']},'compiler_arguments':[],'linker_arguments':[],'consumer_source_inventory_sha256':pre_source}
       expected={'schema_version':1,'kind':'tt02-expected-consumer','build_inputs':recipe,'consumer_name':client,'features':(['default']if mode=='default'else[]),'artifacts':selected}
       write(project/'expected-input.json',expected)
      built=command(stem+'/'+client+'/build',t,project/'Cargo.toml',['build','--offline','--locked','--message-format=json'],target)
      assert p.fixture_digest(project/'src')==pre_source,'consumer source changed during actual build'
      if client.startswith('tt02'):
       assert all(p.sha(selected_files[a['id']])==a['sha256']for a in selected),'selected source/fixture changed during build'

      linked=[json.loads(line)for line in p.stdout(built).splitlines()if line.strip()]
      emitted=[v for v in linked if v.get('reason')=='compiler-artifact'and v.get('executable')and v['target']['name']==client]
      if len(emitted)!=1:raise ValueError('missing unique actual Cargo executable')
      exe=pathlib.Path(emitted[0]['executable']);build_artifact={'package_id':emitted[0]['package_id'],'target_name':client,'executable':str(exe),'sha256':p.sha(exe)}
      write(project/'cargo-build-artifact.json',emitted[0])
      corpus=subject/'tests/fixtures/harness';args=[str(corpus)]if client.startswith('tt02')else[]
      binary(stem+'/'+client,exe,args,t,target)
      if client.startswith('tt02'):
       observed_recipe=dict(recipe,resolved_packages=sorted(records,key=lambda r:(r['name'],r['version'],r['source'])))
       record={'schema_version':1,'kind':'tt02-admitted-build','build_inputs':observed_recipe,'source_mapping':{'name':'scopebase-testkit','version':'0.1.0','original_source_sha256':grant['sha256'],'archive_sha256':p.sha(archive),'resolved_manifest_path':str(subject/'Cargo.toml')},'package_sources':sources,'artifact_files':{i:str(f)for i,f in selected_files.items()},'executable_length':str(exe.stat().st_size),'consumer_name':client,'build_artifact':build_artifact}
       write(project/'build-record.json',record)
       args_binder=['--expected',str(project/'expected-input.json'),'--build-record',str(project/'build-record.json'),'--metadata',str(project/'metadata.json'),'--executable',str(exe),'--output',str(project/'actual-measurement.json')]
       # Binder has no subprocess/Cargo capability; this is a separate bounded pass.
       if a.resume and (project/'actual-measurement.json').exists():
        actual=binder.bind(expected,record,metadata,exe,{n:p.sha(project/file)for n,file in [('expected','expected-input.json'),('build_record','build-record.json'),('metadata','metadata.json')]});assert canonical(actual)==(project/'actual-measurement.json').read_bytes(),'changed generated measurement'
       else:binder.main(args_binder)
       # Independent expected measurement uses hashlib and retained source/build
       # records directly; never copies the binder output or production serializer.
       artifacts=expected['artifacts'];total=sum(int(a['length'])for a in artifacts);binary_len=exe.stat().st_size;binary_sha=p.sha(exe);build_hash=hashlib.sha256(canonical(recipe)).hexdigest();nreads=sum((int(a['length'])+65535)//65536+1 for a in artifacts)+(binary_len+65535)//65536+1
       expected_measure={'schema_version':1,'kind':'tt02-generated-measurement','build_inputs_sha256':build_hash,'input_sha256':{n:p.sha(project/file)for n,file in [('expected','expected-input.json'),('build_record','build-record.json'),('metadata','metadata.json')]},'subject':{'package_name':'scopebase-testkit','package_version':'0.1.0','source_sha256':grant['sha256'],'build_inputs_sha256':build_hash,'features':(['default']if mode=='default'else[]),'backend':None,'host':recipe['host'],'target':recipe['target'],'consumer':{'name':client,'build_inputs_sha256':build_hash,'executable_sha256':binary_sha},'objects':artifacts},'executable':{'length':str(binary_len),'sha256':binary_sha},'artifacts':artifacts,'measurement_usage':{'attempts':str(len(artifacts)+1),'reserved_bytes':str(total+binary_len+len(artifacts)+1),'bytes_returned':str(total+binary_len),'bytes_hashed':str(total+binary_len),'read_calls':str(nreads)}}
       (project/'independent-measurement.json').write_bytes(canonical(expected_measure));binary(stem+'/'+client+'-bound',exe,[str(corpus),str(project/'independent-measurement.json'),str(project/'actual-measurement.json')],t,target)
       write(project/'selected-source-build-relation.json',{'source_members_frozen_before_build':selected,'consumer_source_inventory_sha256':pre_source,'actual_compiler_target':emitted[0]['target'],'actual_consumer_argv':[str(exe),str(corpus)],'fixture_manifest':str(selected_files['client-fixture-manifest']),'scope':'separate actual host consumer binding; receipt importer assertions do not rebind the imported producer'})
       write(project/'executed-binding.json',{'binary':str(exe),'sha256':binary_sha,'metadata_sha256':p.sha(project/'metadata.json'),'source_inventory_sha256':grant['sha256'],'archive_sha256':p.sha(archive),'build_inputs_sha256':build_hash,'generated_measurement_sha256':p.sha(project/'actual-measurement.json')})
  p.verify_original(grant);write(out/'toolchains.json',toolrecords);write(out/'results.json',{'required':required,'results':results,'status':'PASS','resources':'All bounded command process groups and pipes retired by common.run; caller owns retained files.'})
 except Exception as e:
  write(out/'results.json',{'required':required,'results':results,'status':'FAIL','exception':repr(e)});raise
if __name__=='__main__':main()
