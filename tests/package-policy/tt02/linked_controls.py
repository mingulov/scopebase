#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual same-version A/B and admitted SB02 feature-subject binding controls.

Every Cargo process owns the shared host slot separately. No dependency changes,
network, publication, fake package metadata or copied executable identities.
"""
from __future__ import annotations
import argparse,copy,hashlib,json,os,pathlib,shutil,sys
ROOT=pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools/build'));import common as p
sys.path.insert(0,str(ROOT/'tools/qualification'));import bind_consumer as binder
sys.path.insert(0,str(ROOT/'tests/package-policy/tt02'));import execute as delivery

def write(pth,v):pth.write_bytes(json.dumps(v,sort_keys=True,indent=2).encode()+b'\n')
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);ap.add_argument('--matrix',required=True);ap.add_argument('--config',required=True);ap.add_argument('--build-wrapper',required=True);a=ap.parse_args();out=pathlib.Path(a.output).resolve();out.mkdir(mode=0o700);matrix=pathlib.Path(a.matrix).resolve();config=pathlib.Path(a.config).resolve();wrapper=pathlib.Path(a.build_wrapper).resolve();assert p.sha(wrapper)=='f112693933f18ae8483a52aa9811a0df54e5366505ba48a19b720a8a2b8e5f6f'
 tool=pathlib.Path('/home/user/.rustup/toolchains/1.88.0-x86_64-unknown-linux-gnu/bin');target=out/'target';(out/'tmp').mkdir();(out/'cargo-home').mkdir();results=[];counter=0
 env={'PATH':str(tool)+':/usr/bin:/bin','HOME':os.environ['HOME'],'CARGO_HOME':str(out/'cargo-home'),'CARGO_TARGET_DIR':str(target),'RUSTC':str(tool/'rustc'),'RUSTDOC':str(tool/'rustdoc'),'CARGO_NET_OFFLINE':'true','CARGO_BUILD_JOBS':'2','TMPDIR':str(out/'tmp'),'LC_ALL':'C.UTF-8'}
 allowed={(r['name'],r['version'],r['source']):r for r in json.loads((ROOT/'tests/package-policy/tt02/member.json').read_bytes())['allowed_dependencies']}
 def run(name,argv,expect=0):
  nonlocal counter
  counter+=1;r=p.run(argv,out,env,out/f'command-{counter:03d}',timeout=600);results.append({'id':name,**r})
  if r['exit_code']!=expect or r['reason_code'] or r['cleanup']!='complete':raise RuntimeError((name,r))
  return r
 def cargo(name,manifest,args):return run(name,[wrapper,'--',tool/'cargo','--config',config,*args,'--manifest-path',manifest])
 def package(source,name):
  cargo(name+'/lock',source/'Cargo.toml',['generate-lockfile','--offline']);listing=cargo(name+'/list',source/'Cargo.toml',['package','--list','--offline','--locked','--allow-dirty']);cargo(name+'/package',source/'Cargo.toml',['package','--no-verify','--offline','--locked','--allow-dirty'])
  import tomllib
  spec=tomllib.loads((source/'Cargo.toml').read_text())['package'];archive=target/'package'/(spec['name']+'-'+spec['version']+'.crate');retained=out/(name+'.crate');shutil.copy(archive,retained);unpacked=p.safe_unpack(retained,out/(name+'-archive'),spec['name']+'-'+spec['version']);(out/(name+'-archive')/'Cargo.toml').write_text('[workspace]\nresolver="2"\nmembers=["'+spec['name']+'-'+spec['version']+'"]\n');write(out/(name+'-archive.json'),{'sha256':p.sha(retained),'files':p.stdout(listing).splitlines(),'actual':p.tree_records(unpacked)})
  return retained,unpacked
 def build(subject,archive,grant,name,features,client_source):
  project=out/'clients'/name;(project/'src').mkdir(parents=True);(project/'src/main.rs').write_text(client_source);dep=grant['name']
  (project/'Cargo.toml').write_text('[workspace]\n[package]\nname="'+name+'"\nversion="0.1.0"\nedition="2021"\n[dependencies]\n'+dep+'={path='+json.dumps(str(subject))+',default-features=false,features='+json.dumps(features)+'}\n')
  cargo(name+'/lock',project/'Cargo.toml',['generate-lockfile','--offline']);meta=cargo(name+'/metadata',project/'Cargo.toml',['metadata','--offline','--locked','--format-version','1','--filter-platform','x86_64-unknown-linux-gnu']);metadata=json.loads(p.stdout(meta));write(project/'metadata.json',metadata)
  nodes={n['id']:n for n in metadata['resolve']['nodes']};records=[];sources={}
  for package in metadata['packages']:
   if package['id']not in nodes or package['name']==name:continue
   if package['name']==dep:src=grant['source_id'];sha=grant['sha256']
   else:
    r=allowed[(package['name'],package['version'],package['source'])];src=package['source'];sha=r['sha256']
   sources[package['id']]={'source':src,'source_sha256':sha};records.append({'name':package['name'],'version':package['version'],'source':src,'source_sha256':sha,'features':sorted(nodes[package['id']]['features'])})
  pre_source=p.fixture_digest(project/'src');subject_record={'name':dep,'version':'0.1.0','source':grant['source_id'],'source_sha256':grant['sha256'],'features':features}
  if dep=='scopebase-testkit':expected_records=delivery.expected_packages(json.loads((ROOT/'tests/package-policy/tt02/member.json').read_bytes()),grant,features)
  else:
   selected={'itoa':[],'memchr':['alloc','std'],'serde':['std'],'serde_core':['result','std'],'serde_json':['std'],'zmij':[]}if features else{}
   expected_records=[subject_record]+[{'name':r['name'],'version':r['version'],'source':r['source'],'source_sha256':r['sha256'],'features':selected[r['name']]}for r in allowed.values()if r['name']in selected];expected_records.sort(key=lambda r:(r['name'],r['version'],r['source']))
  recipe={'schema_version':1,'subject':{'name':dep,'version':'0.1.0','source_sha256':grant['sha256'],'archive_sha256':p.sha(archive)},'generated_lock_sha256':p.sha(project/'Cargo.lock'),'resolved_packages':expected_records,'backend':None,'host':'x86_64-unknown-linux-gnu','target':'x86_64-unknown-linux-gnu','compiler':{n+'_sha256':p.sha(tool/n)for n in ['rustc','cargo','rustdoc']},'compiler_arguments':[],'linker_arguments':[],'consumer_source_inventory_sha256':pre_source}
  artifacts,files=delivery.selected_sources(project,subject/'tests/fixtures/harness',archive,'tt02-run')if dep=='scopebase-testkit'else([{'id':'subject-archive','revision':1,'role':'subject_archive','length':str(archive.stat().st_size),'sha256':p.sha(archive)}],{'subject-archive':archive})
  expected={'schema_version':1,'kind':'tt02-expected-consumer','build_inputs':recipe,'consumer_name':name,'features':features,'artifacts':artifacts};write(project/'expected-input.json',expected)
  built=cargo(name+'/build',project/'Cargo.toml',['build','--offline','--locked','--message-format=json']);emitted=[json.loads(line)for line in p.stdout(built).splitlines()if line.strip()];emitted=[v for v in emitted if v.get('reason')=='compiler-artifact'and v.get('executable')and v['target']['name']==name]
  if len(emitted)!=1:raise ValueError('actual compiler artifact cardinality')
  assert p.fixture_digest(project/'src')==pre_source and all(p.sha(files[a['id']])==a['sha256']for a in artifacts),'frozen source/fixture changed during build'
  exe=pathlib.Path(emitted[0]['executable']);write(project/'cargo-build-artifact.json',emitted[0])
  record={'schema_version':1,'kind':'tt02-admitted-build','build_inputs':dict(recipe,resolved_packages=sorted(records,key=lambda r:(r['name'],r['version'],r['source']))),'source_mapping':{'name':dep,'version':'0.1.0','original_source_sha256':grant['sha256'],'archive_sha256':p.sha(archive),'resolved_manifest_path':str(subject/'Cargo.toml')},'package_sources':sources,'artifact_files':{i:str(f)for i,f in files.items()},'executable_length':str(exe.stat().st_size),'consumer_name':name,'build_artifact':{'package_id':emitted[0]['package_id'],'target_name':name,'executable':str(exe),'sha256':p.sha(exe)}}
  for f,v in [('build-record.json',record)]:write(project/f,v)
  binder.main(['--expected',str(project/'expected-input.json'),'--build-record',str(project/'build-record.json'),'--metadata',str(project/'metadata.json'),'--executable',str(exe),'--output',str(project/'measurement.json')])
  # Hashlib independently builds the expected measurement; no production output copy.
  n=exe.stat().st_size;total=sum(int(a['length'])for a in artifacts);bh=hashlib.sha256(canonical(recipe)).hexdigest();usage={'attempts':str(len(artifacts)+1),'reserved_bytes':str(total+n+len(artifacts)+1),'bytes_returned':str(total+n),'bytes_hashed':str(total+n),'read_calls':str(sum((int(a['length'])+65535)//65536+1 for a in artifacts)+(n+65535)//65536+1)}
  literal={'schema_version':1,'kind':'tt02-generated-measurement','build_inputs_sha256':bh,'input_sha256':{k:p.sha(project/f)for k,f in [('expected','expected-input.json'),('build_record','build-record.json'),('metadata','metadata.json')]},'subject':{'package_name':dep,'package_version':'0.1.0','source_sha256':grant['sha256'],'build_inputs_sha256':bh,'features':features,'backend':None,'host':recipe['host'],'target':recipe['target'],'consumer':{'name':name,'build_inputs_sha256':bh,'executable_sha256':p.sha(exe)},'objects':artifacts},'executable':{'length':str(n),'sha256':p.sha(exe)},'artifacts':artifacts,'measurement_usage':usage}
  (project/'independent.json').write_bytes(canonical(literal));assert (project/'independent.json').read_bytes()==(project/'measurement.json').read_bytes(),'independent expected measurement'
  return project,exe,expected,record,metadata
 try:
  # A comes from actual final matrix: frozen input/build records and emitted exe.
  abase=matrix/'clients/source/1.88.0/minimal/tt02-run';A=json.loads((abase/'expected-input.json').read_bytes());a_record=json.loads((abase/'build-record.json').read_bytes());a_meta=json.loads((abase/'metadata.json').read_bytes());binder.bind(A,a_record,a_meta,pathlib.Path(a_record['build_artifact']['executable']))
  (out/'Cargo.toml').write_text('[workspace]\nresolver="2"\nmembers=["B-source"]\n');bsource=out/'B-source';assert p.original_grant(ROOT/'crates/scopebase-testkit','fixture:tt02',[])['sha256']==A['build_inputs']['subject']['source_sha256'];p.source_copy(ROOT/'crates/scopebase-testkit',bsource);s=(bsource/'src/artifact.rs').read_text();before='Self(Sha256::digest(b).into())';after='Self(Sha256::digest(std::hint::black_box(b)).into())';assert s.count(before)==1;(bsource/'src/artifact.rs').write_text(s.replace(before,after));grant=p.original_grant(bsource,'fixture:scopebase-testkit',[]);grant['name']='scopebase-testkit';grant['source_id']='fixture:tt02';archive,unpacked=package(bsource,'B');write(out/'B-mutation.json',{'source':'src/artifact.rs','before':before,'after':after,'sha256':p.sha(bsource/'src/artifact.rs'),'original_inventory_sha256':grant['sha256'],'A_source_sha256':A['build_inputs']['subject']['source_sha256'],'archive_sha256':p.sha(archive)})
  for kind,subject in [('source',bsource),('archive',unpacked)]:
   project,exe,B,record,metadata=build(subject,archive,grant,'tt02-run',[],(abase/'src/main.rs').read_text()) if kind=='source' else build(subject,archive,grant,'tt02-run-archive',[],(abase/'src/main.rs').read_text())
   corpus=subject/'tests/fixtures/harness';run(kind+'/B-ordinary-positive',[exe,str(corpus)]);run(kind+'/B-bound-restored',[exe,str(corpus),project/'independent.json',project/'measurement.json'])
   other=matrix/'clients/source/1.88.0/minimal/tt02-receipt/src/main.rs'
   for identity in ['client-case-source','client-oracle-source']:
    bad=copy.deepcopy(B);selected=next(a for a in bad['artifacts']if a['id']==identity);selected.update(length=str(other.stat().st_size),sha256=p.sha(other));wrong=copy.deepcopy(record);wrong['artifact_files'][identity]=str(other)
    try:binder.bind(bad,wrong,metadata,exe)
    except binder.BindingError as e:
     if 'selected source-to-build'not in str(e):raise
     results.append({'id':kind+'/'+identity+'-valid-unused','status':'EXPECTED_REFUSAL','reason':str(e),'actual_selected_sha256':next(a['sha256']for a in B['artifacts']if a['id']==identity),'unused_valid_source_sha256':p.sha(other),'archive_sha256':p.sha(archive),'executable_sha256':p.sha(exe)})
    else:raise AssertionError('unused valid implementation accepted as selected compiled source')
    binder.bind(B,record,metadata,exe);results.append({'id':kind+'/'+identity+'-restored','status':'PASS'})
   frozen=copy.deepcopy(A)
   # Exact A has its actual client identity. Align only the intentional archive
   # consumer label so source/archive mismatches are tested on their own fields.
   if kind=='archive':frozen['consumer_name']=B['consumer_name']
   try:binder.bind(frozen,record,metadata,exe)
   except binder.BindingError as e:
    if 'SubjectMismatch: build inputs'not in str(e):raise
    results.append({'id':kind+'/A-contract-B-build','status':'EXPECTED_REFUSAL','reason':str(e)})
   else:raise AssertionError('B actual build accepted under frozen A')
   r=run(kind+'/A-measurement-B-executable',[exe,str(corpus),abase/'independent-measurement.json',project/'measurement.json'],101)
   if 'actual consumer build/executable binding'not in pathlib.Path(r['logs']['stderr']['path']).read_text():raise AssertionError('wrong negative assertion')
  fsource=out/'feature-source';p.source_copy(ROOT/'tests/package-policy/fixtures/feature_subject',fsource);fgrant=p.original_grant(fsource,'fixture:sb02-feature-subject',[]);fgrant['name']='sb02-feature-subject';fgrant['source_id']='fixture:sb02-feature-subject';farchive,funpacked=package(fsource,'feature');feature=[]
  for kind,subject in [('source',fsource),('archive',funpacked)]:
   for fs in [[],['json']]:
    mode='json'if fs else'minimal';name='feature-'+kind+'-'+mode;src='fn main(){assert_eq!(sb02_feature_subject::decimal_len(10),2);'+('assert_eq!(sb02_feature_subject::parse_u64("42").unwrap(),42);'if fs else'')+'}\n';project,exe,expected,record,metadata=build(subject,farchive,fgrant,name,fs,src);run(name+'/positive',[exe]);feature.append((kind,fs,expected,record,metadata,exe))
  for kind in ['source','archive']:
   small=next(x for x in feature if x[0]==kind and not x[1]);full=next(x for x in feature if x[0]==kind and x[1]);expected=copy.deepcopy(full[2]);expected['features']=[]
   try:binder.bind(expected,full[3],full[4],full[5])
   except binder.BindingError as e:
    if 'subject features'not in str(e):raise
    results.append({'id':kind+'/frozen-minimal-actual-json','status':'EXPECTED_REFUSAL','reason':str(e),'minimal_executable_sha256':p.sha(small[5]),'json_executable_sha256':p.sha(full[5])})
   else:raise AssertionError('actual json features accepted as minimal')
   binder.bind(full[2],full[3],full[4],full[5]);results.append({'id':kind+'/restored-json-binding','status':'PASS'})
  write(out/'results.json',{'status':'PASS','results':results,'resources':'All child process groups/pipes retired; files intentionally retained. No native object/load/privileged capability claim.'})
 except Exception as e:write(out/'results.json',{'status':'FAIL','results':results,'exception':repr(e)});raise
if __name__=='__main__':main()
