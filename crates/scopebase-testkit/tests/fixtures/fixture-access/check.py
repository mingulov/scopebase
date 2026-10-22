#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Delivered external FixtureAccess checks; Python stdlib, explicit offline inputs."""
import argparse, json, pathlib, shutil, time, tomllib
from bounded_process import sha as digest, run as run_command, stdout, rust_refusal

def write(p,v): pathlib.Path(p).write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--toolchain-root',required=True,type=pathlib.Path)
 ap.add_argument('--cargo-home',required=True,type=pathlib.Path)
 ap.add_argument('--output',required=True,type=pathlib.Path)
 ap.add_argument('--feature',choices=['default','no-default'],required=True)
 ap.add_argument('--build-wrapper',type=pathlib.Path)
 ap.add_argument('--lock-file',type=pathlib.Path)
 ap.add_argument('--reference-lock',type=pathlib.Path)
 ap.add_argument('--expect-local-array-rejection',action='store_true',help='Maintainer-only old-signature control; never positive qualification')
 a=ap.parse_args(); fixture=pathlib.Path(__file__).resolve().parent; subject=fixture.parents[2]
 tc=a.toolchain_root.resolve(strict=True); cache=a.cargo_home.resolve(strict=True); out=a.output.resolve()
 if not a.toolchain_root.is_absolute() or not a.cargo_home.is_absolute() or not a.output.is_absolute(): raise ValueError('absolute roots required')
 if out.is_relative_to(subject): raise ValueError('output must be outside package')
 if a.build_wrapper is not None and not a.build_wrapper.is_absolute():raise ValueError('absolute wrapper required')
 out.mkdir(mode=0o700); (out/'home').mkdir(); (out/'tmp').mkdir(); project=out/'consumer'; (project/'src/bin').mkdir(parents=True)
 tools={name:tc/'bin'/name for name in ['cargo','rustc','rustdoc']}
 for t in tools.values():
  if not t.is_file(): raise ValueError('missing installed tool '+str(t))
 manifest=tomllib.loads((subject/'Cargo.toml').read_text()); pkg=manifest['package']
 if pkg['name']!='scopebase-testkit' or pkg['version']!='0.1.0':raise ValueError('unexpected subject')
 subject_manifest_sha256=digest(subject/'Cargo.toml')
 (project/'Cargo.toml').write_text('[workspace]\n[package]\nname="scopebase-fixture-access-check"\nversion="0.0.0"\nedition="2021"\nrust-version="1.88.0"\npublish=false\n[dependencies]\nscopebase-testkit={path='+json.dumps(str(subject))+',version="=0.1.0",default-features='+('true' if a.feature=='default' else 'false')+'}\n')
 for n in ['local_arrays','retained_arrays','dangling_owner','dangling_bytes']:shutil.copyfile(fixture/(n+'.rs'),project/'src/bin'/(n+'.rs'))
 env={'PATH':str(tc/'bin')+':/usr/bin:/bin','HOME':str(out/'home'),'TMPDIR':str(out/'tmp'),'CARGO_HOME':str(cache),'CARGO_TARGET_DIR':str(out/'target'),'CARGO_NET_OFFLINE':'true','CARGO_BUILD_JOBS':'2','RUSTC':str(tools['rustc']),'RUSTDOC':str(tools['rustdoc']),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
 records=[]; binding={}; counter=0; deadline=time.monotonic()+7200
 def checkpoint(status,error=None):write(out/'results.json',{'status':status,'scope':'old-signature semantic refusal control' if a.expect_local_array_rejection else 'public FixtureAccess downstream borrowing checks','subject':str(subject),'subject_manifest_sha256':subject_manifest_sha256,'feature':a.feature,'binding':binding,'records':records,'failure':error})
 def run(name,args,expected=0):
  nonlocal counter
  remaining=deadline-time.monotonic()
  if remaining<=0:raise RuntimeError('aggregate check time bound exhausted before launch')
  counter+=1; argv=([str(a.build_wrapper),'--timeout','1800','--'] if a.build_wrapper else [])+list(map(str,args))
  # Reserve before launch. The extracted runner retains every post-launch
  # collection/wait/group/close/stat/hash error in this row before refusal.
  record={'id':name,'command':argv,'cwd':str(project),'exit_code':None,'reason_code':None,'cleanup':'not_started','process_group':None,'logs':{},'errors':[]}
  records.append(record);checkpoint('IN_PROGRESS')
  try:record.update(run_command(argv,project,env,out/f'{counter:03d}-{name}',timeout=min(2400,remaining)))
  except BaseException as error:
   record['reason_code']='SETUP_FAILURE';record['errors'].append({'stage':'setup','exception':type(error).__name__,'message':str(error)[:512]});checkpoint('FAIL');raise
  checkpoint('IN_PROGRESS')
  if record['reason_code'] is not None or record['cleanup']!='complete' or record['exit_code']!=expected:raise RuntimeError(record)
  return stdout(record)
 try:
  binding['tools']={n:{'path':str(t),'sha256':digest(t),'version':run('identity-'+n,[t,'-Vv'])} for n,t in tools.items()}
  if a.lock_file:shutil.copyfile(a.lock_file,project/'Cargo.lock')
  else:run('lock',[tools['cargo'],'generate-lockfile','--offline'])
  binding['consumer_manifest_sha256']=digest(project/'Cargo.toml');binding['lock_sha256']=digest(project/'Cargo.lock')
  reference=a.reference_lock
  if reference is None:
   reference=next((p/'Cargo.lock' for p in [subject,*subject.parents[:3]] if (p/'Cargo.lock').is_file()),None)
  if reference is None:raise ValueError('supply a pinned --reference-lock')
  reference=reference.resolve(strict=True);approved={(p['name'],p['version'],p.get('source')):p['checksum'] for p in tomllib.loads(reference.read_text())['package'] if 'source'in p}
  binding['reference_lock']={'path':str(reference),'sha256':digest(reference)}
  resolved=tomllib.loads((project/'Cargo.lock').read_text())['package']
  registry=[p for p in resolved if 'source'in p]
  for p in registry:
   if approved.get((p['name'],p['version'],p['source']))!=p['checksum']:raise ValueError('unbound registry package '+p['name'])
  binding['registry']=registry
  md=json.loads(run('metadata',[tools['cargo'],'metadata','--offline','--locked','--format-version','1']))
  found=[p for p in md['packages'] if p['name']=='scopebase-testkit'];assert len(found)==1
  assert pathlib.Path(found[0]['manifest_path'])==subject/'Cargo.toml' and found[0]['version']=='0.1.0'
  node=next(n for n in md['resolve']['nodes'] if n['id']==found[0]['id']);assert node['features']==(['default'] if a.feature=='default' else [])
  binding['metadata']=md;binding['fixture_sources']={n:digest(fixture/(n+'.rs')) for n in ['local_arrays','retained_arrays','dangling_owner','dangling_bytes']}
  cases=['retained_arrays','local_arrays'] if a.expect_local_array_rejection else ['retained_arrays','local_arrays','dangling_owner','dangling_bytes']
  for case in cases:
   refusal=case.startswith('dangling') or (a.expect_local_array_rejection and case=='local_arrays')
   output=run('build-'+case,[tools['cargo'],'build','--offline','--locked','--bin',case,'--message-format=json'],101 if refusal else 0)
   messages=[json.loads(s) for s in output.splitlines() if s.strip()]
   errors=[m['message'] for m in messages if m.get('reason')=='compiler-message' and m['message']['level']=='error']
   if refusal:
    expected={'cannot return value referencing local variable `'+n+'`' for n in (['inputs','resources'] if case=='local_arrays' else ['owner' if case=='dangling_owner' else 'bytes'])}
    assert {e['message'] for e in errors}==expected and len(errors)==len(expected)
    source_file=project/f'src/bin/{case}.rs'
    return_literal='    FixtureAccess::new(&inputs, &resources, EffectBatch::empty(&limits), &limits)'
    return_lines=[n for n,line in enumerate(source_file.read_text().splitlines(),1) if line==return_literal]
    assert len(return_lines)==1
    primary=(f'src/bin/{case}.rs',return_lines[0])
    assert all((e.get('code') or {}).get('code')=='E0515' and rust_refusal(output,'E0515',e['message'],project,expected_primary=primary) for e in errors)
    binding.setdefault('semantic_refusals',{})[case]={'expected_primary':list(primary),'source_line':return_literal,'messages':sorted(expected),'source_sha256':digest(source_file)}
    write(out/(case+'-diagnostics.json'),errors)
   else:
    assert not errors;artifacts=[m for m in messages if m.get('reason')=='compiler-artifact' and m.get('executable') and m['target']['name']==case];assert len(artifacts)==1
    exe=pathlib.Path(artifacts[0]['executable']);before=digest(exe);text=run('execute-'+case,[exe]);assert 'PASS: actual input bytes' in text and digest(exe)==before
    binding.setdefault('executables',{})[case]={'path':str(exe),'sha256':before,'cargo_artifact':artifacts[0]}
   assert digest(project/'Cargo.lock')==binding['lock_sha256']
  checkpoint('CONTROL_PASS' if a.expect_local_array_rejection else 'PASS')
 except BaseException as error:checkpoint('FAIL',{'exception':type(error).__name__,'message':str(error)[:1024]});raise
if __name__=='__main__':main()
