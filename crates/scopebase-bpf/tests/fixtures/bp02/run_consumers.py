#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""BP02's two downstream consumers; explicit tools/cache, package-contained inputs."""
import argparse,hashlib,json,os,shutil,subprocess,tomllib
from pathlib import Path

def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def arguments():
    p=argparse.ArgumentParser();p.add_argument('--package',required=True,type=Path);p.add_argument('--out',required=True,type=Path);p.add_argument('--toolchain',required=True,choices=['1.88.0','1.98.1']);p.add_argument('--toolchain-root',type=Path);p.add_argument('--cargo-home',type=Path);p.add_argument('--build-wrapper',type=Path);p.add_argument('--native',action='store_true');p.add_argument('--prebuilt',type=Path);return p

def inspect(package):
    p=package/'Cargo.toml';d=tomllib.loads(p.read_text());assert d['package']['name']=='scopebase-bpf' and d['package']['version']=='0.1.0';assert d['features']=={'default':[]}
    expected={'rustix':('=1.1.5',{'std','fs','process','thread','linux_4_11'}),'libc':('=0.2.191',{'std'}),'sha2':('=0.11.0',set())}
    targets=d.get('target',{});assert len(targets)==1
    edges=next(iter(targets.values()))['dependencies'];assert set(edges)==set(expected)
    for n,(v,features) in expected.items():assert edges[n]['version']==v and edges[n]['default-features'] is False and set(edges[n].get('features',[]))==features
    tests={x['name']:x['path'] for x in d.get('test',[])};examples={x['name']:x['path'] for x in d.get('example',[])}
    assert set(tests)=={'api_contract','maps_pure','maps_contract','maps_live','maps_mounts','who_preservation'}
    assert set(examples)=={'possible_topology','who_map_reader','bp02_live_fixture'}
    for rel in [*tests.values(),*examples.values()]:assert (package/rel).is_file() and '..' not in Path(rel).parts
    # Cargo omits nested packages; delivered manifests are inert .in files
    # until materialized in an independently owned downstream project.
    for name in ['topology-cli','who-reader']:
        template=package/'tests/consumers'/name/'Cargo.toml.in';assert template.is_file() and (template.parent/'src/main.rs').is_file(),('missing delivered client template',name)
        text=template.read_text();assert '@SUBJECT@' in text and '@DEFAULT@' in text
        parsed=tomllib.loads(text.replace('@SUBJECT@','/selected-subject').replace('@DEFAULT@','false'));assert parsed['package']['name']=='bp02-'+name and parsed['bin']==[{'name':'bp02-'+name,'path':'src/main.rs'}]
    for rel in ['tests/fixtures/bp02/btf-u32-u64.bin','tests/fixtures/bp02/who88-two-lanes.bin','tests/fixtures/bp02/kwho-key16.bin','tests/fixtures/bp02/manifest.json','tests/fixtures/bp02/generate_vectors.py','tests/fixtures/bp02/run_consumers.py','tests/fixtures/bp02/run_mutants.py','tests/fixtures/bp02/run_live.py','tests/fixtures/bp02/payload_run.sh','tests/fixtures/bp02/payload_summary.py','tests/support/native_fixture.rs','tests/support/who_fixture.rs']:
        assert (package/rel).is_file(),('missing delivered input',rel)
    assert (package/'tests/support/mount_custody.rs').is_file(),'missing delivered owned-root custody helper'
    evidence={'manifest_sha256':digest(p),'targets':{'test':tests,'example':examples},'dependencies':edges}
    if (package/'Cargo.toml.orig').exists():evidence['original_manifest_sha256']=digest(package/'Cargo.toml.orig')
    return evidence

def run(args,command,cwd,env,rows,name,expected=0):
    actual=([str(args.build_wrapper),'--'] if args.build_wrapper else [])+list(map(str,command));r=subprocess.run(actual,cwd=cwd,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    log=args.out/(name+'.log');log.write_text(r.stdout);rows.append({'command':actual,'cwd':str(cwd),'exit':r.returncode,'log':str(log),'sha256':digest(log)})
    if expected==0 and r.returncode!=0:raise RuntimeError(f'{name} failed: {r.stdout[-3000:]}')
    if expected!=0 and r.returncode==0:raise RuntimeError(f'{name}: expected semantic refusal')
    return r

def main():
    args=arguments().parse_args();args.package=args.package.resolve();args.out=args.out.resolve();assert not args.out.exists();args.out.mkdir(parents=True)
    if args.prebuilt:
        assert args.native,'prebuilt is exclusively actual native execution'
        spec=json.loads(args.prebuilt.read_text());rows=[];receipt={'status':'FAILED','mode':'native-map','input':inspect(args.package),'prebuilt_sha256':digest(args.prebuilt),'bindings':spec['bindings'],'commands':rows,'cells':[]}
        try:
            for mode,row in spec['clients'].items():
                binary=Path(row['path']);assert binary.is_absolute() and digest(binary)==row['sha256'];r=run(args,[binary,args.package/'tests/fixtures/bp02','--native'],args.out,os.environ,rows,mode+'-native');assert r.stdout.strip()=='4242,12,101,0,0,291,4,11,44';receipt['cells'].append({'feature':mode,'client':'who-reader','status':'PASS'})
            assert set(spec['clients'])=={'default','no-default'};receipt['status']='PASS'
        finally:(args.out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        print(json.dumps({'status':receipt['status'],'cells':len(receipt['cells'])}));return
    for p in [args.toolchain_root,args.cargo_home]:assert p and p.is_absolute() and p.is_dir()
    if args.build_wrapper:assert args.build_wrapper.is_absolute() and args.build_wrapper.is_file()
    rows=[];receipt={'status':'FAILED','package':str(args.package),'input':inspect(args.package),'route':str(args.build_wrapper) if args.build_wrapper else 'explicit-direct-children','mode':'native-map' if args.native else 'offline-fixture','commands':rows,'cells':[]}
    tools=args.toolchain_root/'bin';env={**os.environ,'CARGO_HOME':str(args.cargo_home),'RUSTC':str(tools/'rustc'),'RUSTDOC':str(tools/'rustdoc'),'CARGO_NET_OFFLINE':'true'}
    try:
        version=run(args,[tools/'rustc','--version'],args.out,env,rows,'rustc-version').stdout;assert version.startswith('rustc '+args.toolchain+' ')
        receipt['tools']={n:{'path':str(tools/n),'sha256':digest(tools/n)} for n in ['cargo','rustc','rustdoc']}
        for mode in ['default','no-default']:
            for name in ['topology-cli','who-reader']:
                root=args.out/(mode+'-'+name);shutil.copytree(args.package/'tests/consumers'/name,root)
                manifest=root/'Cargo.toml';manifest.write_text((root/'Cargo.toml.in').read_text().replace('@SUBJECT@',str(args.package)).replace('@DEFAULT@','true' if mode=='default' else 'false'))
                if name=='who-reader':
                    for f in ['who_fixture.rs','native_fixture.rs']:shutil.copyfile(args.package/'tests/support'/f,root/'src'/f)
                    # The copied native fixture's literal include remains local.
                    (root/'tests/fixtures/bp02').mkdir(parents=True)
                    shutil.copyfile(args.package/'tests/fixtures/bp02/btf-u32-u64.bin',root/'tests/fixtures/bp02/btf-u32-u64.bin')
                    nf=root/'src/native_fixture.rs';nf.write_text(nf.read_text().replace('../fixtures/bp02/','../tests/fixtures/bp02/'))
                parsed=tomllib.loads(manifest.read_text());edge=parsed['dependencies']['scopebase-bpf'];assert Path(edge['path'])==args.package and edge['version']=='=0.1.0' and edge['default-features']==(mode=='default');assert parsed['bin']==[{'name':'bp02-'+name,'path':'src/main.rs'}];assert set(parsed['dependencies'])==({'scopebase-bpf','libc'} if name=='who-reader' else {'scopebase-bpf'})
                env['CARGO_TARGET_DIR']=str(args.out/'targets'/(mode+'-'+name))
                prefix=mode+'-'+name
                run(args,[tools/'cargo','generate-lockfile','--offline'],root,env,rows,prefix+'-lock')
                meta=json.loads(run(args,[tools/'cargo','metadata','--locked','--offline','--format-version','1'],root,env,rows,prefix+'-metadata').stdout)
                subject=next(p for p in meta['packages'] if p['name']=='scopebase-bpf');assert Path(subject['manifest_path']).resolve()==args.package/'Cargo.toml' and subject['version']=='0.1.0'
                resolved=next(n for n in meta['resolve']['nodes'] if n['id']==subject['id']);assert set(resolved['features'])==({'default'} if mode=='default' else set())
                tree=run(args,[tools/'cargo','tree','--locked','--offline','-e','features'],root,env,rows,prefix+'-features').stdout
                cell={'feature':mode,'client':name,'manifest_sha256':digest(manifest),'lock_sha256':digest(root/'Cargo.lock'),'features':resolved['features'],'tree_sha256':hashlib.sha256(tree.encode()).hexdigest(),'status':'FAILED'}
                if name=='topology-cli':
                    cpus=root/'cpus';cpus.write_text('0,2,7-8\n');r=run(args,[tools/'cargo','run','--locked','--offline','--quiet','--',cpus,'13'],root,env,rows,prefix+'-positive');assert r.stdout.strip()=='[0, 2, 7, 8] 16 64'
                    cpus.write_text('0,0\n');r=run(args,[tools/'cargo','run','--locked','--offline','--quiet','--',cpus,'13'],root,env,rows,prefix+'-negative',1);assert 'Malformed' in r.stdout
                else:
                    fixtures=args.package/'tests/fixtures/bp02';r=run(args,[tools/'cargo','run','--locked','--offline','--quiet','--',fixtures],root,env,rows,prefix+'-positive');assert r.stdout.strip()=='4242,12,101,0,0,291,4,11,44'
                    stale=root/'stale80.bin';stale.write_bytes((fixtures/'who88-two-lanes.bin').read_bytes()[:160]);r=run(args,[tools/'cargo','run','--locked','--offline','--quiet','--',fixtures,stale],root,env,rows,prefix+'-stale80',1);assert 'schema/extent' in r.stdout
                    if args.native:
                        r=run(args,[tools/'cargo','run','--locked','--offline','--quiet','--',fixtures,'--native'],root,env,rows,prefix+'-native');assert r.stdout.strip()=='4242,12,101,0,0,291,4,11,44'
                if name=='who-reader':
                    deps=Path(env['CARGO_TARGET_DIR'])/'debug/deps';rlibs=list(deps.glob('libscopebase_bpf-*.rlib'));assert len(rlibs)==1
                    controls={'maps_positive.rs':None,'maps_topology_authority.rs':'E0308','maps_from_parts.rs':'E0599','maps_from_report.rs':'E0599','maps_custom_reader.rs':'E0599','maps_send.rs':'E0277','maps_sync.rs':'E0277','maps_clone.rs':'E0599','maps_debug.rs':'E0277','maps_mutable_snapshot.rs':'E0308','maps_raw_fd.rs':'E0599'}
                    for file,code in controls.items():
                        command=[tools/'rustc','--edition=2021',args.package/'tests/ui'/file,'--extern','scopebase_bpf='+str(rlibs[0]),'-L','dependency='+str(deps),'-o',root/(file+'.bin')]
                        result=run(args,command,root,env,rows,prefix+'-'+file,1 if code else 0)
                        if code:assert 'error['+code+']' in result.stdout and 'error[E0432]' not in result.stdout and 'error[E0463]' not in result.stdout,(file,'unrelated compile diagnostic')
                cell['status']='PASS';receipt['cells'].append(cell)
        receipt['status']='PASS'
    finally:(args.out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'status':receipt['status'],'cells':len(receipt['cells']),'receipt':str(args.out/'receipt.json')}))
if __name__=='__main__':main()
