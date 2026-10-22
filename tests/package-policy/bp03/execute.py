#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Finite BP03 host-only source/archive campaign. No archive creation or live probe.

All required cells exist before dispatch. Each child uses the shipped bounded
collector and the explicit caller-provided wrapper exactly once. Never resume
into existing evidence. Source review and resource admission precede invocation.
"""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,shutil,tarfile,tomllib
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[3]
RETAINED=['tt01-inventory','tt01-selection','tt02-run','tt02-receipt']
TK_MODES={'default':([],['default'],None),'minimal':(['--no-default-features'],[],None),'core-default':(['--features','bpf-host'],['bpf-host','default'],[]),'core-minimal':(['--no-default-features','--features','bpf-host'],['bpf-host'],[]),'json-union':(['--no-default-features','--features','bpf-host,bpf-host-json'],['bpf-host','bpf-host-json'],['json'])}
BPF_MODES={'default':([],['default'],'core-default'),'no-default':(['--no-default-features'],[],'core-minimal'),'json':(['--no-default-features','--features','json'],['json'],'json-union')}
def load(path):
    spec=importlib.util.spec_from_file_location('bp03_delivery_'+hashlib.sha256(str(path).encode()).hexdigest()[:16],path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def required_rows():
    rows=[]
    for kind in ['source','archive']:
        for compiler in ['1.88.0','1.98.1']:
            for mode in TK_MODES:rows.append(dict(id=f'{kind}/{compiler}/testkit/{mode}',input=kind,compiler=compiler,subsystem='testkit',mode=mode,status='NOT_RUN',retained_clients=list(RETAINED),bp03_clients=['bp03-cache','bp03-populations'] if mode in ['core-default','core-minimal','json-union'] else []))
            for mode in BPF_MODES:rows.append(dict(id=f'{kind}/{compiler}/bpf/{mode}',input=kind,compiler=compiler,subsystem='bpf',mode=mode,status='NOT_RUN',retained_clients=[],bp03_clients=['bp03-cache','bp03-populations'],corresponding_testkit_cell=f'{kind}/{compiler}/testkit/{BPF_MODES[mode][2]}'))
    return rows

def bind_child_invocations(parent,expectations):
    """Bind caller-owned output/kind expectations before any child launch."""
    try:
        static=json.loads((parent.journal.root/'bindings-v2.json').read_bytes())
        if static['bindings'].get('child_invocations')!=expectations:raise ValueError('child expectations differ from presealed static bindings')
        for ident,plan in expectations.items():
            if not isinstance(ident,str) or set(plan)!={'root','kind'} or not isinstance(plan['kind'],str):raise ValueError('typed child invocation expectation')
            path=Path(plan['root'])
            if not path.is_absolute() or '..' in path.parts or any(p.is_symlink() for p in [path,*path.parents]):raise ValueError('unsafe expected child root')
        parent._child_expectations=json.loads(json.dumps(expectations));parent._child_started=set();parent._child_observed={}
    except BaseException as error:raise parent.journal.fail(error)

def start_child(parent,ident):
    try:
        if parent.journal.failed or ident not in parent._child_expectations or ident in parent._child_started:raise ValueError('unbound, failed or duplicate child dispatch')
        parent.journal.sidecar('child-invocation/'+ident,dict(id=ident,expectation=parent._child_expectations[ident]));parent._child_started.add(ident)
    except BaseException as error:raise parent.journal.fail(error)

def accept_child(parent,module,completion,ident):
    actual=None;reference=None
    try:
        if ident not in parent._child_started or ident in parent._child_observed:raise ValueError('unstarted or duplicate child completion')
        actual,reference=parent.child(module,completion,ident);expected=parent._child_expectations[ident]
        if str(completion.root)!=expected['root'] or actual.get('kind')!=expected['kind']:raise ValueError('actual child output/kind differs from prelaunch invocation binding')
        parent._child_observed[ident]=(module,completion,reference);return actual,reference
    except BaseException as error:
        custody=getattr(error,'custody',None)
        if custody is None:custody=dict(expected=parent._child_expectations.get(ident),observed_reference=reference,last_command=(actual.get('commands') or [None])[-1] if actual is not None else None)
        raise parent.journal.fail(error,custody)

def finish_parent(parent,report):
    if report['status']=='PASS':
        if set(parent._child_observed)!=set(parent._child_expectations):raise parent.journal.fail(ValueError('required child invocation denominator incomplete'))
        # Recheck exact immutable child bytes at final parent publication.
        for ident,(module,completion,reference) in parent._child_observed.items():
            actual=module.accept_finalized(completion);expected=parent._child_expectations[ident]
            if str(completion.root)!=expected['root'] or actual.get('kind')!=expected['kind']:raise parent.journal.fail(ValueError('child association changed before parent finalization'))
    return parent.finish(report)

def unpack(archive,destination,package):
    """Validate the entire regular-file population before extracting any bytes."""
    prefix=package+'-0.1.0';destination.mkdir(parents=True,exist_ok=False)
    with tarfile.open(archive,'r:gz') as tar:
        members=[];names=set();total=0
        for member in tar:
            if len(members)>=10000:raise ValueError('archive member bound')
            path=Path(member.name);normalized=path.as_posix()
            if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0]!=prefix or not (member.isfile() or member.isdir()) or normalized in names or member.name.rstrip('/')!=normalized:raise ValueError('unsafe or duplicate archive member')
            names.add(normalized);total+=member.size
            if total>256*1024*1024:raise ValueError('archive byte bound')
            members.append(member)
        for member in members:
            target=destination/member.name
            if member.isdir():target.mkdir(parents=True,exist_ok=True)
            else:
                target.parent.mkdir(parents=True,exist_ok=True)
                with tar.extractfile(member) as source,target.open('xb') as output:shutil.copyfileobj(source,output)
    root=destination/prefix
    if not (root/'Cargo.toml').is_file() or not (root/'Cargo.toml.orig').is_file():raise ValueError('normalized archive manifest evidence required')
    return root

def archive_mapping(helper,source,archive,root):
    original=helper.inventory(source);packed=helper.inventory(root)
    for name,record in packed.items():
        if name in {'Cargo.toml','Cargo.lock','.cargo_vcs_info.json','Cargo.toml.orig'}:continue
        if original.get(name)!=record:raise ValueError('archive/source file mismatch '+name)
    if (root/'Cargo.toml.orig').read_bytes()!=(source/'Cargo.toml').read_bytes():raise ValueError('archive original manifest differs')
    # Every manifest-selected source/fixture path must be present. Cargo's own
    # explicit include list is also recorded from the normalized archive.
    manifest=tomllib.loads((root/'Cargo.toml').read_text())
    for record in manifest.get('test',[])+manifest.get('example',[]):
        if record['path'] not in packed:raise ValueError('archive omitted registered target '+record['path'])
    return dict(archive=dict(path=str(archive),sha256=helper.sha(archive)),source_inventory_sha256=helper.hashed(original),archive_inventory=packed,archive_inventory_sha256=helper.hashed(packed),normalized_manifest_sha256=helper.sha(root/'Cargo.toml'),original_manifest_sha256=helper.sha(root/'Cargo.toml.orig'),include=manifest['package']['include'])

def target_projection(metadata,root):
    manifest=tomllib.loads((root/'Cargo.toml').read_text());package=next(p for p in metadata['packages'] if Path(p['manifest_path']).resolve()==root/'Cargo.toml')
    expected={}
    for kind,folder,enabled in [('test','tests',manifest['package'].get('autotests',True)),('example','examples',manifest['package'].get('autoexamples',True))]:
        if enabled:
            for path in (root/folder).glob('*.rs'):expected[(kind,path.stem)]=(path,[])
        expected.update({(kind,row['name']):(root/row['path'],row.get('required-features',[])) for row in manifest.get(kind,[])})
    actual={(target['kind'][0],target['name']):(Path(target['src_path']),target.get('required-features',[])) for target in package['targets'] if target['kind'][0] in ['test','example']}
    if actual!=expected:raise ValueError('actual Cargo registered target projection differs')
    if any(t['kind']==['custom-build'] for t in package['targets']):raise ValueError('unexpected build script')
    return dict(package_id=package['id'],targets=package['targets'])

def isolated_graph(helper,metadata,bpf,testkit,mode):
    nodes={node['id']:node for node in metadata['resolve']['nodes']};tk=next(p for p in metadata['packages'] if p['name']=='scopebase-testkit' and p['id'] in nodes)
    if Path(tk['manifest_path']).resolve()!=testkit/'Cargo.toml' or nodes[tk['id']]['features']!=TK_MODES[mode][1]:raise ValueError('isolated testkit identity/features')
    expected=TK_MODES[mode][2];bp=[p for p in metadata['packages'] if p['name']=='scopebase-bpf' and p['id'] in nodes]
    if expected is None:
        if bp:raise ValueError('baseline graph has BPF node')
        return dict(testkit_package_id=tk['id'],testkit_features=nodes[tk['id']]['features'],bpf=None)
    if len(bp)!=1 or Path(bp[0]['manifest_path']).resolve()!=bpf/'Cargo.toml' or nodes[bp[0]['id']]['features']!=expected:raise ValueError('isolated BPF identity/features')
    if [d['pkg'] for d in nodes[tk['id']]['deps'] if d['name']=='scopebase_bpf']!=[bp[0]['id']]:raise ValueError('isolated adapter edge')
    return dict(testkit_package_id=tk['id'],testkit_features=nodes[tk['id']]['features'],bpf=dict(package_id=bp[0]['id'],features=nodes[bp[0]['id']]['features']))

def retained_client(helper,run,bpf,testkit,mode,name):
    project=run.out/'retained-clients'/name;(project/'src').mkdir(parents=True);source=ROOT/'tests/package-policy/fixtures/clients'/(name+'.rs');shutil.copyfile(source,project/'src/main.rs');default=mode in ['default','core-default'];features=[] if mode in ['default','minimal'] else ['bpf-host','bpf-host-json'] if mode=='json-union' else ['bpf-host']
    (project/'Cargo.toml').write_text('[workspace]\n[package]\nname="scopebase-client"\nversion="0.1.0"\nedition="2021"\n[dependencies]\nscopebase-testkit={version="=0.1.0",path='+json.dumps(str(testkit))+',default-features='+str(default).lower()+',features='+json.dumps(features)+'}\n[patch.crates-io]\nscopebase-bpf={path='+json.dumps(str(bpf))+'}\n')
    row=dict(client=name,mode=mode,status='NOT_RUN');run.report['clients'].append(row);run.checkpoint()
    target=project/'target';run.cargo(name+'-lock',['generate-lockfile','--offline'],project,target);_,text=run.cargo(name+'-metadata',['metadata','--offline','--locked','--format-version','1','--filter-platform','x86_64-unknown-linux-gnu'],project,target);metadata=json.loads(text);binding=isolated_graph(helper,metadata,bpf,testkit,mode);helper.atomic_json(project/'metadata.json',metadata);before=helper.inventory(project/'src');_,text=run.cargo(name+'-build',['build','--offline','--locked','--message-format=json'],project,target)
    if helper.inventory(project/'src')!=before or helper.sha(source)!=helper.sha(project/'src/main.rs'):raise ValueError('retained client source changed')
    artifacts=[json.loads(line) for line in text.splitlines() if line.strip()];actual=[v for v in artifacts if v.get('reason')=='compiler-artifact' and v.get('executable') and v['target']['name']=='scopebase-client']
    if len(actual)!=1:raise ValueError('actual retained consumer executable required')
    binary=Path(actual[0]['executable']);digest=helper.sha(binary);argv=[binary]+([testkit/'tests/fixtures/harness'] if name.startswith('tt02') else []);_,output=run.command(name+'-run',argv,project,target)
    if helper.sha(binary)!=digest:raise ValueError('retained consumer executable changed')
    row.update(status='PASS',binding=binding,source_sha256=helper.sha(source),metadata_sha256=helper.sha(project/'metadata.json'),manifest_sha256=helper.sha(project/'Cargo.toml'),lock_sha256=helper.sha(project/'Cargo.lock'),binary=dict(path=str(binary),sha256=digest),output_sha256=hashlib.sha256(output.encode()).hexdigest());run.checkpoint();return row

def parser():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['source-bpf','source-testkit','bpf-archive','testkit-archive','output','config','cargo-home','build-wrapper']:p.add_argument('--'+name,required=True,type=Path)
    p.add_argument('--toolchain-root',required=True,action='append',metavar='VERSION=ABS_ROOT');return p

def bindings(args):
    result={}
    for value in args.toolchain_root:
        version,separator,path=value.partition('=')
        if not separator or version in result or version not in ['1.88.0','1.98.1'] or not Path(path).is_absolute():raise ValueError('two exact version to absolute toolchain-root bindings required')
        result[version]=Path(path)
    if set(result)!={'1.88.0','1.98.1'}:raise ValueError('both compiler bindings required')
    return result

def run_cell(helper,args,tools,row,inputs):
    out=args.output/'cells'/row['id'];bound=SimpleNamespace(out=out,cargo_config=args.config,cargo_home=args.cargo_home,toolchain_root=tools[row['compiler']],toolchain=row['compiler'],build_wrapper=args.build_wrapper);run=helper.Run(bound,'BP03_HOST_LIBRARY_CELL')
    try:
        pair=helper.stage_pair(run,*inputs[row['input']]);bpf=pair['scopebase-bpf'];testkit=pair['scopebase-testkit'];run.report['manifests']=helper.inspect_packages(bpf,testkit);root=bpf if row['subsystem']=='bpf' else testkit
        # Isolate workspace membership as well as the manifest's actual graph.
        (root.parent/'Cargo.toml').write_text('[workspace]\nresolver="2"\nmembers=['+json.dumps(root.name)+']\nexclude=['+json.dumps(testkit.name if root==bpf else bpf.name)+']\n[patch.crates-io]\nscopebase-bpf={path="scopebase-bpf"}\n')
        run.report['stage_workspace']=dict(path=str(root.parent/'Cargo.toml'),sha256=helper.sha(root.parent/'Cargo.toml'));run.checkpoint()
        local=[r for r in helper.fixed_obligations() if r['id']==row['id'] or r['id'].startswith(row['id']+'/retained/') or r['id']==row['id']+'/bpf-contracts'];run.seal(local);cell_result=dict(obligation_id=row['id'],status='NOT_RUN');run.result_phase(cell_result,'reserved');run.report['cell_result']=cell_result
        run.versions();flags=TK_MODES[row['mode']][0] if row['subsystem']=='testkit' else BPF_MODES[row['mode']][0];base=['--offline','--locked','--manifest-path',root/'Cargo.toml',*flags];target=run.out/'target';run.cargo('lock',['generate-lockfile','--offline','--manifest-path',root/'Cargo.toml'],root,target);_,text=run.cargo('metadata',['metadata','--format-version','1','--filter-platform','x86_64-unknown-linux-gnu',*base],root,target);metadata=json.loads(text);helper.atomic_json(run.out/'metadata.json',metadata);run.report['targets']=target_projection(metadata,root)
        if row['subsystem']=='testkit':
            run.report['graph']=isolated_graph(helper,metadata,bpf,testkit,row['mode']);run.cargo('lib-tests',['test',*base,'--lib'],root,target);integration=[target['name'] for target in run.report['targets']['targets'] if target['kind']==['test'] and set(target.get('required-features',[]))<=set(TK_MODES[row['mode']][1])];run.cargo('integration-tests',['test',*base,*[arg for name in integration for arg in ['--test',name]]],root,target);run.cargo('doc-tests',['test',*base,'--doc'],root,target)
            for name in RETAINED:retained_client(helper,run,bpf,testkit,row['mode'],name)
        else:
            run.report['graph']=helper.inspect_graph(metadata,bpf,None,BPF_MODES[row['mode']][1],[]);tests=['api_contract','maps_pure','maps_contract','who_preservation','capability']+(['capability_json'] if row['mode']=='json' else []);run.cargo('lib-tests',['test',*base,'--lib'],root,target);run.cargo('integration-tests',['test',*base,*[arg for name in tests for arg in ['--test',name]]],root,target);run.cargo('doc-tests',['test',*base,'--doc'],root,target)
            for name in ['capability_cache','filter_assessment']:run.cargo('example-'+name,['run',*base,'--example',name],root,target)
            contract=dict(obligation_id=row['id']+'/bpf-contracts',status='NOT_RUN');run.result_phase(contract,'reserved');run.report['contract_result']=contract;project=run.out/'bpf-contracts';(project/'src').mkdir(parents=True);shutil.copyfile(ROOT/'tests/package-policy/clients/bpf-contracts.rs',project/'src/main.rs');(project/'Cargo.toml').write_text('[workspace]\n[package]\nname="bpf-contracts"\nversion="0.1.0"\nedition="2021"\n[dependencies]\nscopebase-bpf={path='+json.dumps(str(bpf))+',default-features='+str(row['mode']=='default').lower()+',features='+json.dumps(['json'] if row['mode']=='json' else [])+'}\n');run.cargo('contracts-lock',['generate-lockfile','--offline'],project,project/'target');run.cargo('contracts-run',['run','--offline','--locked'],project,project/'target');contract['status']='PASS';run.result_phase(contract,'complete')
        cell_result['status']='PASS';run.result_phase(cell_result,'complete');return run.finish('PASS')
    except BaseException as e:
        row['status']='INCOMPLETE';raise run.abort(e)

def main(argv=None):
    args=parser().parse_args(argv);tools=bindings(args)
    if any(not getattr(args,name).is_absolute() or '..' in getattr(args,name).parts for name in ['source_bpf','source_testkit','bpf_archive','testkit_archive','output','config','cargo_home','build_wrapper']):raise ValueError('explicit absolute input/output bindings required')
    # Validate the original spelling before resolution can hide an alias.
    helper=load(args.source_testkit/'tests/fixtures/bp03/run_consumers.py');helper.lexical_path(args.output)
    for source in [args.source_bpf,args.source_testkit,args.bpf_archive,args.testkit_archive,args.config,args.cargo_home,args.build_wrapper,*tools.values()]:
        if args.output.resolve().is_relative_to(source.resolve()):raise ValueError('output inside selected input')
    args.output=args.output.resolve()
    if args.output.exists() or not args.output.is_absolute() or args.output.is_relative_to(ROOT):raise ValueError('fresh absolute output outside worktree required')
    args.output.mkdir(parents=True);helper=load(args.source_testkit/'tests/fixtures/bp03/run_consumers.py');rows=required_rows();parent=None
    report=dict(schema_version=1,kind='BP03_HOST_SOURCE_ARCHIVE_CAMPAIGN',status='INCOMPLETE',required=rows,clients=[],combined_helpers=[dict(id=kind+'/'+version+'/bp03-consumers',input=kind,compiler=version,status='NOT_RUN') for kind in ['source','archive'] for version in tools],archive_mappings={},scope='descriptive host/model only; full BP03 planned')
    try:
        helper.inspect_packages(args.source_bpf,args.source_testkit)
        bpf=unpack(args.bpf_archive,args.output/'archives/bpf','scopebase-bpf');tk=unpack(args.testkit_archive,args.output/'archives/testkit','scopebase-testkit');helper.inspect_packages(bpf,tk)
        report['archive_mappings']={'scopebase-bpf':archive_mapping(helper,args.source_bpf,args.bpf_archive,bpf),'scopebase-testkit':archive_mapping(helper,args.source_testkit,args.testkit_archive,tk)};inputs={'source':(args.source_bpf,args.source_testkit),'archive':(bpf,tk)};expectations={row['id']:dict(root=str(args.output/'cells'/row['id']),kind='BP03_HOST_LIBRARY_CELL') for row in rows};expectations.update({row['id']:dict(root=str(args.output/'bp03-consumers'/row['input']/row['compiler']),kind='BP03_PACKAGE_CONSUMERS') for row in report['combined_helpers']});parent=helper.ParentEvents(args.output,dict(kind=report['kind'],child_invocations=expectations,inputs={k:[str(p) for p in v] for k,v in inputs.items()},tools={k:str(v) for k,v in tools.items()},config=dict(path=str(args.config),sha256=helper.sha(args.config)),cargo_home=str(args.cargo_home),wrapper=dict(path=str(args.build_wrapper),sha256=helper.sha(args.build_wrapper)),archive_mappings=report['archive_mappings']),rows+report['combined_helpers']);bind_child_invocations(parent,expectations);parent.checkpoint(report)
        for row in rows:
            parent.reserve_row(row);start_child(parent,row['id']);completion=run_cell(helper,args,tools,row,inputs);_,reference=accept_child(parent,helper,completion,row['id']);row.update(status='PASS',child_reference=reference);parent.checkpoint(report)
        # One actual delivered helper invocation supplies all three combined
        # modes. Both cell inventories reference its exact binary/corpus graph.
        for kind in ['source','archive']:
            for version in tools:
                combined=next(r for r in report['combined_helpers'] if r['input']==kind and r['compiler']==version);parent.reserve_row(combined);start_child(parent,combined['id']);bp,tp=inputs[kind];client_helper=load(tp/'tests/fixtures/bp03/run_consumers.py');out=args.output/'bp03-consumers'/kind/version
                completion=client_helper.consumers_main(['--package',str(bp),'--testkit-package',str(tp),'--out',str(out),'--toolchain',version,'--toolchain-root',str(tools[version]),'--cargo-home',str(args.cargo_home),'--cargo-config',str(args.config),'--build-wrapper',str(args.build_wrapper)])
                receipt,reference=accept_child(parent,client_helper,completion,kind+'/'+version+'/bp03-consumers')
                combined.update(status='PASS',child_reference=reference)
                if receipt['status']!='PASS' or len(receipt['clients'])!=6:raise ValueError('required actual combined consumers incomplete')
                report['clients'].extend(dict(id=kind+'/'+version+'/'+client['mode']+'/'+client['client'],input=kind,compiler=version,mode=client['mode'],client=client['client'],child_reference=reference) for client in receipt['clients'])
                for row in rows:
                    if row['input']==kind and row['compiler']==version and row['bp03_clients']:
                        mode=row['mode'] if row['subsystem']=='testkit' else BPF_MODES[row['mode']][2];row['bp03_execution_reference']=dict(child_reference=reference,mode=mode,client_ids=[client['obligation_id'] for client in receipt['clients'] if client['mode']==mode])
                parent.checkpoint(report)
        if len(report['clients'])!=24 or any(r['status']!='PASS' for r in rows):raise ValueError('fixed required campaign denominator incomplete')
        report['status']='PASS';return finish_parent(parent,report)
    except BaseException as e:
        if parent is not None:raise parent.abort(e,report)
        raise
if __name__=='__main__':main()
