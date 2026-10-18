#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""CP04 affected-package verification using the accepted SB02 helpers.

All output is private; shared policy/tools are read only. Keeps all workspace
members and grants in a policy projection, appends only CP04 package files, then
runs capture only. Supplements the baseline policy gate with source/archive
examples, precise UI refusals, both API clients and delivered semantic controls.
Cargo calls in the baseline helper take one outer lease; supplemental calls take
separate leases. The controls runner owns its own leases. Never nest a lease.
"""
from __future__ import annotations
import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools/build'))
import common as p
import check_features as cf

ADDITIONS=['src/provenance.rs','tests/insertion_provenance.rs','tests/full_map_loss_contract.rs',
           'tests/support/cp04_model.rs','tests/support/check_cp04_controls.py',
           'tests/ui/cp04_units_match.rs','tests/ui/provenance_units_do_not_mix.rs',
           'fixtures/insertion-v1.json','examples/insertion_journal.rs','examples/cache_attribution.rs']
EXAMPLES=['counter_windows','diagnostic_lanes','insertion_journal','cache_attribution']
NEW_CLIENTS=['insertion_journal','cache_attribution']


def validate_wrapper(path):
    if not path.is_absolute() or not path.is_file() or not os.access(path,os.X_OK) or any(p.is_symlink()for p in [path,*path.parents]):
        raise ValueError('absolute existing executable build wrapper with no symlinks required')
    return {'path':str(path),'sha256':p.sha(path)}


def build_route(wrapper, program, *arguments):
    return [wrapper,'--',program,*arguments]


def policy_phase(output, previous=None, wrapper=None):
    """Executed only as the direct child of the common slot wrapper."""
    matrix_path=output/'policy-input/package-policy.json'
    matrix=p.validate_matrix(matrix_path,'features')
    run_root=output/'policy-run';run_root.mkdir()
    omitted=[]
    for other in matrix['members']:
        if other['id']=='scopebase-capture':continue
        prefix=other['id']
        omitted.extend(prefix+'-'+phase for phase in ['source','lock','admit','package-list-msrv','package-list-current','package','archive','archive-metadata'])
        for mode,_,_ in cf.configurations(other):
            omitted.extend(prefix+'-'+mode+'-'+phase for phase in ['prepare','lock'])
            for t in matrix['toolchains']:
                omitted.extend(prefix+'-'+mode+'-'+t['id']+'-'+phase for phase in ['admit','check','test','doc']+['run-'+v['id']for v in (other['clients']if mode.startswith('union-')else other['clients'][:1])])
    ex=p.Execution('cp04-capture-only',matrix_path,matrix,run_root,matrix_path.parent/'Cargo.toml',scope='affected-capture',omitted=omitted)
    ex.report['build_wrapper']=validate_wrapper(wrapper)
    ex.report['inherited_lock_fds']=[]
    for entry in Path('/proc/self/fd').iterdir():
        try:
            target=os.readlink(entry)
            if target.endswith('.lock'):
                stat=os.fstat(int(entry.name));ex.report['inherited_lock_fds'].append({'fd':entry.name,'path':target,'device':stat.st_dev,'inode':stat.st_ino})
        except OSError:pass
    ex.reserve('inputs')
    ex.staging=ex.step('inputs',lambda r:p.stage_inputs(matrix['cargo_inputs'],run_root))
    ex.report['staged_inputs']=ex.staging['staged_inputs']
    for t in matrix['toolchains']:
        for suffix in ['','-rustc','-cargo']:ex.reserve('identity-'+t['id']+suffix)
        ex.report['toolchains'].append(ex.step('identity-'+t['id'],lambda r,t=t:p.toolchain_info(t,run_root,ex)))
        ex.reserve('root-'+t['id'])
        def metadata(r):
            result=ex.command(r,t,matrix_path.parent/'Cargo.toml',['metadata','--offline','--locked','--format-version','1','--filter-platform',p.HOST],run_root/'root-target')
            data=json.loads(p.stdout(result));actual={str(Path(v['manifest_path']).resolve())for v in data['packages']if v['id']in data['workspace_members']}
            wanted={str(p.relative(matrix_path.parent,v['manifest']).resolve())for v in matrix['members']}
            if actual!=wanted:raise p.PolicyError('UNREGISTERED_MEMBER')
            r['observed']={'members_registered':len(actual)}
        ex.step('root-'+t['id'],metadata)
    member=next(v for v in matrix['members']if v['id']=='scopebase-capture');prefix=member['id']
    for phase in ['source','lock','admit','package-list-msrv','package-list-current','package','archive','archive-metadata']:ex.reserve(prefix+'-'+phase)
    for mode,_,_ in cf.configurations(member):
        for phase in ['prepare','lock']:ex.reserve(prefix+'-'+mode+'-'+phase)
        for t in matrix['toolchains']:
            for phase in (['admit'] if previous else ['admit','check','test','doc']+['run-'+v['id']for v in (member['clients']if mode.startswith('union-')else member['clients'][:1])]):ex.reserve(prefix+'-'+mode+'-'+t['id']+'-'+phase)
    try:cf.run_member(ex,member,matrix_path.parent,bool(previous))
    except p.PolicyError:pass
    code=ex.finish(output/'policy-report-raw.json')
    # Preserve the accepted helper's raw receipt. Its generic feature summary
    # hardcodes selected=declared; correct only that reporting field here.
    corrected=copy.deepcopy(ex.report)
    corrected['summary']['selected_compiler_cells']=len(matrix['toolchains'])*len(cf.configurations(member))
    corrected['derived_from']={'path':str(output/'policy-report-raw.json'),'sha256':p.sha(output/'policy-report-raw.json'),'correction':'selected compiler cells computed from the sole executed capture member; no check results changed'}
    if previous:
        corrected['retained_core_evidence']={'report':str(previous/'policy-report.json'),'sha256':p.sha(previous/'policy-report.json'),'scope':'unchanged production/tests/examples/UI; current run refreshes archive admission only'}
    p.atomic_json(output/'policy-report.json',corrected)
    return code


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--policy-phase',action='store_true')
    parser.add_argument('--build-wrapper',type=Path,required=True,help='explicit controller-selected shared build route; no HOME/XDG/ambient fallback')
    parser.add_argument('--delivery-only-from',type=Path,help='retain controller-approved unchanged core evidence from this prior CP04 run; refresh packaging, helpers and new actual clients')
    parser.add_argument('--skip-controls',action='store_true',help='diagnostic partial run only; not full CP04 acceptance')
    args=parser.parse_args(argv);output=args.output_dir
    try:wrapper_binding=validate_wrapper(args.build_wrapper)
    except ValueError as exc:parser.error(str(exc))
    if args.policy_phase:return policy_phase(output,args.delivery_only_from,args.build_wrapper)
    if not output.is_absolute() or output.exists() or output.resolve().is_relative_to(ROOT):
        parser.error('new absolute output outside the worktree required')
    output.mkdir(parents=True,mode=0o700)
    matrix=json.loads((ROOT/'package-policy.json').read_text());projection=copy.deepcopy(matrix)
    if args.delivery_only_from:
        prior=args.delivery_only_from
        if not prior.is_absolute():parser.error('absolute prior-run path required')
        policy=json.loads((prior/'policy-report.json').read_text())
        old=json.loads((prior/'supplemental-report.json').read_text())
        if policy['summary']['status']!='PASS' or policy['summary']['selected_compiler_cells']!=6:parser.error('prior six-cell core campaign must pass')
        retained=[];changed=[]
        for item in old['file_equality']:
            current=p.sha(ROOT/'crates/scopebase-capture'/item['source'])
            if current!=item['sha256']:
                if item['source']!='tests/support/check_cp04_controls.py':parser.error('non-helper source changed; full verification required')
                changed.append({'path':item['source'],'before':item['sha256'],'after':current})
            else:retained.append(item)
        (output/'retained-evidence.json').write_text(json.dumps({'controller_ruling':'2026-10-18 retain unchanged core; rerun affected helper/archive delivery','prior_policy_report':str(prior/'policy-report.json'),'prior_policy_sha256':p.sha(prior/'policy-report.json'),'prior_supplemental_report':str(prior/'supplemental-report.json'),'prior_supplemental_sha256':p.sha(prior/'supplemental-report.json'),'prior_archive_sha256':old['archive_sha256'],'unchanged_files':retained,'changed_helper':changed},indent=2)+'\n')
    member=next(v for v in projection['members']if v['id']=='scopebase-capture')
    for name in ADDITIONS:
        if name not in member['package_files']:member['package_files'].append(name)
    inputs=output/'policy-input';inputs.mkdir()
    for name in ['Cargo.toml','Cargo.lock']:shutil.copyfile(ROOT/name,inputs/name)
    for m in matrix['members']:
        manifest=Path(m['manifest']);dest=inputs/manifest.parent;dest.parent.mkdir(parents=True,exist_ok=True)
        p.source_copy(ROOT/manifest.parent,dest)
        for client in next(v for v in projection['members']if v['id']==m['id'])['clients']:
            source=Path(client['source']);dest=inputs/source;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/source,dest)
    (inputs/'package-policy.json').write_text(json.dumps(projection,indent=2)+'\n')
    (output/'policy-delta.json').write_text(json.dumps({'baseline_sha256':p.sha(ROOT/'package-policy.json'),'projection_sha256':p.sha(inputs/'package-policy.json'),'capture_package_files_appended':ADDITIONS,'members_grants_inputs_retained':True,'supplemental_clients':[{'id':'cp04-'+v.replace('_','-'),'source':'crates/scopebase-capture/examples/'+v+'.rs'}for v in NEW_CLIENTS],'baseline_clients_retained':member['clients'],'controller_ruling':'2026-10-18 preserve max-two baseline clients; CP04 independent programs are supplemental descriptors'},indent=2)+'\n')
    wrapper=args.build_wrapper
    env=p.clean_env(output,matrix['toolchains'][0],output/'unused-target')
    phase=p.run(build_route(wrapper,sys.executable,Path(__file__).resolve(),'--output-dir',output,'--policy-phase','--build-wrapper',wrapper,*(['--delivery-only-from',args.delivery_only_from]if args.delivery_only_from else[])),ROOT,env,output/'logs/policy-phase',timeout=1200)
    if phase['exit_code']!=0:
        (output/'driver-failure.json').write_text(json.dumps(phase,indent=2));return 1
    policy=json.loads((output/'policy-report.json').read_text())
    archive_row=next(v for v in policy['rows']if v['id']=='scopebase-capture-archive')
    archive=Path(archive_row['observed']['archive']);unpacked=Path(archive_row['observed']['unpacked'])
    source=ROOT/'crates/scopebase-capture'
    # Explicit file identity across candidate, actual tar extraction and inventory.
    expected=set(member['package_files']);actual={v['path']for v in p.tree_records(unpacked)}
    p.package_files(actual,expected)
    equal=[]
    for record in p.tree_records(source):
        name=record['path']
        if name not in expected:raise p.PolicyError('UNLISTED_SOURCE_FILE')
        packaged='Cargo.toml.orig' if name=='Cargo.toml' else name
        if p.sha(source/name)!=p.sha(unpacked/packaged):raise p.PolicyError('ARCHIVE_BYTES_DIFFER')
        equal.append({'source':name,'archive':packaged,'sha256':p.sha(source/name)})
    report={'status':'RUNNING','build_wrapper':wrapper_binding,'source_root':str(source),'archive':str(archive),'archive_sha256':p.sha(archive),'unpacked':str(unpacked),'file_equality':equal,'policy_summary':policy['summary'],'rows':[],'skip_controls':args.skip_controls,'product_qualification':False,'unchanged_packages_omitted':['scopebase-linux','scopebase-testkit','scopebase-bpf'],'baseline_compiler_cells':6,'supplemental_cells':12,'delivery_only_from':str(args.delivery_only_from)if args.delivery_only_from else None,'predecessor_input_sha256':{name:p.sha(source/name)for name in ['src/counter.rs','src/loss.rs','tests/counter_deltas.rs','tests/loss_units.rs','tests/support/check_cp03_controls.py']}}
    def save():(output/'supplemental-report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    cargo_config=output/'policy-run/cargo-home/config.toml'
    def run(ident,argv,cwd,cell_env,negative=False):
        result=p.run(argv,cwd,cell_env,output/'logs'/ident,timeout=600)
        result['id']=ident;report['rows'].append(result);save()
        if result['reason_code'] or result['cleanup']!='complete':raise p.PolicyError('PROCESS_UNRESOLVED',detail=result)
        if not negative and result['exit_code']!=0:raise p.PolicyError('COMMAND_FAILED',detail=result)
        return result
    forms=[('no-default',False,[]),('default',True,[]),('json',False,['json'])]
    for tier,subject in [('source',source),('archive',unpacked)]:
        for t in matrix['toolchains']:
            for form,defaults,features in forms:
                ident=tier+'-'+t['id']+'-'+form;cell=output/'cells'/ident;cell.mkdir(parents=True)
                cell_env=p.clean_env(cell,t,cell/'target');shutil.copyfile(cargo_config,cell/'cargo-home/config.toml')
                flags=[] if defaults else ['--no-default-features']
                if features:flags+=['--features',','.join(features)]
                def cargo(label,arguments,manifest=subject/'Cargo.toml',cwd=subject,extra_flags=flags,negative=False):
                    return run(ident+'-'+label,build_route(wrapper,Path(t['root'])/'bin/cargo',*arguments,'--manifest-path',manifest,*extra_flags),cwd,cell_env,negative)
                if not args.delivery_only_from:
                    cargo('tests',['test','--locked','--offline'])
                    cargo('doctests',['test','--locked','--offline','--doc'])
                for example in (NEW_CLIENTS if args.delivery_only_from else EXAMPLES):cargo('example-'+example,['run','--locked','--offline','--example',example])
                # Two independent workspaces and locks, each solely dependent on subject.
                for example in (NEW_CLIENTS if args.delivery_only_from else EXAMPLES):
                    client=cell/'clients'/example;(client/'src').mkdir(parents=True)
                    shutil.copyfile(subject/'examples'/(example+'.rs'),client/'src/main.rs')
                    manifest=('[package]\nname = "cp04-'+example.replace('_','-')+'"\nversion = "0.1.0"\nedition = "2021"\npublish = false\n'
                              '[workspace]\n[dependencies]\nscopebase-capture = { path = '+json.dumps(str(subject))+', version = "=0.1.0", default-features = '+str(defaults).lower()+', features = '+json.dumps(features)+' }\n')
                    (client/'Cargo.toml').write_text(manifest)
                    cargo('client-'+example+'-lock',['generate-lockfile','--offline'],client/'Cargo.toml',client,[])
                    result=cargo('client-'+example+'-metadata',['metadata','--locked','--offline','--format-version','1'],client/'Cargo.toml',client,[])
                    metadata=json.loads(p.stdout(result));chosen=cf.assert_subject(metadata,'scopebase-capture',features,minimal=not features)
                    if Path(chosen['manifest_path']).resolve()!=(subject/'Cargo.toml').resolve():raise p.PolicyError('WRONG_CLIENT_SUBJECT')
                    result['subject_manifest']=chosen['manifest_path'];result['client_lock_sha256']=p.sha(client/'Cargo.lock');result['client_manifest_sha256']=p.sha(client/'Cargo.toml');result['client_source_sha256']=p.sha(client/'src/main.rs');result['subject_source_sha256']=p.tree_digest(subject);result['selected_features']=features;result['default_features']=defaults;save()
                    cargo('client-'+example+'-run',['run','--locked','--offline'],client/'Cargo.toml',client,[])
                if not args.delivery_only_from:
                    # Compiler JSON verifies the precise primary argument line.
                    ui=cell/'ui';(ui/'src').mkdir(parents=True)
                    (ui/'Cargo.toml').write_text('[package]\nname = "cp04-ui"\nversion = "0.1.0"\nedition = "2021"\n[workspace]\n[dependencies]\nscopebase-capture = { path = '+json.dumps(str(subject))+', version = "=0.1.0", default-features = '+str(defaults).lower()+', features = '+json.dumps(features)+' }\n')
                    positive=subject/'tests/ui/cp03_units_match.rs';shutil.copyfile(positive,ui/'src/main.rs')
                    cargo('ui-lock',['generate-lockfile','--offline'],ui/'Cargo.toml',ui,[])
                    cargo('ui-positive',['check','--locked','--offline','--message-format=json'],ui/'Cargo.toml',ui,[])
                    for name,needle in [('counter_units_do_not_mix','let _ = sample_delta'),('signal_is_not_event_loss','events_only(signal)'),('provenance_units_do_not_mix','let _ = ProvenanceLane')]:
                        fixture=subject/'tests/ui'/(name+'.rs');shutil.copyfile(fixture,ui/'src/main.rs')
                        expected_line=next(i for i,line in enumerate(fixture.read_text().splitlines(),1)if needle in line)
                        result=cargo('ui-'+name,['check','--locked','--offline','--message-format=json'],ui/'Cargo.toml',ui,[],True)
                        if result['exit_code']!=101 or not p.rust_refusal(p.stdout(result),'E0308','mismatched types',ui,expected_primary=('src/main.rs',expected_line)):
                            raise p.PolicyError('UI_PRIMARY_REFUSAL_MISSING',detail=result)
                        argument={'counter_units_do_not_mix':'current','signal_is_not_event_loss':'signal','provenance_units_do_not_mix':'count'}[name]
                        primary=[]
                        for line in p.stdout(result).splitlines():
                            item=json.loads(line)
                            message=item.get('message',{})
                            if (message.get('code') or {}).get('code')!='E0308':continue
                            for span in message.get('spans',[]):
                                if span.get('is_primary') and span.get('line_start')==expected_line and span.get('line_end')==expected_line:
                                    text=fixture.read_text().splitlines()[expected_line-1]
                                    primary.append(text[span['column_start']-1:span['column_end']-1])
                        if primary!=[argument]:raise p.PolicyError('UI_ARGUMENT_MISMATCH',detail={'primary':primary,'expected':argument})
                        result['verified_primary']={'code':'E0308','file':'src/main.rs','line':expected_line,'argument':argument};save()
                        shutil.copyfile(subject/'tests/ui/cp04_units_match.rs' if name=='provenance_units_do_not_mix' else positive,ui/'src/main.rs')
                        cargo('ui-'+name+'-restored',['check','--locked','--offline','--message-format=json'],ui/'Cargo.toml',ui,[])
                    # Separate compiling same-unit CP04 twin.
                    shutil.copyfile(subject/'tests/ui/cp04_units_match.rs',ui/'src/main.rs')
                    cargo('ui-cp04-positive',['check','--locked','--offline','--message-format=json'],ui/'Cargo.toml',ui,[])
                if not args.skip_controls:
                    control_env=dict(cell_env)
                    control=cell/'controls'
                    result=run(ident+'-controls',[sys.executable,subject/'tests/support/check_cp04_controls.py','run','--source-root',subject,'--cargo',Path(t['root'])/'bin/cargo','--rustc',Path(t['root'])/'bin/rustc','--feature-set',form,'--output-dir',control,'--build-wrapper',wrapper,*(['--root-mirror',ROOT/'fixtures/capture/insertion-v1.json'] if tier=='source' else [])],subject,control_env)
                    controls=json.loads((control/'report.json').read_text())
                    if controls['status']!='PASS':raise p.PolicyError('SEMANTIC_CONTROL_FAILED')
                    result['semantic_controls']=len(controls['rows']);save()
    report['status']='PASS_PARTIAL_CONTROLS_NOT_RUN' if args.skip_controls else 'PASS';save()
    print(json.dumps({'status':report['status'],'rows':len(report['rows']),'archive_sha256':report['archive_sha256'],'report':str(output/'supplemental-report.json')}))
    return 0


if __name__=='__main__':sys.exit(main())
