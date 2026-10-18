#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""CP03 affected-package verification using the accepted SB02 helpers.

All output is private; shared policy/tools are read only. Keeps all workspace
members and grants in a policy projection, appends only CP03 package files, then
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

ADDITIONS=['src/counter.rs','src/loss.rs','tests/counter_deltas.rs','tests/loss_units.rs',
           'tests/ui/counter_units_do_not_mix.rs','tests/ui/signal_is_not_event_loss.rs',
           'tests/ui/cp03_units_match.rs','tests/support/check_cp03_controls.py',
           'examples/counter_windows.rs','examples/diagnostic_lanes.rs']


def policy_phase(output):
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
    ex=p.Execution('cp03-capture-only',matrix_path,matrix,run_root,matrix_path.parent/'Cargo.toml',scope='affected-capture',omitted=omitted)
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
            for phase in ['admit','check','test','doc']+['run-'+v['id']for v in (member['clients']if mode.startswith('union-')else member['clients'][:1])]:ex.reserve(prefix+'-'+mode+'-'+t['id']+'-'+phase)
    try:cf.run_member(ex,member,matrix_path.parent,False)
    except p.PolicyError:pass
    code=ex.finish(output/'policy-report-raw.json')
    # Preserve the accepted helper's raw receipt. Its generic feature summary
    # hardcodes selected=declared; correct only that reporting field here.
    corrected=copy.deepcopy(ex.report)
    corrected['summary']['selected_compiler_cells']=len(matrix['toolchains'])*len(cf.configurations(member))
    corrected['derived_from']={'path':str(output/'policy-report-raw.json'),'sha256':p.sha(output/'policy-report-raw.json'),'correction':'selected compiler cells computed from the sole executed capture member; no check results changed'}
    p.atomic_json(output/'policy-report.json',corrected)
    return code


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--policy-phase',action='store_true')
    parser.add_argument('--skip-controls',action='store_true',help='diagnostic partial run only; not full CP03 acceptance')
    args=parser.parse_args(argv);output=args.output_dir
    if args.policy_phase:return policy_phase(output)
    if not output.is_absolute() or output.exists() or output.resolve().is_relative_to(ROOT):
        parser.error('new absolute output outside the worktree required')
    output.mkdir(parents=True,mode=0o700)
    matrix=json.loads((ROOT/'package-policy.json').read_text());projection=copy.deepcopy(matrix)
    member=next(v for v in projection['members']if v['id']=='scopebase-capture')
    for name in ADDITIONS:
        if name not in member['package_files']:member['package_files'].append(name)
    inputs=output/'policy-input';inputs.mkdir()
    for name in ['Cargo.toml','Cargo.lock']:shutil.copyfile(ROOT/name,inputs/name)
    for m in matrix['members']:
        manifest=Path(m['manifest']);dest=inputs/manifest.parent;dest.parent.mkdir(parents=True,exist_ok=True)
        p.source_copy(ROOT/manifest.parent,dest)
        for client in m['clients']:
            source=Path(client['source']);dest=inputs/source;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/source,dest)
    (inputs/'package-policy.json').write_text(json.dumps(projection,indent=2)+'\n')
    (output/'policy-delta.json').write_text(json.dumps({'baseline_sha256':p.sha(ROOT/'package-policy.json'),'projection_sha256':p.sha(inputs/'package-policy.json'),'capture_package_files_appended':ADDITIONS,'members_grants_inputs_retained':True,'supplemental_clients':ADDITIONS[-2:]},indent=2)+'\n')
    wrapper=ROOT/'bin/scopebase-build'
    env=p.clean_env(output,matrix['toolchains'][0],output/'unused-target')
    phase=p.run([wrapper,'--',sys.executable,Path(__file__).resolve(),'--output-dir',output,'--policy-phase'],ROOT,env,output/'logs/policy-phase',timeout=1200)
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
    report={'status':'RUNNING','source_root':str(source),'archive':str(archive),'archive_sha256':p.sha(archive),'unpacked':str(unpacked),'file_equality':equal,'policy_summary':policy['summary'],'rows':[],'skip_controls':args.skip_controls,'product_qualification':False}
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
                    return run(ident+'-'+label,[wrapper,'--',Path(t['root'])/'bin/cargo',*arguments,'--manifest-path',manifest,*extra_flags],cwd,cell_env,negative)
                cargo('tests',['test','--locked','--offline'])
                cargo('doctests',['test','--locked','--offline','--doc'])
                for example in ['counter_windows','diagnostic_lanes']:cargo('example-'+example,['run','--locked','--offline','--example',example])
                # Two independent workspaces and locks, each solely dependent on subject.
                for example in ['counter_windows','diagnostic_lanes']:
                    client=cell/'clients'/example;(client/'src').mkdir(parents=True)
                    shutil.copyfile(subject/'examples'/(example+'.rs'),client/'src/main.rs')
                    manifest=('[package]\nname = "cp03-'+example.replace('_','-')+'"\nversion = "0.1.0"\nedition = "2021"\npublish = false\n'
                              '[workspace]\n[dependencies]\nscopebase-capture = { path = '+json.dumps(str(subject))+', version = "=0.1.0", default-features = '+str(defaults).lower()+', features = '+json.dumps(features)+' }\n')
                    (client/'Cargo.toml').write_text(manifest)
                    cargo('client-'+example+'-lock',['generate-lockfile','--offline'],client/'Cargo.toml',client,[])
                    result=cargo('client-'+example+'-metadata',['metadata','--locked','--offline','--format-version','1'],client/'Cargo.toml',client,[])
                    metadata=json.loads(p.stdout(result));chosen=cf.assert_subject(metadata,'scopebase-capture',features,minimal=not features)
                    if Path(chosen['manifest_path']).resolve()!=(subject/'Cargo.toml').resolve():raise p.PolicyError('WRONG_CLIENT_SUBJECT')
                    result['subject_manifest']=chosen['manifest_path'];result['client_lock_sha256']=p.sha(client/'Cargo.lock');save()
                    cargo('client-'+example+'-run',['run','--locked','--offline'],client/'Cargo.toml',client,[])
                # Compiler JSON verifies the precise primary argument line.
                ui=cell/'ui';(ui/'src').mkdir(parents=True)
                (ui/'Cargo.toml').write_text('[package]\nname = "cp03-ui"\nversion = "0.1.0"\nedition = "2021"\n[workspace]\n[dependencies]\nscopebase-capture = { path = '+json.dumps(str(subject))+', version = "=0.1.0", default-features = '+str(defaults).lower()+', features = '+json.dumps(features)+' }\n')
                positive=subject/'tests/ui/cp03_units_match.rs';shutil.copyfile(positive,ui/'src/main.rs')
                cargo('ui-lock',['generate-lockfile','--offline'],ui/'Cargo.toml',ui,[])
                cargo('ui-positive',['check','--locked','--offline','--message-format=json'],ui/'Cargo.toml',ui,[])
                for name,needle in [('counter_units_do_not_mix','let _ = sample_delta'),('signal_is_not_event_loss','events_only(signal)')]:
                    fixture=subject/'tests/ui'/(name+'.rs');shutil.copyfile(fixture,ui/'src/main.rs')
                    expected_line=next(i for i,line in enumerate(fixture.read_text().splitlines(),1)if needle in line)
                    result=cargo('ui-'+name,['check','--locked','--offline','--message-format=json'],ui/'Cargo.toml',ui,[],True)
                    if result['exit_code']!=101 or not p.rust_refusal(p.stdout(result),'E0308','mismatched types',ui,expected_primary=('src/main.rs',expected_line)):
                        raise p.PolicyError('UI_PRIMARY_REFUSAL_MISSING',detail=result)
                    argument='current' if name=='counter_units_do_not_mix' else 'signal'
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
                    shutil.copyfile(positive,ui/'src/main.rs')
                    cargo('ui-'+name+'-restored',['check','--locked','--offline','--message-format=json'],ui/'Cargo.toml',ui,[])
                if not args.skip_controls:
                    control_env=dict(cell_env,SCOPEBASE_BUILD_WRAPPER=str(wrapper))
                    control=cell/'controls'
                    result=run(ident+'-controls',[sys.executable,subject/'tests/support/check_cp03_controls.py','--source-root',subject,'--cargo',Path(t['root'])/'bin/cargo','--rustc',Path(t['root'])/'bin/rustc','--feature-set',form,'--output-dir',control],subject,control_env)
                    controls=json.loads((control/'report.json').read_text())
                    if controls['status']!='PASS':raise p.PolicyError('SEMANTIC_CONTROL_FAILED')
                    result['semantic_controls']=len(controls['rows']);save()
    report['status']='PASS_PARTIAL_CONTROLS_NOT_RUN' if args.skip_controls else 'PASS';save()
    print(json.dumps({'status':report['status'],'rows':len(report['rows']),'archive_sha256':report['archive_sha256'],'report':str(output/'supplemental-report.json')}))
    return 0


if __name__=='__main__':sys.exit(main())
