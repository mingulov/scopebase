#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Summarize a transported BP02 payload, including bindings and child custody."""
import sys
sys.dont_write_bytecode = True
import argparse,json
from pathlib import Path
from run_live import resource_identity,sha,validate_mount_children,validate_guard_outcomes

CHECKS={'owned_resource_digest','owned_resource_identity','compiler','feature','manifest'}
CONTROLS={'N6-no-symlink-control':'EXPECTED_SEMANTIC_FAILURE','N6-symlink-restored':'PASS'}

def require(condition,description):
    if not condition:raise ValueError(description)

def evaluate(payload,results):
    payload=Path(payload);results=Path(results)
    summary={'status':'FAILED','minimum_native_cells':'NOT_QUALIFIED','rows':[],'errors':[]}
    try:
        resource_path=payload/'resource.json';resource=json.loads(resource_path.read_text())
        resource_digest=sha(resource_path);identity=resource_identity(resource)
    except (OSError,ValueError,KeyError,TypeError) as exc:
        summary['errors'].append('owned resource admission unavailable: '+str(exc))
        return summary
    for mode in ('default','no-default'):
        name='native-'+mode;receipt_path=results/name/'receipt.json'
        row={'route':name,'status':'FAILED'};summary['rows'].append(row)
        try:
            spec_path=payload/'specs'/(mode+'.json');spec=json.loads(spec_path.read_text())
            receipt=json.loads(receipt_path.read_text());bindings=spec['bindings']
            require(receipt['status']=='PASS' and receipt['mode']=='native-map',name+' native receipt failed')
            require(receipt['toolchain']=='1.98.1' and receipt['requested_feature']==mode,name+' requested compiler/feature mismatch')
            require(receipt['prebuilt_sha256']==sha(spec_path) and receipt['bindings']==bindings,name+' prebuilt spec receipt mismatch')
            require(receipt['resource_sha256']==resource_digest and bindings['owned_resource_sha256']==resource_digest,name+' owned resource digest mismatch')
            require(bindings['owned_resource_identity']==identity,name+' owned resource identity mismatch')
            require(bindings['compiler']=='1.98.1' and bindings['feature']==mode,name+' prepared compiler/feature mismatch')
            require(bindings['manifest_sha256']==sha(payload/'source/Cargo.toml'),name+' source manifest mismatch')
            require(receipt['binding_checks']=={key:'PASS' for key in CHECKS},name+' binding checks incomplete')
            controls=[r for r in receipt['commands'] if r.get('case') in CONTROLS]
            require(len(controls)==2 and {r['case'] for r in controls}==set(CONTROLS),name+' symlink controls missing/duplicated')
            for control in controls:
                label=control['case'];expected=CONTROLS[label]
                require(control['status']==expected and control['semantic_status']==expected,name+' '+label+' semantic outcome mismatch')
                require(control['child_reaped'] is True and control['cleanup_status']=='PASS' and control['owned_temp_removed'] is True,name+' '+label+' child/cleanup unresolved')
                require(control['custody_unresolved'] is False and control['root_report_count']==control['identity_report_count']==1
                        and control['reported_identity']==control['observed_identity'] and isinstance(control['reported_identity'],list)
                        and len(control['reported_identity'])==2,name+' '+label+' root identity mismatch')
            mounts=[r for r in receipt['commands'] if r.get('case')=='N6-N8']
            require(len(mounts)==1 and mounts[0]['status']=='PASS' and mounts[0]['child_reaped']is True
                    and mounts[0]['fixture_custody_validation']=='PASS' and mounts[0]['cleanup_status']=='PASS'
                    and mounts[0]['custody_unresolved']is False,name+' mount/child cleanup missing or unresolved')
            try:validate_mount_children(mounts[0]['fixture_children'],{'TMPDIR':'/tmp'})
            except (AssertionError,ValueError,KeyError,TypeError) as exc:raise ValueError(name+' fixture custody invalid: '+repr(exc)) from exc
            guards=[r for r in receipt['commands'] if r.get('case')=='N1-N5-N9']
            require(len(guards)==1 and guards[0]['status']=='PASS',name+' guarded mapping outcomes missing')
            validate_guard_outcomes(guards[0]['guard_outcomes'])
            row.update(status='PASS',receipt_sha256=sha(receipt_path),binding_checks='PASS',child_cleanup='PASS')
        except (OSError,ValueError,KeyError,TypeError) as exc:
            row['error']=str(exc);summary['errors'].append(name+': '+str(exc))
    name='archive-native';receipt_path=results/name/'receipt.json'
    row={'route':name,'status':'FAILED'};summary['rows'].append(row)
    try:
        spec_path=payload/'specs/archive-clients.json';spec=json.loads(spec_path.read_text());receipt=json.loads(receipt_path.read_text())
        require(receipt['status']=='PASS' and receipt['mode']=='native-map',name+' native receipt failed')
        require(receipt['prebuilt_sha256']==sha(spec_path) and receipt['bindings']==spec['bindings'],name+' prebuilt spec receipt mismatch')
        require(spec['bindings']['compiler']=='1.98.1' and spec['bindings']['mode']=='actual-unpacked-archive-native',name+' compiler/mode mismatch')
        require(spec['bindings']['input']['manifest_sha256']==sha(payload/'archive/Cargo.toml'),name+' archive manifest mismatch')
        require(set(spec['clients'])=={'default','no-default'},name+' client modes incomplete')
        require(sorted((c['feature'],c['client'],c['status']) for c in receipt['cells'])==
                [('default','who-reader','PASS'),('no-default','who-reader','PASS')],name+' native client cells incomplete')
        row.update(status='PASS',receipt_sha256=sha(receipt_path),binding_checks='PASS')
    except (OSError,ValueError,KeyError,TypeError) as exc:
        row['error']=str(exc);summary['errors'].append(name+': '+str(exc))
    if not summary['errors']:
        summary['status']='PASS'
        summary['minimum_native_cells']='N1-N9+R1 both source feature modes; archive actual native clients both feature modes'
    return summary

def main():
    p=argparse.ArgumentParser();p.add_argument('--payload',required=True,type=Path);p.add_argument('--results',required=True,type=Path);args=p.parse_args()
    summary=evaluate(args.payload,args.results)
    (args.results/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    if summary['status']!='PASS':
        print(json.dumps({'status':'FAILED','errors':summary['errors']}),file=sys.stderr)
        return 1
    print('BP02_ACTUAL_NATIVE_PASS')
    return 0

if __name__=='__main__':sys.exit(main())
