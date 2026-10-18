#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SB02 independent archive/feature policy checker (Python 3.11+)."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import shutil
import sys
import tomllib
import common as p

ROOT = Path(__file__).resolve().parents[2]


def configurations(member):
    return [('minimal',False,member['minimal']),('default',True,member['default'])] + [
        ('union-'+str(i),False,features) for i,features in enumerate(member['supported_unions'])]


def assert_subject(metadata, subject_name, wanted_features, minimal=False):
    subjects = [v for v in metadata['packages'] if v['name'] == subject_name]
    if len(subjects) != 1 or subjects[0]['version'] != '0.1.0' or subjects[0]['source'] is not None:
        raise p.PolicyError('SUBJECT_IDENTITY_MISMATCH')
    node = next(n for n in metadata['resolve']['nodes'] if n['id'] == subjects[0]['id'])
    actual = set(node['features']) - {'default'}
    if actual != set(wanted_features):
        raise p.PolicyError('FEATURE_UNION_MISMATCH',detail={'expected':wanted_features,'observed':node['features']})
    if minimal and any(v['name'] in ('serde','serde_core','serde_json') for v in metadata['packages']):
        raise p.PolicyError('MINIMAL_FEATURE_LEAK')
    return subjects[0]


def generate_clients(root, member, subject, matrix_root, mode):
    root.mkdir(parents=True)
    source = tomllib.loads((subject/'Cargo.toml').read_text())['package']
    clients = member['clients'] if mode.startswith('union-') else [member['clients'][0]]
    names = []
    trusted = {}
    for client in clients:
        client_root = root/client['id']; (client_root/'src').mkdir(parents=True)
        shutil.copyfile(p.relative(matrix_root,client['source']),client_root/'src/main.rs')
        name = 'sb02-' + mode + '-' + client['id']; names.append(client['id'])
        defaults = client['default_features'] if mode.startswith('union-') else mode == 'default'
        features = client['features'] if mode.startswith('union-') else member['default'] if defaults else member['minimal']
        manifest = ('[package]\nname = '+json.dumps(name)+'\nversion = "0.1.0"\nedition = "2021"\nrust-version = "1.88.0"\npublish = false\n'
                    '[dependencies]\n'+json.dumps(source['name'])+' = { path = '+json.dumps(str(subject))+', version = "='+source['version']+'", default-features = '+str(defaults).lower()+', features = '+json.dumps(features)+' }\n')
        (client_root/'Cargo.toml').write_text(manifest)
        trusted[client_root/'Cargo.toml'] = {'source':'fixture:generated-client','sha256':p.tree_digest(client_root),
                                           'edges':[(client_root/'Cargo.toml',subject)]}
    (root/'Cargo.toml').write_text('[workspace]\nresolver = "2"\nmembers = '+json.dumps(names)+'\n')
    return trusted, clients


def check_notices(member, staging):
    keys = {(r['name'],r['version'],r['source']) for r in member['notice_entries']}
    expected = {(r['name'],r['version'],r['source']) for r in member['allowed_dependencies']}
    if keys != expected or len(keys) != len(member['notice_entries']):
        raise p.PolicyError('NOTICE_INCOMPLETE')
    for n in member['notice_entries']:
        record = next((r for r in staging['packages'] if (r['name'],r['version'],r['source']) == (n['name'],n['version'],n['source'])),None)
        if record is None: raise p.PolicyError('SOURCE_UNAVAILABLE','BLOCKED')
        manifest = tomllib.loads((record['root']/'Cargo.toml').read_text())
        expression = manifest['package'].get('license')
        if expression != n['license_expression']:
            raise p.PolicyError('NOTICE_LICENSE_MISMATCH')
        # Option choice is an explicit reviewed matrix input; preserve byte evidence.
        if not n['selected_option'] or not n['files']:
            raise p.PolicyError('NOTICE_INCOMPLETE')
        if not n['bundled']:
            for f in n['files']:
                p.check_hash(p.relative(record['root'],f['path']),f['sha256'],'LICENSE_TEXT_MISMATCH')


def run_member(ex, member, matrix_root, policy_only):
    prefix = member['id']; original = Path(matrix_root)/member['manifest']
    grant=None
    source_digest=None
    product = member['role']=='product'
    copied = ex.output/'subjects'/prefix/('subject' if product else '')
    source_lock = copied.parent/'Cargo.lock' if product else copied/'Cargo.lock'
    archive_lock = None
    def workspace(root, child):
        root.mkdir(parents=True,exist_ok=True)
        boundary=root/'Cargo.toml'
        boundary.write_text('[workspace]\nresolver = "2"\nmembers = '+json.dumps([child])+'\n')
        ex.report['staged_inputs'].append({'kind':'staging-workspace','path':str(boundary),'sha256':p.sha(boundary)})
    def prepare(r):
        nonlocal grant,source_digest,original
        original=p.relative(matrix_root,member['manifest'])
        grant=p.original_grant(original.parent,'fixture:'+prefix,ex.matrix['approved_build_inputs'])
        source_digest=grant['sha256']
        p.inspect_manifest(original)
        p.check_licenses(original.parent,member['license_files'],member['notice_entries'],member['role'])
        check_notices(member,ex.staging)
        if product: workspace(copied.parent,copied.name)
        p.source_copy(original.parent,copied)
        r['input_sha256'] = source_digest
        r['observed'] = {'source':str(original),'copied_source_sha256':p.tree_digest(copied)}
    ex.step(prefix+'-source',prepare)
    msrv = ex.matrix['toolchains'][0]
    trusted_original = {}
    packaging_target = ex.output/'targets'/prefix/'package'
    def lock(r):
        nonlocal grant
        args=['generate-lockfile','--offline']
        if any(v['path']=='Cargo.lock' for v in grant['original_files']): args.append('--locked')
        if product and (copied/'Cargo.lock').is_file(): shutil.copyfile(copied/'Cargo.lock',source_lock)
        ex.command(r,msrv,copied/'Cargo.toml',args,packaging_target,lock_path=source_lock)
        if product:
            shutil.copyfile(source_lock,copied/'Cargo.lock')
            ex.report['staged_inputs'].append({'kind':'staging-lock-mapping','workspace_lock':str(source_lock),'package_lock':str(copied/'Cargo.lock'),'sha256':p.sha(source_lock)})
        grant=p.copied_mapping(grant,copied)
        trusted_original[copied/'Cargo.toml']=grant
        p.record_transformation(ex,grant,copied)
    ex.step(prefix+'-lock',lock)
    source_metadata=ex.step(prefix+'-admit',lambda r:p.metadata_admission(ex,r,msrv,copied/'Cargo.toml',packaging_target,member['allowed_dependencies'],trusted_original,member['denied_packages'],member['supported_unions'][0] if member['supported_unions'] else member['minimal'],False,lock_path=source_lock))
    def package(r,t):
        result = ex.command(r,t,copied/'Cargo.toml',['package','--list','--offline','--locked','--allow-dirty'],packaging_target,lock_path=source_lock)
        observed = p.stdout(result).splitlines()
        p.package_files(observed,member['package_files']); r['observed'] = {'files':observed}
    for package_toolchain in ex.matrix['toolchains']:
        ex.step(prefix+'-package-list-'+package_toolchain['id'],lambda r,t=package_toolchain:package(r,t))
    ex.step(prefix+'-package',lambda r:ex.command(r,msrv,copied/'Cargo.toml',['package','--no-verify','--offline','--locked','--allow-dirty'],packaging_target,lock_path=source_lock))
    package_info = next(v for v in source_metadata['packages'] if Path(v['manifest_path'])==copied/'Cargo.toml')
    archive = packaging_target/'package'/(package_info['name']+'-'+package_info['version']+'.crate')
    unpacked = None
    def unpack(r):
        nonlocal unpacked,archive_lock
        unpacked = p.safe_unpack(archive,ex.output/'unpacked'/prefix,package_info['name']+'-'+package_info['version'])
        archive_lock=unpacked.parent/'Cargo.lock'
        workspace(unpacked.parent,unpacked.name)
        shutil.copyfile(unpacked/'Cargo.lock',archive_lock)
        ex.report['staged_inputs'].append({'kind':'staging-lock-mapping','workspace_lock':str(archive_lock),'package_lock':str(unpacked/'Cargo.lock'),'sha256':p.sha(archive_lock)})
        p.package_files([v['path'] for v in p.tree_records(unpacked)],member['package_files'])
        p.check_licenses(unpacked,member['license_files'],member['notice_entries'],member['role'])
        p.inspect_manifest(unpacked/'Cargo.toml')
        p.archive_mapping(grant,copied,unpacked,archive,member['package_files'])
        r['input_sha256'] = p.sha(archive)
        r['observed'] = {'archive':str(archive),'unpacked':str(unpacked),'archive_verification':'no-verify; explicit downstream stages follow'}
    ex.step(prefix+'-archive',unpack)
    trusted_subject={}
    def normalized_metadata(r):
        result=ex.command(r,msrv,unpacked/'Cargo.toml',['metadata','--offline','--locked','--no-deps','--format-version','1'],packaging_target,lock_path=archive_lock)
        semantics=p.verify_package_semantics(source_metadata,copied/'Cargo.toml',json.loads(p.stdout(result)),unpacked/'Cargo.toml')
        identity=p.archive_mapping(grant,copied,unpacked,archive,member['package_files'])
        identity['metadata_semantics_sha256']=semantics
        trusted_subject[unpacked/'Cargo.toml']=identity
        p.record_transformation(ex,identity,unpacked)
    ex.step(prefix+'-archive-metadata',normalized_metadata)
    for mode,defaults,features in configurations(member):
        workspace = ex.output/'clients'/prefix/mode
        trusted,clients = ex.step(prefix+'-'+mode+'-prepare',lambda r:generate_clients(workspace,member,unpacked,matrix_root,mode))
        trusted.update(trusted_subject)
        stem = prefix+'-'+mode
        def client_lock(r):
            ex.command(r,msrv,workspace/'Cargo.toml',['generate-lockfile','--offline'],ex.output/'unused-target')
            return p.sha(workspace/'Cargo.lock')
        lock_digest=ex.step(stem+'-lock',client_lock)
        for t in ex.matrix['toolchains']:
            cell = stem+'-'+t['id']; budget=p.CellBudget(cell); target = ex.output/'targets'/prefix/mode/t['id']
            def metadata(r):
                p.check_hash(workspace/'Cargo.lock',lock_digest,'LOCK_CHANGED')
                data = p.metadata_admission(ex,r,t,workspace/'Cargo.toml',target,member['allowed_dependencies'],trusted,member['denied_packages'],budget=budget)
                assert_subject(data,package_info['name'],features,minimal=mode in ('minimal','default') and not features)
                r['observed'] = {'independent_lock':str(workspace/'Cargo.lock'),'subject_features':features,'client_count':len(clients)}
            try:
                ex.step(cell+'-admit',metadata)
                if policy_only: continue
                ex.step(cell+'-check',lambda r:ex.command(r,t,workspace/'Cargo.toml',['check','--offline','--locked','--all-targets'],target,budget=budget))
                ex.step(cell+'-test',lambda r:ex.command(r,t,unpacked/'Cargo.toml',['test','--offline','--locked','--lib','--tests'],target,features,defaults,budget=budget,lock_path=archive_lock))
                def doctest(r):
                    result = ex.command(r,t,unpacked/'Cargo.toml',['test','--offline','--locked','--doc'],target,features,defaults,'DOCTEST_FAILED',budget=budget,lock_path=archive_lock)
                    if not re.search(r'test result: ok\. [1-9][0-9]* passed',p.stdout(result)):
                        raise p.PolicyError('DOCTEST_MISSING')
                ex.step(cell+'-doc',doctest)
                for client in clients:
                    client_name = 'sb02-'+mode+'-'+client['id']
                    ex.step(cell+'-run-'+client['id'],lambda r,name=client_name:ex.command(r,t,workspace/'Cargo.toml',['run','--offline','--locked','--package',name],target,budget=budget))
            except p.PolicyError:
                continue


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,default=ROOT/'Cargo.toml')
    parser.add_argument('--matrix',type=Path,required=True)
    parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--policy-only',action='store_true')
    args = parser.parse_args(argv)
    ex = None
    try:
        matrix_path=args.matrix.resolve(); m=p.validate_matrix(matrix_path,'features')
        manifest=args.manifest.resolve(); p.inspect_config_ancestors(manifest.parent); p.inspect_manifest(manifest)
        members=m['fixture_members']+m['members']
        sources=[matrix_path.parent,manifest.parent,*[p.relative(matrix_path.parent,c['manifest'],False).parent for c in members]]
        p.validate_report_target(args.report,sources)
        output=p.fresh_output(args.output_dir,sources)
        # Root repository contains assigned private output roots. A run under the
        # repository's ignored administrative tree is allowed only outside all
        # actual fixture/probe source trees; do not treat root config as source.
        ex=p.Execution('check_features',matrix_path,m,output,manifest)
        ex.reserve('inputs',phase='staging')
        for t in m['toolchains']:
            for suffix in ('','-rustc','-cargo'):
                ex.reserve('identity-'+t['id']+suffix,role='configuration',toolchain=t['id'],phase='identity'+suffix)
        for t in m['toolchains']: ex.reserve('root-'+t['id'],role='configuration',toolchain=t['id'],phase='metadata')
        for member in members:
            prefix=member['id']
            for phase in ('source','lock','admit','package-list-msrv','package-list-current','package','archive','archive-metadata'):
                ex.reserve(prefix+'-'+phase,member['role'],phase=phase)
            for mode,_,_ in configurations(member):
                ex.reserve(prefix+'-'+mode+'-prepare',member['role'],phase='prepare')
                ex.reserve(prefix+'-'+mode+'-lock',member['role'],phase='lock')
                for t in m['toolchains']:
                    stem=prefix+'-'+mode+'-'+t['id']
                    phases=['admit','check','test','doc']+['run-'+v['id'] for v in (member['clients'] if mode.startswith('union-') else member['clients'][:1])]
                    for phase in phases: ex.reserve(stem+'-'+phase,member['role'],t['id'],phase)
        ex.staging=ex.step('inputs',lambda r:p.stage_inputs(m['cargo_inputs'],output))
        ex.report['staged_inputs']=ex.staging['staged_inputs']
        for t in m['toolchains']:
            ex.report['toolchains'].append(ex.step('identity-'+t['id'],lambda r:p.toolchain_info(t,output,ex)))
            def root_metadata(r):
                args=['metadata','--offline','--locked','--format-version','1','--filter-platform',p.HOST] if m['members'] else ['metadata','--offline','--no-deps','--format-version','1']
                result=ex.command(r,t,manifest,args,output/'root-target')
                metadata=json.loads(p.stdout(result)); actual={str(Path(v['manifest_path']).resolve()) for v in metadata['packages'] if v['id'] in metadata['workspace_members']}
                declared={str(p.relative(matrix_path.parent,v['manifest']).resolve()) for v in m['members']}
                if actual != declared: raise p.PolicyError('UNREGISTERED_MEMBER',detail={'actual_count':len(actual),'registered_count':len(declared)})
                r['observed']={'real_members':len(actual),'available_storage_bytes':shutil.disk_usage(output).free,
                               'environment':'reconstructed; inherited Cargo/Rust overrides absent'}
            ex.step('root-'+t['id'],root_metadata,'NOT_APPLICABLE')
            ex.by_id['root-'+t['id']]['reason_code']='CONFIGURATION_ONLY' if not m['members'] else 'MEMBERS_REGISTERED'
        for member in members:
            try: run_member(ex,member,matrix_path.parent,args.policy_only)
            except p.PolicyError: continue
        return ex.finish(args.report)
    except p.InputError as e:
        print(str(e)[:1024],file=sys.stderr); return 2
    except (p.PolicyError,OSError,tomllib.TOMLDecodeError) as e:
        if ex: return ex.abort(e,args.report)
        print(str(e)[:1024],file=sys.stderr); return 3 if isinstance(e,p.PolicyError) and e.status=='BLOCKED' else 2
    except Exception as error:
        print('INTERNAL_ERROR: '+type(error).__name__,file=sys.stderr)
        if ex: return ex.abort(error,args.report)
        return 1


if __name__ == '__main__':
    sys.exit(main())
