# SPDX-License-Identifier: Apache-2.0
"""Actual source/archive/API matrix for LX03, called by execute.py."""
import json
from pathlib import Path
import shutil
import sys

NEW_FILES = ['src/file/read.rs','src/file/read/tests.rs','tests/positional_read.rs',
    'tests/support/read_adopted.rs','tests/support/read_opened.rs',
    'tests/ui/read_positive.rs','tests/ui/read_private.rs','tests/ui/read_mut.rs',
    'tests/ui/read_observations_private.rs','tests/ui/read_charges_private.rs',
    'tests/ui/read_limits_default.rs','tests/ui/read_owner.rs']


def run(ex, root, matrix, command, p):
    out=ex.output
    # A gitless projection retains every base package, root metadata and client
    # input. The source projection is byte-checked before every stage is bound.
    source=out/'source';source.mkdir()
    for name in ['Cargo.toml','Cargo.lock','package-policy.json']:shutil.copyfile(root/name,source/name)
    shutil.copytree(root/'crates',source/'crates')
    shutil.copytree(root/'tests/package-policy',source/'tests/package-policy')
    member=next(m for m in matrix['members'] if m['id']=='scopebase-linux')
    assert len(member['package_files'])==len(set(member['package_files'])), 'duplicate base package files'
    added=[f for f in NEW_FILES if f not in member['package_files']]
    expected=sorted(set(member['package_files'])|set(NEW_FILES))
    ex.report['delivery_source']={'path':str(source),'original_crate_sha256':p.tree_digest(root/'crates/scopebase-linux'),'projected_crate_sha256':p.tree_digest(source/'crates/scopebase-linux'),'workspace_lock_sha256':p.sha(source/'Cargo.lock')}
    assert ex.report['delivery_source']['original_crate_sha256']==ex.report['delivery_source']['projected_crate_sha256']
    projection=json.loads(json.dumps(matrix))
    next(m for m in projection['members'] if m['id']=='scopebase-linux')['package_files']=expected
    (source/'package-policy.json').write_text(json.dumps(projection,indent=2)+'\n')
    ex.report['policy_delta']={'member':'scopebase-linux','added_package_files':added,'removed_package_files':[],'projection':str(source/'package-policy.json'),'projection_sha256':p.sha(source/'package-policy.json'),'combined_root_gate':False,'proposed_public_clients':['tests/support/read_adopted.rs','tests/support/read_opened.rs'],'proposed_description':'ScopeBase retained regular-file acquisition, bounded positional reads and descriptor observations'}
    cells=[]
    for t in matrix['toolchains']:
        # Retain actual compiler identity/binary/configuration inputs.
        for tool in ['rustc','cargo']:
            ident='identity-'+t['id']+'-'+tool
            ex.reserve(ident,role='configuration',toolchain=t['id'],phase='identity')
            def identity(row,tool=tool,t=t):
                env=p.clean_env(out,t,out/'identity-target')
                result=p.run([Path(t['root'])/'bin'/tool,'-Vv'],root,env,out/'logs'/ident)
                ex.attach(row,result);row['run_result']=result;p.succeeded(result)
                row.update(binary_sha256=p.sha(Path(t['root'])/'bin'/tool),environment=env,observed=p.stdout(result))
            ex.step(ident,identity)
        for cfg,flags,features,defaults in [('minimal',['--no-default-features'],[],False),('default',[],[],True),('union',['--all-features'],['mapping','process','supervision','walk'],False)]:
            stem=t['id']+'-'+cfg
            target=out/'targets'/stem/'package'
            package_list=command(stem+'-package-list',t,source,['package','--offline','--locked','--allow-dirty','-p','scopebase-linux','--list',*flags],target)
            observed=p.stdout(package_list).splitlines();p.package_files(observed,expected)
            ex.by_id[stem+'-package-list']['observed']={'files':observed}
            command(stem+'-package',t,source,['package','--offline','--locked','--allow-dirty','-p','scopebase-linux','--no-verify',*flags],target)
            archive=target/'package/scopebase-linux-0.1.0.crate'
            unpacked=p.safe_unpack(archive,out/'archives'/stem,'scopebase-linux-0.1.0')
            p.package_files([r['path'] for r in p.tree_records(unpacked)],expected)
            # Isolate this pristine archive from the enclosing repository's
            # workspace without editing its delivered Cargo.toml or lock.
            (unpacked.parent/'Cargo.toml').write_text('[workspace]\nresolver = "2"\nmembers = ["scopebase-linux-0.1.0"]\n')
            shutil.copyfile(unpacked/'Cargo.lock',unpacked.parent/'Cargo.lock')
            # Logical package contents must exactly preserve all source fixtures.
            for rel in expected:
                if rel in ['Cargo.lock','Cargo.toml','Cargo.toml.orig']:continue
                p.check_hash(unpacked/rel,p.sha(source/'crates/scopebase-linux'/rel),'ARCHIVE_SOURCE_MISMATCH')
            cell={'compiler':t['version'],'configuration':cfg,'flags':flags,'archive':str(archive),'archive_sha256':p.sha(archive),'archive_lock_sha256':p.sha(unpacked/'Cargo.lock'),'forms':[]}
            cells.append(cell)
            for form,workspace,subject in [('source',source,source/'crates/scopebase-linux'),('unpacked-crate',unpacked.parent,unpacked)]:
                prefix=stem+'-'+form;build=out/'targets'/prefix
                selectors=[('lib',['--lib']),('positional_read',['--test','positional_read']),('controls',['--test','controls']),('traits',['--test','traits']),('held_file',['--test','held_file']),('doc',['--doc']),('all-targets',['--all-targets'])]
                for suffix,selector in selectors:
                    argv=['test','--offline','--locked',*(['-p','scopebase-linux'] if form=='source' else []),*flags,*selector,*(['--manifest-path',str(subject/'Cargo.toml')] if form=='unpacked-crate' else [])]
                    result=command(prefix+'-'+suffix,t,workspace,argv,build)
                    text=p.stdout(result)
                    if suffix!='all-targets' and not __import__('re').search(r'test result: ok\. [1-9][0-9]* passed',text):raise p.PolicyError('EMPTY_TEST_SELECTION')
                clients=out/'clients'/prefix;(clients/'src/bin').mkdir(parents=True)
                cases=p.read_json(subject/'tests/ui/cases.json')
                positives={'authority_positive':subject/cases['positive'],'control_positive':subject/'tests/ui/control_positive.rs','read_positive':subject/'tests/ui/read_positive.rs',
                    'read_adopted':subject/'tests/support/read_adopted.rs','read_opened':subject/'tests/support/read_opened.rs',
                    'client_linux_minimal':source/'tests/package-policy/clients/linux-minimal.rs','client_linux_union':source/'tests/package-policy/clients/linux-union.rs'}
                for name,path in positives.items():shutil.copyfile(path,clients/'src/bin'/f'{name}.rs')
                for case in cases['cases']:shutil.copyfile(subject/case['source'],clients/'src/bin'/(case['id']+'.rs'))
                manifest='[package]\nname = '+json.dumps('lx03-'+prefix)+'\nversion = "0.1.0"\nedition = "2021"\nrust-version = "1.88.0"\npublish = false\n[workspace]\n[dependencies]\nscopebase-linux = { path = '+json.dumps(str(subject))+', version = "=0.1.0", default-features = '+str(defaults).lower()+', features = '+json.dumps(features)+' }\n'
                (clients/'Cargo.toml').write_text(manifest)
                client_target=out/'targets'/prefix/'clients'
                command(prefix+'-client-lock',t,clients,['generate-lockfile','--offline'],client_target)
                metadata=command(prefix+'-client-metadata',t,clients,['metadata','--offline','--locked','--format-version','1','--filter-platform',p.HOST],client_target)
                data=json.loads(p.stdout(metadata));subjects=[v for v in data['packages'] if v['name']=='scopebase-linux']
                if len(subjects)!=1 or Path(subjects[0]['manifest_path']).resolve()!=(subject/'Cargo.toml').resolve() or subjects[0]['version']!='0.1.0':raise p.PolicyError('SUBJECT_IDENTITY_MISMATCH')
                actual=next(n['features'] for n in data['resolve']['nodes'] if n['id']==subjects[0]['id'])
                if set(actual)-{'default'}!=set(features):raise p.PolicyError('FEATURE_UNION_MISMATCH')
                wanted={(v['name'],v['version'],v['source']) for v in member['allowed_dependencies']}
                observed={(v['name'],v['version'],v['source']) for v in data['packages'] if v['source'] is not None}
                if observed!=wanted:raise p.PolicyError('DEPENDENCY_CLOSURE_MISMATCH')
                ex.by_id[prefix+'-client-metadata']['resolved_packages']=subjects
                ex.by_id[prefix+'-client-metadata']['resolved_features']=actual
                for name in positives:
                    command(prefix+'-'+name,t,clients,['run','--offline','--locked','--bin',name],client_target)
                for case in cases['cases']:
                    command(prefix+'-ui-'+case['id'],t,clients,['check','--offline','--locked','--bin',case['id'],'--message-format=json'],client_target,
                        dict(code=case['code'],contains=case['contains'],source='src/bin/'+case['id']+'.rs',line=case['line']))
                cell['forms'].append({'form':form,'subject':str(subject),'subject_sha256':p.tree_digest(subject),'positive_clients':list(positives),'exact_refusals':len(cases['cases']),'status':'PASS'})
                # Every execution row binds both the actual consumer and its subject.
                for ident,row in ex.by_id.items():
                    if ident.startswith(prefix):row.update(subject_root=str(subject),subject_sha256=p.tree_digest(subject),archive_sha256=cell['archive_sha256'],compiler_binary_sha256=p.sha(Path(t['root'])/'bin/rustc'),configuration=cfg,features=features)
    ex.report['delivery_cells']=cells
    ex.report['delivery_qualification']='LX03 bounded reads/source/archive/API only; runtime/installed profiles open'
