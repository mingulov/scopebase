# SPDX-License-Identifier: Apache-2.0
"""Manifest, archive and real offline Cargo package-policy controls."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools' / 'build'))
try:
    import common as policy
except ImportError:
    policy = None


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(policy, 'the bounded build-policy implementation is absent')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.subject = self.root / 'subject'; self.subject.mkdir()
        (self.subject / 'src').mkdir()
        (self.subject / 'src/lib.rs').write_text('pub fn answer() -> u32 { 42 }')
        self.manifest = self.subject / 'Cargo.toml'
        self.base = '[package]\nname="subject"\nversion="0.1.0"\nedition="2021"\n'
        self.manifest.write_text(self.base)
        sibling = self.root / 'donor-helper'; sibling.mkdir()
        (sibling / 'Cargo.toml').write_text('[package]\nname="donor-helper"\nversion="0.1.0"\n')

    def test_all_dependency_kinds_and_overrides_refuse_existing_sibling(self):
        policy.inspect_manifest(self.manifest)
        for header, value in (
            ('dependencies', '{ path="../donor-helper" }'),
            ('build-dependencies', '{ path="../donor-helper" }'),
            ('dev-dependencies', '{ path="../donor-helper" }'),
            ("target.'cfg(unix)'.dependencies", '{ path="../donor-helper", optional=true }'),
            ('patch.crates-io', '{ path="../donor-helper" }'),
            ('workspace.dependencies', '{ path="../donor-helper" }'),
            ('replace', '{ path="../donor-helper" }'),
        ):
            with self.subTest(header=header):
                self.manifest.write_text(self.base + f'[{header}]\n"helper"={value}\n')
                with self.assertRaisesRegex(policy.PolicyError, 'EXTERNAL_PATH_DEPENDENCY'):
                    policy.inspect_manifest(self.manifest)
        (self.subject / 'linked').symlink_to(self.root / 'donor-helper', target_is_directory=True)
        self.manifest.write_text(self.base + '[dependencies]\nhelper={path="linked"}\n')
        with self.assertRaisesRegex(policy.PolicyError, 'EXTERNAL_PATH_DEPENDENCY'):
            policy.inspect_manifest(self.manifest)

    def test_script_discovery_and_nonstandard_path(self):
        self.assertIsNone(policy.inspect_manifest(self.manifest)['build_script'])
        (self.subject / 'build.rs').write_text('fn main() {}')
        self.assertEqual(policy.inspect_manifest(self.manifest)['build_script'], 'build.rs')
        self.manifest.write_text(self.base + 'build="other.rs"\n')
        (self.subject / 'other.rs').write_text('fn main() {}')
        self.assertEqual(policy.inspect_manifest(self.manifest)['build_script'], 'other.rs')

    def test_package_allowlist_requires_the_selected_private_sentinel_to_be_rejected(self):
        policy.package_files(['Cargo.toml', 'src/lib.rs'], ['Cargo.toml', 'src/lib.rs'])
        with self.assertRaisesRegex(policy.PolicyError, 'UNEXPECTED_PACKAGE_FILE'):
            policy.package_files(['Cargo.toml', 'src/lib.rs', 'private-evidence.txt'],
                                 ['Cargo.toml', 'src/lib.rs'])

    def test_license_delivery_checks_real_bytes_and_exact_notice_inventory(self):
        license_path = self.subject / 'LICENSE-APACHE'
        license_path.write_bytes(b'approved license\n')
        licenses = [{'path': 'LICENSE-APACHE', 'sha256': hashlib.sha256(b'approved license\n').hexdigest()}]
        entries = [{'name': 'helper', 'version': '1.0.0', 'source': 'registry:fixture',
                    'license_expression': 'Apache-2.0', 'selected_option': 'Apache-2.0',
                    'bundled': True, 'files': [{'path': 'LICENSE-APACHE', 'sha256': licenses[0]['sha256']}]}]
        notice = self.subject / 'THIRD-PARTY-NOTICES.md'
        notice.write_text(policy.NOTICE_INTRO + '\n```json\n' + json.dumps(entries, sort_keys=True) + '\n```\n')
        policy.check_licenses(self.subject, licenses, entries)
        license_path.unlink()
        with self.assertRaisesRegex(policy.PolicyError, 'LICENSE_TEXT_MISSING'):
            policy.check_licenses(self.subject, licenses, entries)
        license_path.write_bytes(b'changed')
        with self.assertRaisesRegex(policy.PolicyError, 'LICENSE_TEXT_MISMATCH'):
            policy.check_licenses(self.subject, licenses, entries)
        license_path.write_bytes(b'approved license\n')
        notice.write_text(policy.NOTICE_INTRO + '\n```json\n[]\n```\n')
        with self.assertRaisesRegex(policy.PolicyError, 'NOTICE_INCOMPLETE'):
            policy.check_licenses(self.subject, licenses, entries)

    def test_product_notices_are_role_specific_and_keep_license_checks(self):
        intro = 'ScopeBase package dependency notices. Dependency references are not bundled unless explicitly marked.'
        notice = self.subject / 'THIRD-PARTY-NOTICES.md'
        license_path = self.subject / 'LICENSE-APACHE'
        license_path.write_bytes(b'approved license\n')
        licenses = [dict(path='LICENSE-APACHE', sha256=hashlib.sha256(b'approved license\n').hexdigest())]
        notice.write_text(intro + '\n```json\n[]\n```\n')
        policy.check_licenses(self.subject, licenses, [], role='product')
        with self.assertRaisesRegex(policy.PolicyError, 'NOTICE_INCOMPLETE'):
            policy.check_licenses(self.subject, licenses, [])
        notice.write_text(policy.NOTICE_INTRO + '\n```json\n[]\n```\n')
        policy.check_licenses(self.subject, licenses, [])
        with self.assertRaisesRegex(policy.PolicyError, 'NOTICE_INCOMPLETE'):
            policy.check_licenses(self.subject, licenses, [], role='product')
        with self.assertRaisesRegex(policy.PolicyError, 'NOTICE_ROLE_UNKNOWN'):
            policy.check_licenses(self.subject, licenses, [], role='other')
        for body in ('[]', '[{}]', '[{"name":"one","name":"two"}]'):
            notice.write_text(intro + '\n```json\n' + body + '\n```\n')
            if body != '[]':
                with self.assertRaisesRegex(policy.PolicyError, 'NOTICE_INCOMPLETE'):
                    policy.check_licenses(self.subject, licenses, [], role='product')
        notice.unlink()
        with self.assertRaisesRegex(policy.PolicyError, 'NOTICE_INCOMPLETE'):
            policy.check_licenses(self.subject, licenses, [], role='product')
        notice.write_text(intro + '\n```json\n[]\n```\n')
        license_path.write_bytes(b'changed')
        with self.assertRaisesRegex(policy.PolicyError, 'LICENSE_TEXT_MISMATCH'):
            policy.check_licenses(self.subject, licenses, [], role='product')

    def test_RR2_complete_metadata_projection_and_explicit_manifest_surface(self):
        import copy
        other=self.root/'relocated'; other.mkdir(); (other/'src').mkdir()
        normalized=other/'Cargo.toml'; normalized.write_text(self.base+'autolib=false\nreadme=false\n[lib]\npath="src/lib.rs"\n')
        def metadata(root):
            return {'packages':[dict(id=str(root),manifest_path=str(root/'Cargo.toml'),name='subject',version='0.1.0',
                authors=['approved'],description='description',homepage='homepage',repository='repository',license='Apache-2.0',
                license_file=None,readme=None,rust_version='1.88.0',documentation='docs',keywords=['key'],categories=['category'],
                source=None,edition='2021',links=None,default_run=None,publish=[],metadata={},features={},dependencies=[],
                targets=[dict(name='subject',kind=['lib'],crate_types=['lib'],edition='2021',doc=True,doctest=True,test=True,src_path=str(root/'src/lib.rs'))])]}
        original=metadata(self.subject); changed=metadata(other)
        policy.verify_package_semantics(original,self.manifest,changed,normalized)
        # Projection/report units, separate from the actual Cargo authors control.
        for key in ('authors','description','homepage','repository','license','license_file','readme','rust_version','documentation','keywords','categories'):
            mutant=copy.deepcopy(changed); mutant['packages'][0][key]=['changed'] if key in ('authors','keywords','categories') else 'changed'
            with self.subTest(field=key),self.assertRaisesRegex(policy.PolicyError,'ARCHIVE_SEMANTICS_CHANGED'):
                policy.verify_package_semantics(original,self.manifest,mutant,normalized)
        for key in ('readme','license_file'):
            left=copy.deepcopy(original); right=copy.deepcopy(changed)
            left['packages'][0][key]='./LICENSE'; right['packages'][0][key]='LICENSE'
            with self.subTest(relative_string=key),self.assertRaisesRegex(policy.PolicyError,'ARCHIVE_SEMANTICS_CHANGED'):
                policy.verify_package_semantics(left,self.manifest,right,normalized)
        normalized.write_text(self.base+'include=["src/lib.rs"]\n')
        with self.assertRaisesRegex(policy.PolicyError,'ARCHIVE_SEMANTICS_CHANGED'):
            policy.verify_package_semantics(original,self.manifest,changed,normalized)
        for surface in ('[profile.dev]\nopt-level=1\n','[lib]\nharness=false\n','[package.unrecognized]\nx=true\n','[workspace]\nresolver="2"\n','[dependencies]\nx={version="1",artifact="bin"}\n'):
            self.manifest.write_text(self.base+surface)
            with self.subTest(surface=surface),self.assertRaisesRegex(policy.PolicyError,'MANIFEST_SURFACE_UNSUPPORTED'):
                policy.original_grant(self.subject,'fixture:subject',[])


if __name__ == '__main__':
    unittest.main()

class RealCargoControls(unittest.TestCase):
    """PP02/03/04/05/06/08/10 use real Cargo and owned source mutants.

    Every subprocess is under the existing cooperative build lease. This suite
    needs the exact installed compilers and the matrix's frozen acquired inputs.
    """
    @classmethod
    def setUpClass(cls):
        import subprocess
        cls.temp = tempfile.TemporaryDirectory(prefix='sb02-policy-')
        cls.root = Path(cls.temp.name)
        cls.matrix = json.loads((ROOT/'tests/package-policy/matrix.json').read_text())
        cls.inputs = cls.matrix['cargo_inputs']
        cls.t = cls.matrix['toolchains'][0]
        cls.counter = 0
        cls.positive = cls.root/'positive'
        cls.positive_report = cls.root/'positive.json'
        result = subprocess.run([str(ROOT/'bin/scopebase-build'),'--',sys.executable,
            str(ROOT/'tools/build/check_features.py'),'--manifest',str(ROOT/'tests/package-policy/fixtures/empty-workspace/Cargo.toml'),
            '--matrix',str(ROOT/'tests/package-policy/matrix.json'),'--output-dir',str(cls.positive),
            '--report',str(cls.positive_report)],capture_output=True,text=True)
        if result.returncode:
            raise AssertionError('positive Cargo setup failed: '+result.stdout+result.stderr)
        cls.report = json.loads(cls.positive_report.read_text())

    @classmethod
    def tearDownClass(cls):
        # Evidence is retained by design; no generated target/source is deleted.
        cls.temp._finalizer.detach()

    def directory(self, name):
        type(self).counter += 1
        p = self.root/(str(self.counter)+'-'+name); p.mkdir()
        return p

    def cargo(self, source, arguments, output, name, env_extra=None, toolchain=None):
        import subprocess
        t=toolchain or self.t
        env = policy.clean_env(output,t,output/'target')
        if env_extra: env.update(env_extra)
        import os
        shared_root = Path(os.environ['XDG_RUNTIME_DIR'])/'scopebase-locks' if os.environ.get('XDG_RUNTIME_DIR') else Path.home()/'.cache/scopebase/locks'
        argv = [str(ROOT/'bin/scopebase-build'),'--lock-root',str(shared_root),'--',str(Path(t['root'])/'bin/cargo'),*arguments,'--manifest-path',str(source/'Cargo.toml')]
        result = policy.run(argv,source,env,output/name)
        return result

    def fixture(self,name='fixture',build='build.rs'):
        output = self.directory(name); source = output/'source'; (source/'src').mkdir(parents=True)
        (source/'Cargo.toml').write_text('[package]\nname="script-fixture"\nversion="0.1.0"\nedition="2021"\nbuild='+json.dumps(build)+'\n[workspace]\n')
        (source/'src/lib.rs').write_text('pub fn value() -> u32 { 42 }')
        return output,source

    def metadata(self,output,source):
        result=self.cargo(source,['generate-lockfile','--offline'],output,'lock')
        policy.succeeded(result)
        result=self.cargo(source,['metadata','--offline','--locked','--format-version','1'],output,'metadata')
        policy.succeeded(result)
        return json.loads(policy.stdout(result))

    def test_PP02_PP03_build_script_and_included_helper_admission(self):
        for build in ('build.rs','other.rs'):
            output,source=self.fixture(build.replace('.','-'),build)
            marker=output/'approved-marker'
            (source/build).write_text('include!("helper.rs");')
            (source/'helper.rs').write_text('fn main() { std::fs::write('+json.dumps(str(marker))+', "executed").unwrap(); }')
            metadata=self.metadata(output,source)
            original=policy.fixture_digest(source)
            grant=dict(name='script-fixture',version='0.1.0',source='fixture:script',sha256=original,build_script=build,reason='Inspected ordinary Rust file marker fixture')
            trusted={source/'Cargo.toml':dict(source='fixture:script',sha256=original)}
            with self.assertRaisesRegex(policy.PolicyError,'APPROVAL_REQUIRED'):
                policy.admit(metadata,[],[],{'packages':[]},trusted)
            self.assertFalse(marker.exists())
            policy.admit(metadata,[],[grant],{'packages':[]},trusted)
            result=self.cargo(source,['check','--offline','--locked'],output,'approved-check')
            policy.succeeded(result); self.assertEqual(marker.read_text(),'executed')
            fake=output/'bpf-linker'; denied_marker=output/'bpf-marker'
            fake.write_text('#!/bin/sh\nprintf forbidden > '+str(denied_marker)+'\n'); fake.chmod(0o700)
            # Prove the owned fake is capable of making its marker.
            import subprocess
            subprocess.run([str(fake)],check=True); self.assertTrue(denied_marker.exists()); denied_marker.unlink()
            top=(source/build).read_bytes()
            (source/'helper.rs').write_text('fn main() { std::process::Command::new('+json.dumps(str(fake))+').status().unwrap(); }')
            self.assertEqual((source/build).read_bytes(),top)
            with self.assertRaisesRegex(policy.PolicyError,'APPROVED_INPUT_CHANGED'):
                policy.admit(metadata,[],[grant],{'packages':[]},trusted)
            self.assertFalse(denied_marker.exists())
            with self.assertRaisesRegex(policy.PolicyError,'APPROVAL_REQUIRED'):
                policy.admit(metadata,[],[],{'packages':[]},trusted)
            self.assertFalse(denied_marker.exists())

    def test_PP04_PP08_real_union_clients_independent_locks_and_same_compiler_inputs(self):
        rows=self.report['rows']
        for mode in ('minimal','default','union-0'):
            lock=self.positive/'clients/feature-subject'/mode/'Cargo.lock'
            self.assertTrue(lock.is_file())
            matching=[r for r in rows if r['id'].startswith('feature-subject-'+mode+'-') and r['phase']=='admit']
            self.assertEqual(len(matching),2)
            self.assertEqual({r['lock_sha256'] for r in matching},{hashlib.sha256(lock.read_bytes()).hexdigest()})
        locks=[self.positive/'clients/feature-subject'/v/'Cargo.lock' for v in ('minimal','default','union-0')]
        self.assertEqual(len({v.stat().st_ino for v in locks}),3)
        run_rows=[r for r in rows if '-union-0-' in r['id'] and r['phase'].startswith('run-')]
        self.assertEqual(len(run_rows),4)
        self.assertTrue(all(r['status']=='PASS' for r in run_rows))
        import check_features
        subject=self.positive/'unpacked/feature-subject/sb02-feature-subject-0.1.0'
        for mode,wanted in (('minimal',[]),('union-0',['json'])):
            md=next(r for r in rows if r['id']=='feature-subject-'+mode+'-msrv-admit')
            data=json.loads(Path(md['logs']['stdout']['path']).read_text())
            check_features.assert_subject(data,'sb02-feature-subject',wanted,minimal=mode=='minimal')
            if mode=='union-0':
                # Wrong aggregation drops json-client's features after both ran.
                mutant=json.loads(json.dumps(data))
                subject_id=next(p['id'] for p in mutant['packages'] if p['name']=='sb02-feature-subject')
                next(n for n in mutant['resolve']['nodes'] if n['id']==subject_id)['features']=[]
                with self.assertRaisesRegex(policy.PolicyError,'FEATURE_UNION_MISMATCH'):
                    check_features.assert_subject(mutant,'sb02-feature-subject',['json'])
        # Actual Cargo resolves the unconditional optional-dependency mutant.
        output=self.directory('unconditional'); copied=output/'subject'
        import shutil
        shutil.copytree(subject,copied)
        manifest=copied/'Cargo.toml'
        manifest.write_text(manifest.read_text().replace('optional = true','optional = false').replace('    "dep:serde",\n','').replace('    "dep:serde_json",\n',''))
        staged=policy.stage_inputs(self.inputs,output)
        md=self.cargo(copied,['metadata','--offline','--format-version','1','--no-default-features'],output,'unconditional-metadata')
        policy.succeeded(md)
        with self.assertRaisesRegex(policy.PolicyError,'MINIMAL_FEATURE_LEAK'):
            check_features.assert_subject(json.loads(policy.stdout(md)),'sb02-feature-subject',[],True)
        lock=copied/'Cargo.lock'; expected=policy.sha(lock)
        lock.write_text(lock.read_text()+'\n# changed input\n')
        with self.assertRaisesRegex(policy.PolicyError,'LOCK_CHANGED'):
            policy.check_hash(lock,expected,'LOCK_CHANGED')

    def test_PP05_mutated_subject_doctest_reaches_assertion(self):
        output=self.directory('doctest'); source=output/'subject'
        import shutil
        shutil.copytree(self.positive/'unpacked/feature-subject/sb02-feature-subject-0.1.0',source)
        policy.stage_inputs(self.inputs,output)
        lib=source/'src/lib.rs'; lib.write_text(lib.read_text().replace('decimal_len(10), 2','decimal_len(10), 3'))
        check=self.cargo(source,['check','--offline','--locked','--no-default-features'],output,'mutant-check')
        policy.succeeded(check)
        result=self.cargo(source,['test','--offline','--locked','--doc','--no-default-features'],output,'mutant-doc')
        self.assertNotEqual(result['exit_code'],0)
        log=policy.stdout(result)
        self.assertIn('assertion `left == right` failed',log)
        self.assertIn('left: 2',log); self.assertIn('right: 3',log)

    def test_PP06_selected_private_file_is_in_actual_cargo_package_list(self):
        output=self.directory('private'); source=output/'subject'
        import shutil
        shutil.copytree(ROOT/'tests/package-policy/fixtures/feature_subject',source)
        policy.stage_inputs(self.inputs,output)
        (source/'private-evidence.txt').write_text('owned sentinel\n')
        manifest=source/'Cargo.toml'; manifest.write_text(manifest.read_text().replace('include = [','include = ["private-evidence.txt", '))
        result=self.cargo(source,['generate-lockfile','--offline'],output,'lock'); policy.succeeded(result)
        result=self.cargo(source,['package','--list','--offline','--locked','--allow-dirty'],output,'package-list'); policy.succeeded(result)
        actual=policy.stdout(result).splitlines()
        self.assertIn('private-evidence.txt',actual)
        with self.assertRaisesRegex(policy.PolicyError,'UNEXPECTED_PACKAGE_FILE'):
            policy.package_files(actual,self.matrix['fixture_members'][0]['package_files'])

    def test_PP10_mutants_change_delivered_archive_license_and_notice_bytes(self):
        import shutil
        subject=self.positive/'unpacked/feature-subject/sb02-feature-subject-0.1.0'
        member=self.matrix['fixture_members'][0]
        for mutation,code in (('missing','LICENSE_TEXT_MISSING'),('bytes','LICENSE_TEXT_MISMATCH'),('notice','NOTICE_INCOMPLETE')):
            output=self.directory(mutation); copied=output/'subject'; shutil.copytree(subject,copied)
            if mutation=='missing': (copied/'LICENSE-APACHE').unlink()
            elif mutation=='bytes': (copied/'LICENSE-APACHE').write_bytes(b'wrong license')
            else:
                entries=member['notice_entries'][:-1]
                (copied/'THIRD-PARTY-NOTICES.md').write_text(policy.NOTICE_INTRO+'\n```json\n'+json.dumps(entries,sort_keys=True)+'\n```\n')
            with self.assertRaisesRegex(policy.PolicyError,code):
                policy.check_licenses(copied,member['license_files'],member['notice_entries'])

    def test_PP02_transitive_auto_discovered_script_is_not_executed(self):
        output,subject=self.fixture('transitive')
        manifest=subject/'Cargo.toml'; manifest.write_text(manifest.read_text().replace('build="build.rs"\n',''))
        marker=output/'transitive-fake-tool-marker'
        fake=output/'bpf-linker'; fake.write_text('#!/bin/sh\nprintf forbidden > '+str(marker)+'\n'); fake.chmod(0o700)
        (subject/'build.rs').write_text('fn main() { std::process::Command::new('+json.dumps(str(fake))+').status().unwrap(); }')
        client=output/'client'; (client/'src').mkdir(parents=True)
        (client/'Cargo.toml').write_text('[package]\nname="outer-client"\nversion="0.1.0"\nedition="2021"\n[workspace]\n[dependencies]\nscript-fixture={path='+json.dumps(str(subject))+'}\n')
        (client/'src/main.rs').write_text('fn main() { assert_eq!(script_fixture::value(),42); }')
        md=self.metadata(output,client)
        trusted={client/'Cargo.toml':dict(source='fixture:client',sha256=policy.fixture_digest(client),edges=[(client/'Cargo.toml',subject)]),subject/'Cargo.toml':dict(source='fixture:script',sha256=policy.fixture_digest(subject))}
        with self.assertRaisesRegex(policy.PolicyError,'APPROVAL_REQUIRED'):
            policy.admit(md,[],[],{'packages':[]},trusted)
        self.assertFalse(marker.exists())

    def test_PP03_PP08_frozen_vendor_archive_checksum_and_added_input_controls(self):
        import shutil
        original=json.loads(Path(self.inputs['inventory']).read_text())
        for mutation in ('source','checksum','added','missing','archive'):
            output=self.directory('identity-'+mutation); frozen=output/'frozen'; frozen.mkdir()
            inv=json.loads(json.dumps(original)); vendor=frozen/'vendor'
            shutil.copytree(original['cargo_vendor']['root'],vendor)
            config=frozen/'vendor-config.toml'
            config.write_text(Path(original['cargo_vendor']['config']).read_text().replace(original['cargo_vendor']['root'],str(vendor)))
            inv['cargo_vendor'].update(root=str(vendor),config=str(config),config_sha256=policy.sha(config))
            if mutation=='source': next(vendor.glob('serde-*/src/lib.rs')).write_text('malicious source')
            elif mutation=='checksum': next(vendor.glob('serde-*/.cargo-checksum.json')).write_text('{}\n')
            elif mutation=='added': (vendor/'unlisted-package').mkdir(); (vendor/'unlisted-package/build.rs').write_text('fn main() {}')
            elif mutation=='missing': shutil.rmtree(next(vendor.glob('serde-*')))
            else:
                archive=frozen/'input.crate'; shutil.copyfile(inv['registry_packages'][0]['archive'],archive)
                inv['registry_packages'][0]['archive']=str(archive)
                archive.write_bytes(archive.read_bytes()+b'wrong')
            inventory=frozen/'inventory.json'; inventory.write_bytes(policy.compact(inv))
            run=output/'run'; run.mkdir()
            with self.assertRaisesRegex(policy.PolicyError,'INPUT_CHANGED'):
                policy.stage_inputs({'inventory':str(inventory),'sha256':policy.sha(inventory)},run)

    def test_missing_proc_macro_approval_blocks_before_execution(self):
        output=self.directory('macro'); source=output/'source'; (source/'src').mkdir(parents=True)
        (source/'Cargo.toml').write_text('[package]\nname="macro-fixture"\nversion="0.1.0"\nedition="2021"\n[workspace]\n[lib]\nproc-macro=true\n')
        marker=output/'macro-executed'
        (source/'src/lib.rs').write_text('extern crate proc_macro; #[proc_macro] pub fn marker(x:proc_macro::TokenStream)->proc_macro::TokenStream { std::fs::write('+json.dumps(str(marker))+', "executed").unwrap(); x }')
        md=self.metadata(output,source); digest=policy.fixture_digest(source)
        trusted={source/'Cargo.toml':dict(source='fixture:macro',sha256=digest)}
        with self.assertRaisesRegex(policy.PolicyError,'APPROVAL_REQUIRED'):
            policy.admit(md,[],[],{'packages':[]},trusted)
        self.assertFalse(marker.exists())

    def test_probe_cli_real_synthetic_candidate_and_fixed_pending_denominator(self):
        import subprocess
        output=self.directory('probe-cli'); source=output/'input/probe'; (source/'src').mkdir(parents=True)
        (source/'Cargo.toml').write_text('[package]\nname="sb02-synthetic-probe"\nversion="0.1.0"\nedition="2021"\nrust-version="1.88.0"\n[workspace]\n[dependencies]\nitoa={version="=1.0.18",default-features=false,features=[]}\n')
        (source/'src/lib.rs').write_text('#[test] fn formats_literal() { let mut b=itoa::Buffer::new(); assert_eq!(b.format(123u64),"123"); }')
        seed=output/'seed'; seed.mkdir(); policy.stage_inputs(self.inputs,seed)
        result=self.cargo(source,['generate-lockfile','--offline'],seed,'seed-lock'); policy.succeeded(result)
        inv=json.loads(Path(self.inputs['inventory']).read_text())
        inv['cargo_vendor']['acquisition_locks'].append(dict(manifest=str(source/'Cargo.toml'),manifest_sha256=policy.sha(source/'Cargo.toml'),lock=str(source/'Cargo.lock'),lock_sha256=policy.sha(source/'Cargo.lock')))
        inventory=output/'inventory.json'; inventory.write_bytes(policy.compact(inv))
        record=next(r for r in inv['registry_packages'] if r['name']=='itoa')
        candidate={k:record[k] for k in ('name','version','source','sha256')}
        case=dict(id='itoa-synthetic',required=True,manifest='probe/Cargo.toml',candidate=candidate,default_features=False,features=[],tier='host_semantic',assertions=['formats_literal'],expected_fit='SATISFIED',availability='ready',compile_refusals=[],allowed_dependencies=[dict(**candidate,role='host-rust')],obligation_refs=['SB02'])
        pending=json.loads(json.dumps(case)); pending.update(id='required-pending',availability='pending_acquisition'); pending['candidate']['sha256']=None
        matrix=dict(schema_version=1,host=policy.HOST,cargo_inputs=dict(inventory=str(inventory),sha256=policy.sha(inventory)),approved_build_inputs=[],toolchains=self.matrix['toolchains'],cases=[case,pending])
        matrix_path=output/'input/matrix.json'; matrix_path.write_text(json.dumps(matrix))
        for selection,wanted in (([],3),(['--case','itoa-synthetic'],0)):
            name='selected' if selection else 'full'
            report=output/(name+'.json')
            proc=subprocess.run([str(ROOT/'bin/scopebase-build'),'--',sys.executable,str(ROOT/'tools/build/dependency_probe.py'),'--matrix',str(matrix_path),'--output-dir',str(output/name),'--report',str(report),*selection],capture_output=True,text=True)
            self.assertEqual(proc.returncode,wanted,proc.stdout+proc.stderr)
            data=json.loads(report.read_text())
            self.assertFalse(data['product_qualification'])
            self.assertFalse(data['summary']['full_matrix_complete'])
            actual=[r for r in data['rows'] if r['id'].startswith('itoa-synthetic-')]
            self.assertTrue(all(r['status']=='PASS' for r in actual))
            if selection: self.assertTrue(data['summary']['omitted_required_ids'])
            else: self.assertTrue(any(r['reason_code']=='SOURCE_UNAVAILABLE' for r in data['rows']))

    def test_F1_approved_script_traverses_cli_lock_and_archive_without_new_grant(self):
        import shutil,subprocess
        for original_lock in (False,True):
            output=self.directory('approved-cli-'+str(original_lock)); inputs=output/'input'; inputs.mkdir()
            shutil.copytree(ROOT/'tests/package-policy/fixtures',inputs/'fixtures')
            source=inputs/'fixtures/feature_subject'; manifest=source/'Cargo.toml'
            manifest.write_text(manifest.read_text().replace('[package]','[package]\nauthors=["approved"]').replace('include = [','include = ["build.rs", "helper.inc", '))
            (source/'build.rs').write_text('include!("helper.inc");\n')
            (source/'helper.inc').write_text('fn main() { let author=std::env::var("CARGO_PKG_AUTHORS").unwrap(); let marker=if author=="approved" { "approved-marker" } else { "changed-metadata-marker" }; std::fs::write(std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join(marker), author).unwrap(); }\n')
            if original_lock:
                seed=output/'seed'; seed.mkdir(); policy.stage_inputs(self.inputs,seed)
                policy.succeeded(self.cargo(source,['generate-lockfile','--offline'],seed,'original-lock'))
            matrix=json.loads(json.dumps(self.matrix)); member=matrix['fixture_members'][0]
            member['package_files']+=['build.rs','helper.inc']
            grant=dict(name='sb02-feature-subject',version='0.1.0',source='fixture:feature-subject',sha256=policy.fixture_digest(source),build_script='build.rs',reason='Inspected include helper writes only an OUT_DIR marker')
            matrix['approved_build_inputs'].append(grant)
            matrix_path=inputs/'matrix.json'; matrix_path.write_text(json.dumps(matrix))
            report=output/'report.json'; run=output/'run'
            argv=[str(ROOT/'bin/scopebase-build'),'--',sys.executable,str(ROOT/'tools/build/check_features.py'),'--manifest',str(ROOT/'tests/package-policy/fixtures/empty-workspace/Cargo.toml'),'--matrix',str(matrix_path),'--output-dir',str(run),'--report',str(report)]
            result=subprocess.run(argv,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr+report.read_text())
            data=json.loads(report.read_text())
            for mode in ('minimal','default','union-0'):
                for t in matrix['toolchains']:
                    markers=list((run/'targets/feature-subject'/mode/t['id']).rglob('approved-marker'))
                    self.assertTrue(markers,(original_lock,mode,t['id']))
                    self.assertTrue(all(p.read_text()=='approved' for p in markers))
            transformations=[r for r in data['staged_inputs'] if r['kind']=='fixture-transformation']
            self.assertTrue(transformations)
            self.assertTrue(all(r['original_source_sha256']==grant['sha256'] for r in transformations))
            self.assertEqual(transformations[0]['original_lock_sha256'],policy.sha(source/'Cargo.lock') if original_lock else None)
            # A capable fake command is never reached by stale original grants.
            fake=output/'fake-bpf-tool'; marker=output/'bad-marker'
            fake.write_text('#!/usr/bin/python3\nfrom pathlib import Path\nPath('+repr(str(marker))+').write_text("executed")\n'); fake.chmod(0o700)
            subprocess.run([str(fake)],check=True); marker.unlink()
            baseline={p.relative_to(source):p.read_bytes() for p in source.rglob('*') if p.is_file()}
            for mutation in ('helper','added','target','dependency','feature'):
                for p in source.rglob('*'):
                    if p.is_file() and p.relative_to(source) not in baseline: p.unlink()
                for p,raw in baseline.items(): (source/p).write_bytes(raw)
                if mutation=='helper': (source/'helper.inc').write_text('fn main() { std::process::Command::new('+json.dumps(str(fake))+').status().unwrap(); }')
                elif mutation=='added': (source/'added-support.rs').write_text('fn evil() {}')
                elif mutation=='target': manifest.write_text(manifest.read_text().replace('[package]','[package]\nbuild="other.rs"')); (source/'other.rs').write_text('fn main() {}')
                elif mutation=='dependency': manifest.write_text(manifest.read_text().replace('features = ["std"]','features = ["std", "derive"]',1))
                else: manifest.write_text(manifest.read_text().replace('default = []','default = ["json"]'))
                mutant_report=output/(mutation+'.json')
                badargv=argv.copy(); badargv[badargv.index(str(run))]=str(output/mutation); badargv[badargv.index(str(report))]=str(mutant_report)
                bad=subprocess.run(badargv,capture_output=True,text=True)
                self.assertEqual(bad.returncode,1,bad.stdout+bad.stderr)
                self.assertFalse(marker.exists())
                self.assertTrue(any(r['reason_code']=='APPROVED_INPUT_CHANGED' for r in json.loads(mutant_report.read_text())['rows']))

            for p in source.rglob('*'):
                if p.is_file() and p.relative_to(source) not in baseline: p.unlink()
            for p,raw in baseline.items(): (source/p).write_bytes(raw)
            original_identity=policy.original_grant(source,'fixture:feature-subject',matrix['approved_build_inputs'])
            copied_identity=policy.copied_mapping(original_identity,run/'subjects/feature-subject')
            original_md=json.loads(Path(next(r for r in data['rows'] if r['id']=='feature-subject-admit')['logs']['stdout']['path']).read_text())
            archive=Path(next(r for r in data['rows'] if r['id']=='feature-subject-archive')['observed']['archive'])
            packaged=run/'unpacked/feature-subject/sb02-feature-subject-0.1.0'
            for mutation in ('helper','support','build','dependency','feature','authors'):
                mutated=output/('archive-'+mutation); shutil.copytree(packaged,mutated)
                changed=mutated/'Cargo.toml'
                if mutation=='helper': (mutated/'helper.inc').write_text('fn main() { panic!("unapproved"); }')
                elif mutation=='support': (mutated/'added-helper.inc').write_text('unapproved support')
                elif mutation=='build': changed.write_text(changed.read_text().replace('build = "build.rs"','build = "helper.inc"'))
                elif mutation=='dependency': changed.write_text(changed.read_text().replace('default-features = false','default-features = true',1))
                elif mutation=='feature': changed.write_text(changed.read_text().replace('default = []','default = ["json"]'))
                else: changed.write_text(changed.read_text().replace('authors = ["approved"]','authors = ["changed"]').replace('    "approved",','    "changed",'))
                if mutation=='authors':
                    import tarfile
                    mutant_archive=output/'authors-only.crate'
                    with tarfile.open(mutant_archive,'w:gz') as tar:
                        for file in sorted(mutated.rglob('*')):
                            if file.is_file(): tar.add(file,arcname='sb02-feature-subject-0.1.0/'+file.relative_to(mutated).as_posix(),recursive=False)
                    mutated=policy.safe_unpack(mutant_archive,output/'authors-unpacked','sb02-feature-subject-0.1.0')
                    policy.archive_mapping(copied_identity,run/'subjects/feature-subject',mutated,mutant_archive,member['package_files'])
                    authors_control=dict(original_source_sha256=original_identity['sha256'],
                        original_lock_sha256=copied_identity['original_lock_sha256'],
                        generated_lock_sha256=copied_identity['generated_lock_sha256'],archive_sha256=policy.sha(mutant_archive),
                        original_manifest_sha256=policy.sha(source/'Cargo.toml'),normalized_manifest_sha256=policy.sha(mutated/'Cargo.toml'),
                        known_bad_runs=[],semantic_refusals=[])
                    # Deliberately bypass the semantic gate in a separate owned
                    # target to prove the unchanged script's changed branch is
                    # capable. This is the known-bad policy control, not admission.
                    for t in matrix['toolchains']:
                        bad=output/('authors-known-bad-'+t['id']); bad.mkdir()
                        policy.stage_inputs(self.inputs,bad)
                        result=self.cargo(mutated,['check','--offline','--locked','--no-default-features'],bad,'changed-author-check',toolchain=t)
                        policy.succeeded(result)
                        changed_markers=list((bad/'target').rglob('changed-metadata-marker'))
                        self.assertTrue(changed_markers)
                        self.assertTrue(all(p.read_text()=='changed' for p in changed_markers))
                        authors_control['known_bad_runs'].append(dict(toolchain=t['id'],result=result,changed_markers=[str(p) for p in changed_markers]))
                if mutation in ('helper','support'):
                    with self.assertRaisesRegex(policy.PolicyError,'ARCHIVE_SOURCE_CHANGED|UNEXPECTED_PACKAGE_FILE'):
                        policy.archive_mapping(copied_identity,run/'subjects/feature-subject',mutated,archive,member['package_files'])
                else:
                    for t in matrix['toolchains'] if mutation=='authors' else [self.t]:
                        result=self.cargo(mutated,['metadata','--offline','--locked','--no-deps','--format-version','1'],run,'mutant-metadata-'+mutation+'-'+t['id'],toolchain=t)
                        policy.succeeded(result)
                        with self.assertRaisesRegex(policy.PolicyError,'ARCHIVE_SEMANTICS_CHANGED') as rejection:
                            policy.verify_package_semantics(original_md,run/'subjects/feature-subject/Cargo.toml',json.loads(policy.stdout(result)),mutated/'Cargo.toml')
                        if mutation=='authors': authors_control['semantic_refusals'].append(dict(toolchain=t['id'],code=rejection.exception.code,result=result))
                if mutation=='authors':
                    authors_control['production_changed_markers']=[str(p) for p in (run/'targets').rglob('changed-metadata-marker')]
                    (output/'authors-only-evidence.json').write_text(json.dumps(authors_control,indent=2)+'\n')
                self.assertFalse(marker.exists())
                self.assertFalse(list((run/'targets').rglob('changed-metadata-marker')))


class LockDiagnosticControls(unittest.TestCase):
    """Real pinned Cargo refusals, separate from the full feature matrix."""
    def setUp(self):
        import os
        output = Path(os.environ.get('SCOPEBASE_TEST_OUTPUT_ROOT', str(ROOT/'.scopebase/test-output')))
        output.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='lock-diagnostic-', dir=output)
        temporary._finalizer.detach()  # Preserve partial outcomes and raw logs.
        self.output = Path(temporary.name)
        self.matrix_path = ROOT/'package-policy.json'
        self.matrix = json.loads(self.matrix_path.read_text())
        self.execution = policy.Execution('lock-controls', self.matrix_path, self.matrix, self.output)
        self.addCleanup(lambda: policy.atomic_json(self.output/'report.json', self.execution.report))
        runtime = os.environ.get('XDG_RUNTIME_DIR')
        self.lock_root = Path(runtime)/'scopebase-locks' if runtime else Path.home()/'.cache/scopebase/locks'

    def command(self, ident, toolchain, manifest):
        from unittest.mock import patch
        real_run = policy.run
        def owned_run(argv, *args, **kwargs):
            return real_run([ROOT/'bin/scopebase-build', '--lock-root', self.lock_root, '--', *argv], *args, **kwargs)
        self.execution.reserve(ident, toolchain=toolchain['id'], phase='metadata')
        with patch.object(policy, 'run', side_effect=owned_run):
            return self.execution.step(ident, lambda row: self.execution.command(
                row, toolchain, manifest,
                ['metadata', '--offline', '--locked', '--format-version', '1', '--filter-platform', policy.HOST],
                self.output/('target-'+toolchain['id'])))

    def workspace(self):
        import shutil
        subject = self.output/'input'; subject.mkdir()
        for name in ('Cargo.toml', 'Cargo.lock'):
            shutil.copyfile(ROOT/name, subject/name)
        for member in self.matrix['members']:
            path = Path(member['manifest']).parent
            shutil.copytree(ROOT/path, subject/path)
        policy.stage_inputs(self.matrix['cargo_inputs'], self.output)
        return subject

    def assert_command(self, ident, toolchain, subject, wanted):
        before = policy.tree_digest(subject)
        reason = None
        try:
            result = self.command(ident, toolchain, subject/'Cargo.toml')
            metadata = json.loads(policy.stdout(result))
            self.assertEqual(len(metadata['workspace_members']), len(self.matrix['members']))
        except policy.PolicyError as error:
            reason = error.code
        row = self.execution.by_id[ident]
        self.assertEqual(row['cleanup'], 'complete')
        self.assertEqual(row['input_sha256'], before)
        self.assertEqual(row['input_sha256_after'], before)
        self.assertEqual(policy.tree_digest(subject), before)
        self.assertEqual(row['lock_sha256_before'], row['lock_sha256'])
        self.assertEqual(reason, wanted)
        self.assertEqual(row['status'], 'PASS' if wanted is None else
                         'BLOCKED' if wanted == 'OFFLINE_CLOSURE_INCOMPLETE' else 'FAIL')

    def test_missing_stale_and_restored_locks_on_both_pinned_compilers(self):
        subject = self.workspace(); lock = subject/'Cargo.lock'; valid = lock.read_bytes()
        needle = b'name = "scopebase-capture"\nversion = "0.1.0"'
        self.assertEqual(valid.count(needle), 1)
        stale = valid.replace(needle, b'name = "scopebase-capture"\nversion = "0.0.0"')
        for toolchain in self.matrix['toolchains']:
            for label, raw, wanted in (('valid', valid, None), ('missing', None, 'LOCK_REQUIRED'),
                                       ('missing-restored', valid, None), ('stale', stale, 'LOCK_REQUIRED'),
                                       ('stale-restored', valid, None)):
                with self.subTest(compiler=toolchain['id'], control=label):
                    if raw is None: lock.unlink()
                    else: lock.write_bytes(raw)
                    self.assert_command(toolchain['id']+'-'+label, toolchain, subject, wanted)
                    self.assertEqual(lock.read_bytes() if lock.exists() else None, raw)

    def test_real_unavailable_offline_source_is_not_a_lock_refusal(self):
        subject = self.workspace()
        manifest = subject/self.matrix['members'][0]['manifest']; valid = manifest.read_bytes()
        manifest.write_bytes(valid+b'\n[dependencies.scopebase-unavailable-offline-control]\nversion="=0.0.0"\n')
        for toolchain in self.matrix['toolchains']:
            with self.subTest(compiler=toolchain['id']):
                self.assert_command(toolchain['id']+'-offline', toolchain, subject, 'OFFLINE_CLOSURE_INCOMPLETE')
                row = self.execution.by_id[toolchain['id']+'-offline']
                diagnostic = Path(row['logs']['stderr']['path']).read_text()
                self.assertIn('no matching package named', diagnostic)
                self.assertIn('scopebase-unavailable-offline-control', diagnostic)
        manifest.write_bytes(valid)
        for toolchain in self.matrix['toolchains']:
            with self.subTest(restored=toolchain['id']):
                self.assert_command(toolchain['id']+'-offline-restored', toolchain, subject, None)

    def test_lock_diagnostic_does_not_override_process_cleanup_or_lock_changes(self):
        from unittest.mock import patch
        subject = self.output/'input'; subject.mkdir()
        manifest = subject/'Cargo.toml'; manifest.write_text('[workspace]\n')
        lock = subject/'Cargo.lock'; lock.write_text('owned lock\n')
        diagnostic = 'error: cannot create the lock file /owned/Cargo.lock because --locked was passed to prevent this\nhelp: use --offline instead.\n'
        captured = policy.run([sys.executable, '-c', 'import sys; sys.stderr.write('+repr(diagnostic)+'); sys.exit(101)'],
                              subject, {'PATH': '/usr/bin:/bin'}, self.output/'captured')
        for index, (reason, cleanup, changed, wanted) in enumerate((
                ('TIMEOUT', 'complete', False, 'TIMEOUT'),
                ('LOG_BOUND', 'complete', False, 'LOG_BOUND'),
                ('INTERNAL_ERROR', 'complete', False, 'INTERNAL_ERROR'),
                (None, 'unresolved', False, 'CLEANUP_UNRESOLVED'),
                (None, 'complete', True, 'LOCK_CHANGED'))):
            with self.subTest(reason=wanted):
                result = {**captured, 'reason_code': reason, 'cleanup': cleanup}
                ident = 'priority-'+str(index); self.execution.reserve(ident)
                def run(*args, **kwargs):
                    if changed: lock.write_text('changed lock\n')
                    return result
                with patch.object(policy, 'run', side_effect=run), self.assertRaises(policy.PolicyError) as error:
                    self.execution.step(ident, lambda row: self.execution.command(
                        row, self.matrix['toolchains'][0], manifest,
                        ['metadata', '--offline', '--locked'], self.output/'target'))
                self.assertEqual(error.exception.code, wanted)

    def test_lock_wording_requires_a_failed_locked_command_and_the_specific_refusal(self):
        from unittest.mock import patch
        subject = self.output/'input'; subject.mkdir()
        manifest = subject/'Cargo.toml'; manifest.write_text('[workspace]\n')
        refusal = 'error: cannot create the lock file /owned/Cargo.lock because --locked was passed to prevent this\n'
        help_text = 'help: remove --locked and use --offline instead.\n'
        for index, (diagnostic, locked, code, wanted) in enumerate((
                ('error: cannot create the lock file /owned/Cargo.lock: Permission denied\n'+help_text, True, 101, 'OFFLINE_CLOSURE_INCOMPLETE'),
                ('error: failed to read lock file /owned/Cargo.lock\n'+help_text, True, 101, 'OFFLINE_CLOSURE_INCOMPLETE'),
                (refusal+help_text, False, 101, 'OFFLINE_CLOSURE_INCOMPLETE'),
                (refusal+help_text, True, 0, None))):
            with self.subTest(control=index):
                captured = policy.run([sys.executable, '-c', 'import sys; sys.stderr.write('+repr(diagnostic)+'); sys.exit('+str(code)+')'],
                                      subject, {'PATH': '/usr/bin:/bin'}, self.output/('diagnostic-'+str(index)))
                ident = 'wording-'+str(index); self.execution.reserve(ident)
                arguments = ['metadata', '--offline']+(['--locked'] if locked else [])
                observed = None
                with patch.object(policy, 'run', return_value=captured):
                    try:
                        self.execution.step(ident, lambda row: self.execution.command(
                            row, self.matrix['toolchains'][0], manifest, arguments, self.output/'target'))
                    except policy.PolicyError as error:
                        observed = error.code
                self.assertEqual(observed, wanted)


class ProductPolicyControls(unittest.TestCase):
    """First-product lock custody and true workspace-member staging controls."""
    @classmethod
    def setUpClass(cls):
        import os
        product_output=Path(os.environ.get('SCOPEBASE_TEST_OUTPUT_ROOT',str(ROOT/'.scopebase/test-output')))
        product_output.mkdir(parents=True,exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix='lx01-product-',dir=product_output)
        cls.root = Path(cls.temp.name)
        cls.temp._finalizer.detach()  # Retain command logs and controls for review.
        cls.base = json.loads((ROOT/'tests/package-policy/matrix.json').read_text())
        cls.counter = 0

    def product(self):
        import shutil
        type(self).counter += 1
        cell = self.root/str(self.counter); cell.mkdir()
        inputs = cell/'input'; inputs.mkdir()
        source = inputs/'subject'; (source/'src').mkdir(parents=True)
        (source/'Cargo.toml').write_text('[package]\nname="product-subject"\nversion="0.1.0"\nedition="2021"\nrust-version="1.88.0"\nlicense="Apache-2.0"\nbuild=false\ninclude=["Cargo.toml","src/lib.rs","LICENSE-APACHE","THIRD-PARTY-NOTICES.md"]\n[features]\ndefault=[]\nextra=[]\n')
        (source/'src/lib.rs').write_text('//! ```\n//! use product_subject as _;\n//! ```\n')
        shutil.copyfile(ROOT/'LICENSE-APACHE',source/'LICENSE-APACHE')
        (source/'THIRD-PARTY-NOTICES.md').write_text('ScopeBase package dependency notices. Dependency references are not bundled unless explicitly marked.\n```json\n[]\n```\n')
        (inputs/'client.rs').write_text('use product_subject as _; fn main() {}\n')
        (inputs/'Cargo.toml').write_text('[workspace]\nresolver="2"\nmembers=["subject"]\n')
        matrix = json.loads(json.dumps(self.base)); matrix['fixture_members']=[]; matrix['approved_build_inputs']=[]
        matrix['members']=[dict(id='product-subject',manifest='subject/Cargo.toml',role='product',minimal=[],default=[],supported_unions=[['extra']],clients=[dict(id='product-client',source='client.rs',default_features=False,features=['extra']),dict(id='product-other',source='client.rs',default_features=False,features=[])],package_files=['Cargo.toml','Cargo.toml.orig','Cargo.lock','src/lib.rs','LICENSE-APACHE','THIRD-PARTY-NOTICES.md'],allowed_dependencies=[],license_files=[dict(path='LICENSE-APACHE',sha256=policy.sha(ROOT/'LICENSE-APACHE'))],notice_entries=[],denied_packages=['aya','cc'])]
        (inputs/'matrix.json').write_text(json.dumps(matrix))
        seed=cell/'seed'; seed.mkdir(); policy.stage_inputs(matrix['cargo_inputs'],seed)
        import subprocess
        result=subprocess.run([str(ROOT/'bin/scopebase-build'),'--',str(Path(matrix['toolchains'][0]['root'])/'bin/cargo'),'generate-lockfile','--offline','--manifest-path',str(inputs/'Cargo.toml')],env=policy.clean_env(seed,matrix['toolchains'][0],seed/'target'),capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        return cell,inputs,source,matrix

    def check(self,cell,inputs,label,expected=0,policy_only=False):
        import subprocess
        report=cell/(label+'.json')
        argv=[str(ROOT/'bin/scopebase-build'),'--',sys.executable,str(ROOT/'tools/build/check_features.py'),'--manifest',str(inputs/'Cargo.toml'),'--matrix',str(inputs/'matrix.json'),'--output-dir',str(cell/label),'--report',str(report)]
        if policy_only: argv.append('--policy-only')
        result=subprocess.run(argv,capture_output=True,text=True)
        data=json.loads(report.read_text()) if report.exists() else None
        if expected == 0: self.assertEqual(result.returncode,0,result.stdout+result.stderr+str(data['summary'] if data else None))
        else: self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIsNotNone(data,result.stderr)
        return data

    def test_product_member_stages_without_changing_approved_manifest(self):
        cell,inputs,source,matrix=self.product()
        before=policy.tree_digest(inputs)
        data=self.check(cell,inputs,'valid',policy_only=False)
        self.assertEqual(policy.tree_digest(inputs),before)
        copied=cell/'valid/subjects/product-subject/subject'
        self.assertEqual((copied/'Cargo.toml').read_bytes(),(source/'Cargo.toml').read_bytes())
        self.assertNotIn('[workspace]',(copied/'Cargo.toml').read_text())
        self.assertTrue((copied/'Cargo.lock').is_file())
        self.assertFalse((source/'Cargo.lock').exists())
        self.assertEqual(policy.sha(copied/'Cargo.lock'),policy.sha(copied.parent/'Cargo.lock'))
        import subprocess
        boundary=copied.parent/'Cargo.toml'; valid_boundary=boundary.read_bytes()
        self.assertEqual(tomllib.loads(valid_boundary.decode())['workspace']['members'],['subject'])
        boundary.unlink()
        t=matrix['toolchains'][0]
        argv=[str(ROOT/'bin/scopebase-build'),'--',str(Path(t['root'])/'bin/cargo'),'metadata','--offline','--locked','--no-deps','--format-version','1','--manifest-path',str(copied/'Cargo.toml')]
        env=policy.clean_env(cell/'valid',t,cell/'bad-boundary-target')
        bad=policy.run(argv,copied,env,cell/'no-boundary')
        self.assertNotEqual(bad['exit_code'],0)
        self.assertIn("believes it's in a workspace",Path(bad['logs']['stderr']['path']).read_text())
        boundary.write_bytes(valid_boundary)
        good=policy.run(argv,copied,env,cell/'restored-boundary')
        policy.succeeded(good)
        for row in data['rows']:
            if row['id'].startswith('root-'):
                self.assertIn('--locked',row['command'])
                self.assertNotIn('--no-deps',row['command'])
                self.assertIn('--filter-platform',row['command'])
                self.assertEqual(row['lock_sha256_before'],row['lock_sha256'])
                self.assertEqual(row['input_sha256'],row['input_sha256_after'])
        unpacked=cell/'valid/unpacked/product-subject/product-subject-0.1.0'
        (unpacked/'THIRD-PARTY-NOTICES.md').write_text(policy.NOTICE_INTRO+'\n```json\n[]\n```\n')
        with self.assertRaisesRegex(policy.PolicyError,'NOTICE_INCOMPLETE'):
            policy.check_licenses(unpacked,matrix['members'][0]['license_files'],[],role='product')

    def test_missing_and_stale_root_locks_refuse_unchanged_and_restored_twin_passes(self):
        cell,inputs,source,matrix=self.product()
        lock=inputs/'Cargo.lock'; valid=lock.read_bytes()
        for label,raw in (('missing',None),('stale',valid.replace(b'0.1.0',b'0.0.0'))):
            if raw is None: lock.unlink()
            else: lock.write_bytes(raw)
            before=policy.tree_digest(inputs)
            data=self.check(cell,inputs,label,expected=1)
            self.assertEqual(policy.tree_digest(inputs),before)
            for row in data['rows']:
                if row['id'].startswith('root-') and row['command']:
                    self.assertEqual(row['status'],'FAIL')
                    self.assertIn('--locked',row['command'])
                    self.assertNotIn('--no-deps',row['command'])
                    self.assertEqual(row['lock_sha256_before'],row['lock_sha256'])
                    self.assertEqual(row['input_sha256'],row['input_sha256_after'])
            lock.write_bytes(valid)
            self.check(cell,inputs,label+'-restored')

    def test_product_requires_an_executed_doctest(self):
        cell,inputs,source,matrix=self.product()
        (source/'src/lib.rs').write_text('// no executable documentation\n')
        data=self.check(cell,inputs,'no-doctest',expected=1)
        docs=[r for r in data['rows'] if r['phase']=='doc']
        self.assertEqual(len(docs),6)
        self.assertTrue(all(r['reason_code']=='DOCTEST_MISSING' for r in docs))

    def test_product_source_refusals_precede_compilation(self):
        cell,inputs,source,matrix=self.product()
        notice=source/'THIRD-PARTY-NOTICES.md'; original=notice.read_bytes()
        notice.write_text(policy.NOTICE_INTRO+'\n```json\n[]\n```\n')
        data=self.check(cell,inputs,'fixture-notice',expected=1)
        self.assertEqual(next(r for r in data['rows'] if r['id']=='product-subject-source')['reason_code'],'NOTICE_INCOMPLETE')
        notice.write_bytes(original)
        manifest=source/'Cargo.toml'; baseline=manifest.read_text()
        sibling=inputs/'sibling'; (sibling/'src').mkdir(parents=True)
        (sibling/'Cargo.toml').write_text('[package]\nname="sibling"\nversion="0.1.0"\n')
        (sibling/'src/lib.rs').write_text('')
        manifest.write_text(baseline+'[dependencies]\nsibling={path="../sibling"}\n')
        with self.assertRaisesRegex(policy.PolicyError,'EXTERNAL_PATH_DEPENDENCY'):
            policy.inspect_manifest(manifest)
        manifest.write_text(baseline)
        matrix['members'][0]['manifest']='../elsewhere/Cargo.toml'
        (inputs/'matrix.json').write_text(json.dumps(matrix))
        import check_features,contextlib,io
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(check_features.main(['--manifest',str(inputs/'Cargo.toml'),'--matrix',str(inputs/'matrix.json'),'--output-dir',str(cell/'escaped'),'--report',str(cell/'escaped.json')]),2)


class MandatoryMinimalPolicyControl(ProductPolicyControls):
    """One real archived consumer, with exact mandatory serde closure controls."""

    # This narrow subclass uses the existing fixture setup, not unrelated cases.
    test_product_member_stages_without_changing_approved_manifest = None
    test_missing_and_stale_root_locks_refuse_unchanged_and_restored_twin_passes = None
    test_product_requires_an_executed_doctest = None
    test_product_source_refusals_precede_compilation = None

    def test_mandatory_minimal_dependencies_use_exact_archive_metadata(self):
        cell, inputs, source, matrix = self.product()
        manifest = source / 'Cargo.toml'
        manifest.write_text(manifest.read_text().replace('extra=[]\n', '') +
            '[dependencies]\n'
            'serde={version="=1.0.229",default-features=false,features=["std","derive"]}\n'
            'serde_json={version="=1.0.151",default-features=false,features=["std"]}\n')
        (source / 'src/lib.rs').write_text(
            '//! ```\n//! assert_eq!(product_subject::value(), 42);\n//! ```\n'
            '#[derive(serde::Deserialize)] struct Value { value: u64 }\n'
            'pub fn value() -> u64 { serde_json::from_str::<Value>(r#"{"value":42}"#).unwrap().value }\n')
        (inputs / 'client.rs').write_text('fn main() { assert_eq!(product_subject::value(), 42); }\n')
        original = self.base['fixture_members'][0]
        member = matrix['members'][0]
        member['supported_unions'] = []
        for client in member['clients']:
            client['features'] = []
        member['allowed_dependencies'] = original['allowed_dependencies']
        member['minimal_dependencies'] = original['allowed_dependencies']
        member['notice_entries'] = original['notice_entries']
        matrix['approved_build_inputs'] = self.base['approved_build_inputs']
        (source / 'THIRD-PARTY-NOTICES.md').write_text(
            policy.PRODUCT_NOTICE_INTRO + '\n```json\n' +
            json.dumps(member['notice_entries'], sort_keys=True) + '\n```\n')
        # Existing fixture construction made a no-dependency lock. Deliberately
        # regenerate for this changed manifest through the same admitted runner.
        seed = cell / 'seed'
        t = matrix['toolchains'][0]
        result = policy.run([str(ROOT / 'bin/scopebase-build'), '--',
            str(Path(t['root']) / 'bin/cargo'), 'generate-lockfile', '--offline',
            '--manifest-path', str(inputs / 'Cargo.toml')], inputs,
            policy.clean_env(seed, t, seed / 'target'), cell / 'mandatory-lock')
        policy.succeeded(result)
        (inputs / 'matrix.json').write_text(json.dumps(matrix))
        valid = self.check(cell, inputs, 'mandatory-valid')
        admits = [r for r in valid['rows'] if r['id'].endswith('-admit') and
                  r['id'].startswith(('product-subject-minimal-', 'product-subject-default-'))]
        self.assertEqual(len(admits), 4)
        self.assertTrue(all(r['status'] == 'PASS' for r in admits))
        self.assertEqual(len([r for r in valid['rows'] if '-run-' in r['id']]), 4)
        # The expected closure comes from reviewed inputs, not Cargo's observed
        # result. Removing one declared dependency must fail the intended gate.
        member['minimal_dependencies'] = [r for r in original['allowed_dependencies']
                                          if r['name'] != 'serde_json']
        (inputs / 'matrix.json').write_text(json.dumps(matrix))
        missing = self.check(cell, inputs, 'mandatory-missing', expected=1, policy_only=True)
        failures = [r for r in missing['rows'] if r['status'] == 'FAIL']
        self.assertEqual(len(failures), 4)
        self.assertTrue(all(r['reason_code'] == 'MINIMAL_DEPENDENCY_MISMATCH' for r in failures))
        del member['minimal_dependencies']
        (inputs / 'matrix.json').write_text(json.dumps(matrix))
        legacy = self.check(cell, inputs, 'mandatory-legacy', expected=1, policy_only=True)
        failures = [r for r in legacy['rows'] if r['status'] == 'FAIL']
        self.assertEqual(len(failures), 4)
        self.assertTrue(all(r['reason_code'] == 'MINIMAL_FEATURE_LEAK' for r in failures))
        member['minimal_dependencies'] = original['allowed_dependencies']
        (inputs / 'matrix.json').write_text(json.dumps(matrix))
        restored = self.check(cell, inputs, 'mandatory-restored', expected=3, policy_only=True)
        restored_admits = [r for r in restored['rows'] if r['id'].endswith('-admit') and
                           r['id'].startswith(('product-subject-minimal-', 'product-subject-default-'))]
        self.assertEqual(len(restored_admits), 4)
        self.assertTrue(all(r['status'] == 'PASS' for r in restored_admits))
        self.assertEqual(restored['summary']['counts']['FAIL'], 0)
        self.assertEqual(restored['summary']['counts']['BLOCKED'], 0)
        self.assertEqual(restored['summary']['counts']['NOT_RUN'], 16)
        self.assertFalse(restored['summary']['full_matrix_complete'])


class ExactRustRefusalTests(unittest.TestCase):
    """Parser evidence: exact diagnostics must refer to the owned fixture line."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'src').mkdir()
        self.file = self.root / 'src/main.rs'
        self.file.write_text('fn main() {\n    takes_events(records);\n}\n')

    def diagnostic(self, *, file='src/main.rs', line=2, code='E0308', message='mismatched types', primary=True):
        return json.dumps({'reason':'compiler-message', 'message':{'code':{'code':code},
            'message':message, 'spans':[{'file_name':file, 'line_start':line, 'is_primary':primary}]}})

    def refusal(self, output, **kwargs):
        return policy.rust_refusal(output, 'E0308', 'mismatched types', self.root,
                                   expected_primary=kwargs.get('expected', ('src/main.rs', 2)))

    def test_exact_diagnostic_does_not_require_message_words_in_source(self):
        self.assertTrue(self.refusal(self.diagnostic()))
        self.assertTrue(self.refusal(self.diagnostic(file=str(self.file))))
        self.assertFalse(policy.rust_refusal(self.diagnostic(), 'E0308', 'mismatched types', self.root))

    def test_wrong_code_message_line_file_or_secondary_span_is_rejected(self):
        other = self.root / 'src/other.rs'; other.write_text(self.file.read_text())
        for kw in ({'code':'E0599'}, {'message':'other'}, {'line':1}, {'file':'src/other.rs'}, {'primary':False}):
            with self.subTest(kw=kw):
                self.assertFalse(self.refusal(self.diagnostic(**kw)))
        self.assertFalse(self.refusal(''))

    def test_expected_location_must_be_owned_real_and_in_bounds(self):
        outside = self.root.parent / (self.root.name + '-outside.rs')
        outside.write_text(self.file.read_text()); self.addCleanup(outside.unlink)
        (self.root / 'src/escape.rs').symlink_to(outside)
        for expected in ((str(self.file),2), ('../main.rs',2), ('src/escape.rs',2),
                         ('src/absent.rs',2), ('src/invalid\x00.rs',2), ('src/main.rs',0), ('src/main.rs',-1),
                         ('src/main.rs',True), ('src/main.rs',2.0), ('src/main.rs',4),
                         ('src/main.rs',), ('src/main.rs',2,3), 'src/main.rs'):
            with self.subTest(expected=expected):
                self.assertFalse(self.refusal(self.diagnostic(), expected=expected))
        self.assertFalse(policy.rust_refusal(self.diagnostic(), 'E0308', 'mismatched types',
                                            expected_primary=('src/main.rs',2)))

    def test_unowned_reported_path_and_malformed_spans_are_rejected(self):
        outside = self.root.parent / (self.root.name + '-outside.rs')
        outside.write_text(self.file.read_text()); self.addCleanup(outside.unlink)
        for file in (str(outside), '../' + outside.name):
            self.assertFalse(self.refusal(self.diagnostic(file=file)))
        for line in (True, 2.0, '2', None, -1):
            self.assertFalse(self.refusal(self.diagnostic(line=line)))
        for output in ('null', '[]', '{"message": null}', '{"reason":"compiler-message","message":{"code":{"code":"E0308"},"message":"mismatched types","spans":[null]}}'):
            self.assertFalse(self.refusal(output))

    def test_legacy_refusal_behavior_and_diagnostic_selection_are_preserved(self):
        self.file.write_text('fn main() {\n    // legacy token\n}\n')
        output = self.diagnostic(message='legacy token')
        self.assertTrue(policy.rust_refusal(output, 'E0308', 'legacy token', self.root))
        self.assertTrue(policy.rust_refusal(output, 'E0308', 'legacy token'))
        self.assertFalse(policy.rust_refusal(output, 'E0308', 'absent', self.root))
        self.assertTrue(self.refusal(self.diagnostic(line=1) + '\n' + self.diagnostic()))
