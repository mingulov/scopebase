# SPDX-License-Identifier: Apache-2.0
"""Manifest, archive and real offline Cargo package-policy controls."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
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
            str(ROOT/'tools/build/check_features.py'),'--manifest',str(ROOT/'Cargo.toml'),
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

    def cargo(self, source, arguments, output, name, env_extra=None):
        import subprocess
        env = policy.clean_env(output,self.t,output/'target')
        if env_extra: env.update(env_extra)
        import os
        shared_root = Path(os.environ['XDG_RUNTIME_DIR'])/'scopebase-locks' if os.environ.get('XDG_RUNTIME_DIR') else Path.home()/'.cache/scopebase/locks'
        argv = [str(ROOT/'bin/scopebase-build'),'--lock-root',str(shared_root),'--',str(Path(self.t['root'])/'bin/cargo'),*arguments,'--manifest-path',str(source/'Cargo.toml')]
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
