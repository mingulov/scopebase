# SPDX-License-Identifier: Apache-2.0
"""Strict input/report and frozen-source controls; no Cargo subprocess doubles."""
import copy
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


class InputPolicyTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(policy, 'the bounded build-policy implementation is absent')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_duplicate_json_and_unknown_fields_are_errors(self):
        p = self.root / 'x.json'
        p.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(policy.InputError, 'DUPLICATE_KEY'):
            policy.read_json(p)
        with self.assertRaisesRegex(policy.InputError, 'SCHEMA'):
            policy.exact({'x': 1, 'extra': 2}, {'x'})

    def test_safe_paths_reject_traversal_and_existing_symlink_escape(self):
        (self.root / 'okay').write_text('yes')
        self.assertEqual(policy.relative(self.root, 'okay'), self.root / 'okay')
        for text in ('../other', '/etc/passwd', 'a/../okay'):
            with self.assertRaisesRegex(policy.InputError, 'PATH'):
                policy.relative(self.root, text)
        (self.root / 'escape').symlink_to('/etc')
        with self.assertRaisesRegex(policy.InputError, 'PATH'):
            policy.relative(self.root, 'escape/passwd')

    def test_required_rows_cannot_disappear_or_duplicate(self):
        rows = [policy.row('one', required=True), policy.row('two', required=True)]
        for r in rows:
            r.update(status='PASS', cleanup='complete')
        self.assertEqual(policy.summarize(rows, ['one', 'two'])['status'], 'PASS')
        for status in ('BLOCKED', 'NOT_RUN'):
            changed = copy.deepcopy(rows)
            changed[1]['status'] = status
            self.assertEqual(policy.summarize(changed, ['one', 'two'])['exit_code'], 3)
        with self.assertRaisesRegex(policy.InputError, 'MISSING_ROW'):
            policy.summarize(rows[:1], ['one', 'two'])
        with self.assertRaisesRegex(policy.InputError, 'DUPLICATE_ROW'):
            policy.summarize(rows + rows[:1], ['one', 'two'])
        rows[0]['status'] = 'FAIL'
        rows[1]['status'] = 'BLOCKED'
        summary = policy.summarize(rows, ['one', 'two'])
        self.assertEqual(summary['exit_code'], 1)
        self.assertEqual(summary['counts']['BLOCKED'], 1)

    def test_selected_cases_never_claim_full_matrix(self):
        r = policy.row('one'); r.update(status='PASS', cleanup='complete')
        summary = policy.summarize([r], ['one'], omitted=['two'])
        self.assertFalse(summary['full_matrix_complete'])
        self.assertEqual(summary['omitted_required_ids'], ['two'])

    def test_whole_tree_hash_detects_included_helper_and_added_file(self):
        (self.root / 'build.rs').write_text('include!("helper.rs");')
        (self.root / 'helper.rs').write_text('fn main() {}')
        original = policy.tree_digest(self.root)
        (self.root / 'helper.rs').write_text('fn main() { panic!("wrong"); }')
        self.assertNotEqual(original, policy.tree_digest(self.root))
        (self.root / 'extra').write_text('new')
        self.assertNotEqual(original, policy.tree_digest(self.root))

    def test_new_outputs_reject_reuse_symlinks_and_source_containment(self):
        out = self.root / 'out'
        policy.fresh_output(out, [self.root / 'input'])
        (out / 'receipt').write_text('old success')
        with self.assertRaisesRegex(policy.InputError, 'OUTPUT'):
            policy.fresh_output(out, [])
        with self.assertRaisesRegex(policy.InputError, 'OUTPUT'):
            policy.fresh_output(self.root / 'input' / 'out', [self.root / 'input'])

    def test_compile_refusal_requires_positive_and_intended_rust_diagnostic(self):
        diagnostic = {'message': {'code': {'code': 'E0624'}, 'message': 'method `type_by_id` is private',
                      'spans': [{'file_name': 'src/lib.rs', 'line_start': 4, 'is_primary': True}]}}
        text = json.dumps({'reason': 'compiler-message', **diagnostic})
        self.assertTrue(policy.rust_refusal(text, 'E0624', 'type_by_id'))
        self.assertFalse(policy.rust_refusal('failed to download dependency', 'E0624', 'type_by_id'))
        self.assertFalse(policy.rust_refusal(text.replace('E0624', 'E0432'), 'E0624', 'type_by_id'))


if __name__ == '__main__':
    unittest.main()

class StagingTests(unittest.TestCase):
    def test_changed_cargo_vendor_tree_is_not_availability_or_permission(self):
        self.assertIsNotNone(policy)
        self.assertTrue(hasattr(policy, 'stage_inputs'), 'immutable vendor staging is absent')

    def test_btf_mapping_relocates_only_the_exact_reviewed_git_edge(self):
        self.assertIsNotNone(policy)
        self.assertTrue(hasattr(policy, 'map_btf_manifest'), 'controlled BTF manifest mapping is absent')
        raw = '''[package]\nname="trial"\nversion="0.1.0"\n[dependencies]\nbtf-rs={git="https://github.com/retis-org/btf-rs",rev="0a5838f8dad54b6da9a7b0539f1e2d7aeeb009a0",default-features=false,features=[]}\n'''
        rewritten = policy.map_btf_manifest(raw, '/owned/staged/btf-rs')
        import tomllib
        dep = tomllib.loads(rewritten)['dependencies']['btf-rs']
        self.assertEqual(dep, {'path': '/owned/staged/btf-rs', 'default-features': False, 'features': []})
        for old, new in (('retis-org','wrong-org'), ('0a5838','1a5838')):
            with self.assertRaisesRegex(policy.PolicyError, 'SOURCE_MAPPING'):
                policy.map_btf_manifest(raw.replace(old, new), '/owned/staged/btf-rs')

class ProcessAndSchemaTests(unittest.TestCase):
    def test_timeout_reaps_owned_child_and_preserves_bounded_logs(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            result=policy.run([sys.executable,'-c','import time; print("started",flush=True); time.sleep(30)'],root,{'PATH':'/usr/bin:/bin'},root/'timeout',timeout=.05)
            self.assertEqual(result['reason_code'],'TIMEOUT')
            self.assertEqual(result['cleanup'],'complete')
            self.assertIn('started',policy.stdout(result))
            with self.assertRaises(ProcessLookupError):
                os.kill(result['process_group'],0)

    def test_malformed_nested_schema_is_input_error(self):
        base=json.loads((ROOT/'tests/package-policy/matrix.json').read_text())
        for key in ('members','fixture_members','approved_build_inputs','toolchains'):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                changed=copy.deepcopy(base); changed[key]=17
                path=Path(tmp)/'matrix.json'; path.write_text(json.dumps(changed))
                with self.assertRaises(policy.InputError):
                    policy.validate_matrix(path,'features')

class BtfLockMappingTests(unittest.TestCase):
    def test_acquisition_matching_preserves_every_nonpath_field(self):
        import dependency_probe as probe
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); bundle=root/'bundle'; package=bundle/'btf-rs'; package.mkdir(parents=True)
            manifest=package/'Cargo.toml'; manifest.write_text('[package]\nname="btf-rs"\nversion="2.0.0"\n')
            files=[dict(path='btf-rs/Cargo.toml',kind='file',sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),link_target=None)]
            entry=dict(root=package,bundle=dict(files=files,packages=[dict(name='btf-rs',manifest='btf-rs/Cargo.toml')]))
            canonical='[package]\nname="probe"\nversion="0.1.0"\n[dependencies]\nbtf-rs={git="'+policy.BTF_URL+'",rev="'+policy.BTF_REV+'",default-features=false,features=[]}\nitoa={version="=1.0.18"}\n'
            acquired=root/'Cargo.toml'; acquired.write_text(policy.map_btf_manifest(canonical,package))
            lock=root/'Cargo.lock'
            # This unit tests manifest binding only. No subprocess/lock contents
            # are used as Cargo execution evidence.
            staging=dict(inventory=dict(cargo_vendor=dict(acquisition_locks=[dict(manifest=str(acquired),lock=str(lock))])))
            self.assertEqual(probe.acquisition_lock(canonical,staging,entry),lock)
            mutants=[canonical.replace('retis-org','wrong-org'),canonical.replace(policy.BTF_REV,'f'*40),canonical.replace('name="probe"','name="other"'),canonical.replace('features=[]','features=["elf"]'),canonical.replace('=1.0.18','=1.0.17')]
            for changed in mutants:
                with self.subTest(changed=changed),self.assertRaisesRegex(policy.PolicyError,'ACQUISITION_LOCK_UNAVAILABLE'):
                    probe.acquisition_lock(changed,staging,entry)

class FailureStageAttributionTests(unittest.TestCase):
    def test_only_input_stage_owns_missing_or_changed_inventory_failure(self):
        import subprocess
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); inputs=root/'inputs'; inputs.mkdir()
            shutil.copytree(ROOT/'tests/package-policy/fixtures',inputs/'fixtures')
            probe=inputs/'probe'; (probe/'src').mkdir(parents=True)
            (probe/'Cargo.toml').write_text('[package]\nname="synthetic"\nversion="0.1.0"\nedition="2021"\n[workspace]\n[dependencies]\nitoa={version="=1.0.18",default-features=false,features=[]}\n')
            (probe/'src/lib.rs').write_text('#[test] fn literal() { assert_eq!(1,1); }')
            original=json.loads((ROOT/'tests/package-policy/matrix.json').read_text())
            for kind in ('features','probe'):
                for mutation,exit_code,code,status in (('missing',3,'SOURCE_UNAVAILABLE','BLOCKED'),('changed',1,'INPUT_CHANGED','FAIL')):
                    matrix=copy.deepcopy(original)
                    if kind=='probe':
                        del matrix['fixture_members']; del matrix['members']
                        record=original['fixture_members'][0]['allowed_dependencies'][0]
                        candidate={k:record[k] for k in ('name','version','source','sha256')}
                        matrix['cases']=[dict(id='synthetic',required=True,manifest='probe/Cargo.toml',candidate=candidate,default_features=False,features=[],tier='host_semantic',assertions=['literal'],expected_fit='SATISFIED',availability='ready',compile_refusals=[],allowed_dependencies=[record],obligation_refs=['SB02'])]
                    if mutation=='missing': matrix['cargo_inputs']['inventory']=str(root/'absent-inventory.json')
                    else: matrix['cargo_inputs']['sha256']='0'*64
                    path=inputs/(kind+'-'+mutation+'.json'); path.write_text(json.dumps(matrix))
                    report=root/(kind+'-'+mutation+'-report.json')
                    argv=[sys.executable,str(ROOT/'tools/build'/('check_features.py' if kind=='features' else 'dependency_probe.py')),'--matrix',str(path),'--output-dir',str(root/(kind+'-'+mutation+'-output')),'--report',str(report)]
                    if kind=='features': argv.extend(['--manifest',str(ROOT/'Cargo.toml')])
                    result=subprocess.run(argv,capture_output=True,text=True)
                    self.assertEqual(result.returncode,exit_code,result.stdout+result.stderr)
                    rows=json.loads(report.read_text())['rows']
                    active=[r for r in rows if r['status']!='NOT_RUN']
                    self.assertEqual([(r['id'],r['status'],r['reason_code']) for r in active],[('inputs',status,code)])
                    self.assertTrue(all(r['command'] is None and r['cleanup']=='not_started' for r in rows))


class RefusalCompletionTests(unittest.TestCase):
    def test_diagnostic_cannot_certify_timeout_log_bound_or_interruption(self):
        import dependency_probe as probe
        self.assertTrue(hasattr(probe,'accept_refusal'), 'refusal completion predicate is absent')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); source=root/'src'; source.mkdir()
            (source/'lib.rs').write_text('fn check() { btf.type_by_id(1); }\n')
            lock=root/'Cargo.lock'; lock.write_text('frozen lock\n'); lock_sha=policy.sha(lock)
            diagnostic=dict(reason='compiler-message',message=dict(code=dict(code='E0624'),message='method `type_by_id` is private',spans=[dict(file_name=str(source/'lib.rs'),line_start=1,is_primary=True)]))
            log=root/'diagnostics'; log.write_text(json.dumps(diagnostic)+'\n')
            # This is a report predicate unit, not a fabricated Rust/Cargo run.
            result=dict(cleanup='complete',exit_code=101,reason_code=None,logs=dict(stdout=dict(path=str(log))))
            probe.accept_refusal(result,lock,lock_sha,'E0624','type_by_id',root)
            for reason in ('TIMEOUT','LOG_BOUND','INTERRUPTED'):
                changed={**result,'reason_code':reason}
                with self.subTest(reason=reason):
                    with self.assertRaises(policy.PolicyError) as error:
                        probe.accept_refusal(changed,lock,lock_sha,'E0624','type_by_id',root)
                    self.assertEqual((error.exception.status,error.exception.code),('BLOCKED',reason))
            with self.assertRaisesRegex(policy.PolicyError,'CLEANUP_UNRESOLVED'):
                probe.accept_refusal({**result,'cleanup':'unresolved'},lock,lock_sha,'E0624','type_by_id',root)
            with self.assertRaisesRegex(policy.PolicyError,'REFUSAL_INCOMPLETE'):
                probe.accept_refusal({**result,'exit_code':None},lock,lock_sha,'E0624','type_by_id',root)
            lock.write_text('changed lock\n')
            with self.assertRaisesRegex(policy.PolicyError,'LOCK_CHANGED'):
                probe.accept_refusal(result,lock,lock_sha,'E0624','type_by_id',root)
