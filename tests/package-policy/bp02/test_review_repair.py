# SPDX-License-Identifier: Apache-2.0
"""BP02 review regressions; local children only, no guest or BPF calls."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


FIXTURES = Path(__file__).resolve().parents[3] / "crates/scopebase-bpf/tests/fixtures/bp02"
sys.path.insert(0, str(FIXTURES))


def load(name):
    spec = importlib.util.spec_from_file_location(name, FIXTURES / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def matching_mount_children():
    """Synthetic transported-receipt population; never runtime authority."""
    children = []
    for pid, case in enumerate(['full-root','fake','online-leaf','symlink-leaf','symlink-root','subtree',
                                'full-root','replace-root','full-root','fork','nested'], 101):
        required = case not in ('fork', 'nested')
        output = 'PASS owned fixture\n'
        if not required:
            output += 'BP02_INTERNAL_CHILD_CUSTODY=' + json.dumps({
                'schema_version': 1, 'child_pid': 2, 'returned_pid': 2, 'status': 0,
                'errno': None, 'attempts': 1, 'retries': 0, 'child_reaped': True,
                'child_success': True, 'custody_unresolved': False}) + '\n'
        children.append({'schema_version': 1, 'case_hex': case.encode().hex(),
            'child_pid': pid, 'child_reaped': True, 'child_exit': 0, 'child_success': True,
            'root_required': required, 'expected_temp_root_hex': ('/tmp/scopebase-bp02-' + str(pid)).encode().hex(),
            'root_report_count': int(required), 'identity_report_count': int(required),
            'reported_identity': [47, pid + 20] if required else None,
            'observed_identity': [47, pid + 20] if required else None,
            'report_error_hex': None, 'cleanup_error_hex': None, 'child_error_hex': None,
            'cleanup_status': 'PASS' if required else 'NOT_REQUIRED', 'owned_temp_removed': required,
            'custody_unresolved': False, 'child_stdout_hex': output.encode().hex(), 'child_stderr_hex': ''})
    return children


class PrebuiltBindingTests(unittest.TestCase):
    def setUp(self):
        self.live = load("run_live")
        self.tmp = tempfile.TemporaryDirectory(prefix="bp02-bind-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.package = self.root / "package"
        self.package.mkdir()
        (self.package / "Cargo.toml").write_text("bound manifest\n")
        self.resource_path = self.root / "resource.json"
        self.resource = {
            "kind": "ROOT_BP02_RESOURCE_ADMISSION",
            "schema_version": 1,
            "status": "ADMITTED_FOR_STAGING_AND_REVIEWED_BP02_TEST_EXECUTION",
            "owner": {"token": "owned-token", "root": "/owned/root", "host": "owned-host"},
            "kernel": {"release": "owned-kernel", "kernel_sha256": "kernel-digest",
                       "config_sha256": "config-digest", "gnu_build_id": "build-id"},
            "resource_sha256": "admitted-resource-digest",
        }
        self.resource_path.write_text(json.dumps(self.resource))
        self.spec = {"bindings": {
            "compiler": "1.98.1", "feature": "default",
            "manifest_sha256": self.live.sha(self.package / "Cargo.toml"),
            "owned_resource_sha256": self.live.sha(self.resource_path),
            "owned_resource_identity": {
                "kind": "ROOT_BP02_RESOURCE_ADMISSION", "schema_version": 1,
                "status": "ADMITTED_FOR_STAGING_AND_REVIEWED_BP02_TEST_EXECUTION",
                "owner_token": "owned-token", "owner_root": "/owned/root",
                "owner_host": "owned-host", "kernel_release": "owned-kernel",
                "kernel_sha256": "kernel-digest", "config_sha256": "config-digest",
                "gnu_build_id": "build-id", "resource_sha256": "admitted-resource-digest",
            },
        }}

    def check(self, compiler="1.98.1", feature="default"):
        return self.live.validate_prebuilt_bindings(
            self.spec, self.package, self.resource_path, self.resource, compiler, feature
        )

    def test_matching_prebuilt_resource_compiler_feature_and_manifest(self):
        self.assertEqual(set(self.check().values()), {"PASS"})

    def test_changed_resource_bytes_and_identity_refuse(self):
        self.resource_path.write_text(self.resource_path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "owned resource digest"):
            self.check()
        self.resource_path.write_text(json.dumps(self.resource))
        self.spec["bindings"]["owned_resource_identity"]["owner_token"] = "other"
        with self.assertRaisesRegex(ValueError, "owned resource identity"):
            self.check()

    def test_requested_compiler_feature_and_package_refuse(self):
        for compiler, feature, expected in [
            ("1.88.0", "default", "compiler"),
            ("1.98.1", "no-default", "feature"),
        ]:
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, expected):
                self.check(compiler, feature)
        (self.package / "Cargo.toml").write_text("different manifest\n")
        with self.assertRaisesRegex(ValueError, "manifest"):
            self.check()

    def test_resource_without_reviewed_admission_refuses(self):
        self.resource["status"] = "NOT_ADMITTED"
        self.resource_path.write_text(json.dumps(self.resource))
        self.spec["bindings"]["owned_resource_sha256"] = self.live.sha(self.resource_path)
        self.spec["bindings"]["owned_resource_identity"]["status"] = "NOT_ADMITTED"
        with self.assertRaisesRegex(ValueError, "admission"):
            self.check()

    def test_prebuilt_cli_retains_binding_failure_receipt_without_execution(self):
        spec_path = self.root / "prebuilt.json"
        spec_path.write_text(json.dumps(self.spec))
        out = self.root / "receipt-out"
        result = subprocess.run(
            [sys.executable, str(FIXTURES / "run_live.py"), "--package", str(self.package),
             "--out", str(out), "--toolchain", "1.98.1", "--feature", "no-default",
             "--owned-resource", str(self.resource_path), "--prebuilt", str(spec_path)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        self.assertNotEqual(result.returncode, 0)
        receipt = json.loads((out / "receipt.json").read_text())
        self.assertEqual(receipt["status"], "FAILED")
        self.assertIn("feature mismatch", receipt["error"])
        self.assertEqual(receipt["commands"], [])


class SymlinkCustodyTests(unittest.TestCase):
    def setUp(self):
        self.live = load("run_live")
        self.tmp = tempfile.TemporaryDirectory(prefix="bp02-child-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / "out"
        self.out.mkdir()
        self.child = self.root / "child.py"
        self.child.write_text(
            "#!/usr/bin/env python3\n"
            "import os,pathlib,sys\n"
            "p=pathlib.Path(os.environ['TMPDIR'])/('scopebase-bp02-'+str(os.getpid()))\n"
            "p.mkdir()\n"
            "print('OWNED_TEMP_ROOT='+str(p),flush=True)\n"
            "s=p.stat()\n"
            "print('OWNED_TEMP_ROOT_ID='+str(s.st_dev)+':'+str(s.st_ino),flush=True)\n"
            "print(os.environ.get('CHILD_MARKER',''),flush=True)\n"
            "sys.exit(101)\n"
        )
        self.child.chmod(0o700)
        self.env = {**os.environ, "TMPDIR": str(self.root), "CHILD_MARKER": "false source accepted symlink-root\npanicked at"}

    def test_missing_semantic_marker_still_records_reap_and_cleanup(self):
        self.env["CHILD_MARKER"] = "later setup panic"
        rows = []
        with self.assertRaisesRegex(RuntimeError, "semantic"):
            self.live.run_symlink_case("N6-no-symlink-control", self.child, True,
                                       self.env, self.out, rows)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["semantic_status"], "FAILED_SEMANTIC_ASSERTION")
        self.assertTrue(rows[0]["child_reaped"])
        self.assertEqual(rows[0]["cleanup_status"], "PASS")
        self.assertTrue(rows[0]["owned_temp_removed"])
        self.assertFalse(list(self.root.glob("scopebase-bp02-*")))

    def test_cleanup_failure_retains_child_and_unresolved_path(self):
        import unittest.mock
        rows = []
        with unittest.mock.patch.object(self.live.shutil, "rmtree", side_effect=OSError("cleanup denied")):
            with self.assertRaisesRegex(RuntimeError, "cleanup"):
                self.live.run_symlink_case("N6-no-symlink-control", self.child, True,
                                           self.env, self.out, rows)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["child_reaped"])
        self.assertEqual(rows[0]["semantic_status"], "EXPECTED_SEMANTIC_FAILURE")
        self.assertEqual(rows[0]["cleanup_status"], "FAILED")
        self.assertFalse(rows[0]["owned_temp_removed"])
        self.assertTrue(Path(rows[0]["unresolved_temp_root"]).is_dir())

    def test_root_identity_mismatch_is_unresolved_and_never_deleted(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        import stat
        real_lstat = Path.lstat

        def changed_identity(path, *args, **kwargs):
            current = real_lstat(path, *args, **kwargs)
            if path.parent == self.root and path.name.startswith("scopebase-bp02-"):
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700,
                                       st_dev=current.st_dev, st_ino=current.st_ino + 1)
            return current

        rows = []
        with patch.object(Path, "lstat", changed_identity):
            with patch.object(self.live.shutil, "rmtree") as remove:
                with self.assertRaises(RuntimeError):
                    self.live.run_symlink_case("N6-no-symlink-control", self.child, True,
                                               self.env, self.out, rows)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["child_reaped"])
        self.assertEqual(rows[0]["semantic_status"], "EXPECTED_SEMANTIC_FAILURE")
        remove.assert_not_called()
        self.assertEqual(rows[0]["cleanup_status"], "UNRESOLVED")
        self.assertFalse(rows[0]["owned_temp_removed"])
        self.assertTrue(rows[0]["custody_unresolved"])


class SymlinkLogFailureTests(unittest.TestCase):
    """Log persistence must never bypass owned-root retirement or its row."""
    def setUp(self):
        self.live = load("run_live")
        self.tmp = tempfile.TemporaryDirectory(prefix="bp02-log-failure-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.owned = self.root / "scopebase-bp02-314159"
        self.owned.mkdir()
        owned = self.owned

        class NoChild:
            pid = 314159
            returncode = 101

            def communicate(self):
                identity = owned.stat()
                return ("OWNED_TEMP_ROOT=" + str(owned) +
                        "\nOWNED_TEMP_ROOT_ID=" + str(identity.st_dev) + ":" + str(identity.st_ino) +
                        "\nfalse source accepted symlink-root\npanicked at semantic assertion\n", None)

            def kill(self):
                raise AssertionError("no actual child launched")

        self.child = NoChild()

    def invoke(self, rows):
        return self.live.run_symlink_case(
            "N6-no-symlink-control", Path("/never-executed"), True,
            {"TMPDIR": str(self.root)}, self.root, rows
        )

    def assert_log_failure_retained(self, rows):
        self.assertFalse(self.owned.exists(), "log I/O failure bypassed owned-root cleanup")
        self.assertEqual(len(rows), 1, "log I/O failure bypassed custody-row retention")
        row = rows[0]
        self.assertTrue(row["child_reaped"])
        self.assertEqual(row["semantic_status"], "EXPECTED_SEMANTIC_FAILURE")
        self.assertEqual(row["cleanup_status"], "PASS")
        self.assertTrue(row["owned_temp_removed"])
        self.assertEqual(row["status"], "LOG_PERSISTENCE_FAILED")
        self.assertIn("injected", row["log_error"])
        self.assertNotIn("log_sha256", row)

    def test_log_write_failure_retires_owned_root_and_retains_custody(self):
        from unittest.mock import patch
        rows = []
        with patch.object(self.live.subprocess, "Popen", return_value=self.child):
            with patch.object(Path, "write_text", side_effect=OSError(28, "injected log write failure")):
                with self.assertRaises(Exception):
                    self.invoke(rows)
        self.assert_log_failure_retained(rows)

    def test_log_hash_failure_retires_owned_root_and_retains_custody(self):
        from unittest.mock import patch
        rows = []
        with patch.object(self.live.subprocess, "Popen", return_value=self.child):
            with patch.object(self.live, "sha", side_effect=OSError(5, "injected log hash failure")):
                with self.assertRaises(Exception):
                    self.invoke(rows)
        self.assert_log_failure_retained(rows)

    def test_restored_log_positive_retires_owned_root(self):
        from unittest.mock import patch
        rows = []
        with patch.object(self.live.subprocess, "Popen", return_value=self.child):
            self.invoke(rows)
        self.assertFalse(self.owned.exists())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "EXPECTED_SEMANTIC_FAILURE")
        self.assertEqual(rows[0]["cleanup_status"], "PASS")
        self.assertNotIn("log_error", rows[0])
        self.assertEqual(rows[0]["log_sha256"], self.live.sha(self.root / "N6-no-symlink-control.log"))


class MutantOracleTests(unittest.TestCase):
    def test_later_unwrap_panic_does_not_kill_stale80(self):
        mutants = load("run_mutants")
        later = "test who88_every_lookup_path ... FAILED\nthread panicked at valid 88 unwrap\n"
        with self.assertRaisesRegex(AssertionError, "named stale80"):
            mutants.require_semantic_failure(later, "who88_every_lookup_path", "BP02_STALE80_REPORT_REJECTION")
        named = "test who88_every_lookup_path ... FAILED\nthread panicked at BP02_STALE80_REPORT_REJECTION\n"
        mutants.require_semantic_failure(named, "who88_every_lookup_path", "BP02_STALE80_REPORT_REJECTION")


class MountRunnerTests(unittest.TestCase):
    def setUp(self):
        self.live = load('run_live')
        self.tmp = tempfile.TemporaryDirectory(prefix='bp02-mount-runner-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def invoke(self, code, rows):
        return self.live.run_mount_cases([sys.executable, '-c', code], {'PATH': os.environ['PATH'], 'TMPDIR': '/tmp'}, self.root, rows)

    def child_code(self, exit_code=0, children=None):
        records = matching_mount_children() if children is None else children
        text = ''.join('BP02_CHILD_CUSTODY=' + json.dumps(row) + '\n' for row in records)
        text += '3 passed; 0 failed\n' if exit_code == 0 else 'BP02_PRIMARY_RUNNER_FAILURE\n'
        return 'import sys; print(' + repr(text) + ',flush=True); sys.exit(' + str(exit_code) + ')'

    def test_matching_custody_population_and_failed_child_retention(self):
        rows = []
        self.invoke(self.child_code(), rows)
        self.assertEqual(rows[0]['status'], 'PASS')
        self.assertEqual(len(rows[0]['fixture_children']), 11)
        # Reuse no output directory/log file: a distinct owned run retains its row.
        self.root = self.root / 'failed'
        self.root.mkdir()
        rows = []
        with self.assertRaises(RuntimeError): self.invoke(self.child_code(101), rows)
        self.assertTrue(rows[0]['child_reaped'])
        self.assertEqual(rows[0]['exit'], 101)
        self.assertEqual(rows[0]['cleanup_status'], 'PASS')
        self.assertIn('BP02_PRIMARY_RUNNER_FAILURE', rows[0]['primary_output_tail'])

    def test_primary_and_log_failures_remain_together(self):
        from unittest.mock import patch
        rows = []
        with patch.object(Path, 'write_text', side_effect=OSError(5, 'injected mount log failure')):
            with self.assertRaises(RuntimeError): self.invoke(self.child_code(101), rows)
        self.assertTrue(rows[0]['child_reaped'])
        self.assertEqual(rows[0]['exit'], 101)
        self.assertIn('BP02_PRIMARY_RUNNER_FAILURE', rows[0]['primary_output_tail'])
        self.assertIn('injected mount log failure', rows[0]['log_error'])
        self.assertEqual(len(rows[0]['fixture_children']), 11)

    def test_unresolved_child_and_missing_population_refuse(self):
        for index, records in enumerate([matching_mount_children()[:-1], matching_mount_children()]):
            if index: records[0]['custody_unresolved'] = True
            self.root = Path(self.tmp.name) / str(index)
            self.root.mkdir()
            rows = []
            with self.assertRaises(RuntimeError): self.invoke(self.child_code(children=records), rows)
            self.assertEqual(rows[0]['status'], 'FAILED')
            self.assertTrue(rows[0]['custody_unresolved'])

    def test_missing_root_report_distinguishes_absent_and_existing(self):
        pid = 314159
        expected = self.root / ('scopebase-bp02-' + str(pid))
        absent = self.live.cleanup_reported_root('', pid, True, {'TMPDIR': str(self.root)})
        self.assertEqual(absent['cleanup_status'], 'ABSENT')
        self.assertFalse(absent['custody_unresolved'])
        expected.mkdir()
        existing = self.live.cleanup_reported_root('', pid, True, {'TMPDIR': str(self.root)})
        self.assertEqual(existing['cleanup_status'], 'UNRESOLVED')
        self.assertTrue(existing['custody_unresolved'])
        self.assertTrue(expected.is_dir())


class PayloadSummaryTests(unittest.TestCase):
    def setUp(self):
        self.summary = load("payload_summary")
        self.live = load("run_live")
        self.tmp = tempfile.TemporaryDirectory(prefix="bp02-summary-")
        self.addCleanup(self.tmp.cleanup)
        self.payload = Path(self.tmp.name) / "payload"
        self.results = Path(self.tmp.name) / "results"
        (self.payload / "specs").mkdir(parents=True)
        (self.payload / "source").mkdir()
        (self.payload / "archive").mkdir()
        self.results.mkdir()
        (self.payload / "source/Cargo.toml").write_text("source manifest\n")
        (self.payload / "archive/Cargo.toml").write_text("archive manifest\n")
        resource = {
            "kind": "ROOT_BP02_RESOURCE_ADMISSION", "schema_version": 1,
            "status": "ADMITTED_FOR_STAGING_AND_REVIEWED_BP02_TEST_EXECUTION",
            "owner": {"token": "token", "root": "/owned", "host": "host"},
            "kernel": {"release": "release", "kernel_sha256": "kernel",
                       "config_sha256": "config", "gnu_build_id": "build"},
            "resource_sha256": "resource",
        }
        (self.payload / "resource.json").write_text(json.dumps(resource))
        self.native = {}
        for mode in ("default", "no-default"):
            spec = {"bindings": {
                "feature": mode, "compiler": "1.98.1",
                "manifest_sha256": self.live.sha(self.payload / "source/Cargo.toml"),
                "owned_resource_sha256": self.live.sha(self.payload / "resource.json"),
                "owned_resource_identity": self.live.resource_identity(resource),
            }}
            path = self.payload / "specs" / (mode + ".json")
            path.write_text(json.dumps(spec))
            receipt = {
                "status": "PASS", "mode": "native-map", "toolchain": "1.98.1",
                "requested_feature": mode, "resource_sha256": self.live.sha(self.payload / "resource.json"),
                "prebuilt_sha256": self.live.sha(path), "bindings": spec["bindings"],
                "binding_checks": dict.fromkeys(
                    ["owned_resource_digest", "owned_resource_identity", "compiler", "feature", "manifest"], "PASS"
                ),
                "commands": [
                    {"case": "N6-no-symlink-control", "status": "EXPECTED_SEMANTIC_FAILURE",
                     "semantic_status": "EXPECTED_SEMANTIC_FAILURE", "child_reaped": True,
                     "cleanup_status": "PASS", "owned_temp_removed": True, 'custody_unresolved': False,
                     'root_report_count': 1, 'identity_report_count': 1, 'reported_identity': [1, 2], 'observed_identity': [1, 2]},
                    {"case": "N6-symlink-restored", "status": "PASS", "semantic_status": "PASS",
                     "child_reaped": True, "cleanup_status": "PASS", "owned_temp_removed": True, 'custody_unresolved': False,
                     'root_report_count': 1, 'identity_report_count': 1, 'reported_identity': [1, 2], 'observed_identity': [1, 2]},
                    {'case': 'N6-N8', 'status': 'PASS', 'child_reaped': True, 'fixture_custody_validation': 'PASS',
                     'cleanup_status': 'PASS', 'custody_unresolved': False, 'fixture_children': matching_mount_children()},
                    {'case': 'N1-N5-N9', 'status': 'PASS', 'guard_outcomes': [{'stage': 'munmap', 'primary_errno': None,
                     'cleanup_errno': None, 'base': 4096, 'extent': 8192, 'cleanup_status': 'PASS'} for _ in range(42)]},
                ],
            }
            dest = self.results / ("native-" + mode)
            dest.mkdir()
            (dest / "receipt.json").write_text(json.dumps(receipt))
            self.native[mode] = receipt
        archive_spec = {"bindings": {"mode": "actual-unpacked-archive-native", "compiler": "1.98.1",
                                     "input": {"manifest_sha256": self.live.sha(self.payload / "archive/Cargo.toml")}},
                        "clients": {"default": {}, "no-default": {}}}
        (self.payload / "specs/archive-clients.json").write_text(json.dumps(archive_spec))
        dest = self.results / "archive-native"
        dest.mkdir()
        (dest / "receipt.json").write_text(json.dumps({
            "status": "PASS", "mode": "native-map",
            "prebuilt_sha256": self.live.sha(self.payload / "specs/archive-clients.json"),
            "bindings": archive_spec["bindings"],
            "cells": [{"feature": m, "client": "who-reader", "status": "PASS"}
                      for m in ("default", "no-default")],
        }))

    def test_matching_bindings_and_cleanup_pass(self):
        self.assertEqual(self.summary.evaluate(self.payload, self.results)["status"], "PASS")

    def test_runner_guard_validator_requires_complete_population_and_extent(self):
        guards = self.native['default']['commands'][-1]['guard_outcomes']
        self.live.validate_guard_outcomes(guards)
        with self.assertRaisesRegex(ValueError, 'exactly42'):
            self.live.validate_guard_outcomes(guards[:-1])
        guards[0]['extent'] = 8191
        with self.assertRaisesRegex(ValueError, 'failed or unresolved'):
            self.live.validate_guard_outcomes(guards)
        guards[0]['extent'] = 8192
        self.live.validate_guard_outcomes(guards)

    def test_guard_ledger_missing_one_row_refuses_and_restored_twin_passes(self):
        path = self.results / 'native-default/receipt.json'
        row = json.loads(path.read_text())
        guards = next(item for item in row['commands'] if item['case'] == 'N1-N5-N9')['guard_outcomes']
        self.assertEqual(len(guards), 42)
        removed = guards.pop()
        path.write_text(json.dumps(row))
        self.assertEqual(self.summary.evaluate(self.payload, self.results)['status'], 'FAILED',
                         'BP02_GUARD_COMPLETE_LEDGER: missing one owned mapping outcome must refuse')
        guards.append(removed)
        path.write_text(json.dumps(row))
        self.assertEqual(self.summary.evaluate(self.payload, self.results)['status'], 'PASS')

    def test_broad_pass_cannot_hide_missing_binding_or_cleanup(self):
        path = self.results / "native-default/receipt.json"
        row = json.loads(path.read_text())
        row["binding_checks"].pop("owned_resource_identity")
        path.write_text(json.dumps(row))
        self.assertEqual(self.summary.evaluate(self.payload, self.results)["status"], "FAILED")
        row["binding_checks"]["owned_resource_identity"] = "PASS"
        row["commands"][0]["cleanup_status"] = "FAILED"
        path.write_text(json.dumps(row))
        self.assertEqual(self.summary.evaluate(self.payload, self.results)["status"], "FAILED")

    def test_missing_resource_produces_failed_summary(self):
        (self.payload / "resource.json").unlink()
        result = self.summary.evaluate(self.payload, self.results)
        self.assertEqual(result["status"], "FAILED")
        self.assertTrue(result["errors"])

    def test_mount_missing_identity_mismatch_and_unresolved_refuse(self):
        import copy
        path = self.results / 'native-default/receipt.json'
        original = json.loads(path.read_text())
        for fault in ['missing', 'identity', 'unresolved', 'internal-wait', 'guard']:
            with self.subTest(fault=fault):
                row = copy.deepcopy(original)
                mounts = next(item for item in row['commands'] if item['case'] == 'N6-N8')
                if fault == 'missing': mounts['fixture_children'].pop()
                elif fault == 'identity': mounts['fixture_children'][0]['observed_identity'][1] += 1
                elif fault == 'unresolved': mounts['fixture_children'][0]['custody_unresolved'] = True
                elif fault == 'internal-wait':
                    mounts['fixture_children'][-1]['child_stdout_hex'] = b'PASS without internal wait custody'.hex()
                else: next(item for item in row['commands'] if item['case'] == 'N1-N5-N9')['guard_outcomes'][0]['cleanup_errno'] = 5
                path.write_text(json.dumps(row))
                self.assertEqual(self.summary.evaluate(self.payload, self.results)['status'], 'FAILED')
        path.write_text(json.dumps(original))
        self.assertEqual(self.summary.evaluate(self.payload, self.results)['status'], 'PASS')


if __name__ == "__main__":
    unittest.main()
