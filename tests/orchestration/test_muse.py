"""Real Git/process tests; only the external Muse service is controlled."""

import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "bin/muse-run.sh"


class MuseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="scopebase muse ")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "candidate with spaces"
        self.repo.mkdir()
        for args in (["init", "-q"], ["config", "user.name", "Test"],
                     ["config", "user.email", "test@example.invalid"]):
            self.git(*args)
        (self.repo / "source.txt").write_text("candidate\n")
        self.git("add", "source.txt")
        self.git("commit", "-qm", "candidate")
        self.head = self.git("rev-parse", "HEAD").stdout.strip()
        self.prompt = self.base / "review prompt.txt"
        self.prompt.write_text("Review this candidate and return the structured review report.\n")
        self.prefix = self.base / "private result"
        self.report = {"status": "REVIEW_COMPLETE", "reviewed_commit": self.head,
                       "summary": "A delivered review, with findings.",
                       "findings": [{"severity": "important", "message": "Example concern"}],
                       "concerns": ["External service fixture only"]}
        self.events = self.base / "service events.jsonl"
        self.set_events([self.terminal()])
        self.launch = self.base / "launched.json"
        self.fake_bin = self.base / "fake bin"
        self.fake_bin.mkdir()
        fake = self.fake_bin / "muse"
        fake.write_text("""#!/usr/bin/env python3
import json, os, pathlib, signal, subprocess, sys
if sys.argv[1:] == ['--version']:
    print('Muse Code 1.4.10 (controlled external-service fixture)')
    raise SystemExit(0)
pathlib.Path(os.environ['FAKE_LAUNCH']).write_text(json.dumps({
    'argv': sys.argv[1:], 'cwd': os.getcwd(), 'tmpdir': os.environ.get('TMPDIR')}))
if os.environ.get('FAKE_CHANGE_HEAD'):
    subprocess.run(['git', 'commit', '--allow-empty', '-qm', 'moved during review'], check=True)
if os.environ.get('FAKE_WRITE_PATH'):
    pathlib.Path(os.environ['FAKE_WRITE_PATH']).write_text(os.environ.get('FAKE_WRITE_CONTENT', 'changed during review\\n'))
sys.stdout.buffer.write(pathlib.Path(os.environ['FAKE_EVENTS']).read_bytes())
sys.stdout.buffer.flush()
if os.environ.get('FAKE_SIGNAL'):
    os.kill(os.getpid(), signal.SIGTERM)
raise SystemExit(int(os.environ.get('FAKE_EXIT', '0')))
""")
        fake.chmod(0o700)
        self.env = dict(os.environ, PATH=str(self.fake_bin) + os.pathsep + os.environ["PATH"],
                        FAKE_LAUNCH=str(self.launch), FAKE_EVENTS=str(self.events))

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], text=True,
                              capture_output=True, check=True)

    def terminal(self, report=None, kind="completed", terminal="completed"):
        # Complete envelope shape observed in Muse 1.4.10, with synthetic IDs.
        # The outer SESSION stream differs from the payload's RUN stream.
        return {"schema_version": 1, "id": "terminal-event", "stream": {"kind": "session", "id": "session-1"},
                "sequence": 8, "recorded_at": 1, "record_type": "event", "durability": "durable",
                "causation_id": "cause-1", "payload_type": "run.terminal." + kind,
                "payload_schema_version": 1,
                "payload": {"command_id": "command-1", "kind": "run_terminal", "terminal": terminal,
                            "text": json.dumps(self.report if report is None else report),
                            "reason": None, "run_stream": {"kind": "run", "id": "run-1"}}}

    def set_events(self, events):
        self.events.write_text("".join(json.dumps(event) + "\n" for event in events))

    def run_wrapper(self, *extra, paths=None):
        args = paths or [str(self.repo), str(self.prompt), str(self.prefix)]
        # bash also makes the pre-implementation failure an assertion, not a spawn exception.
        return subprocess.run(["bash", str(WRAPPER), *args, *extra], text=True,
                              capture_output=True, env=self.env, timeout=10)

    def metadata(self):
        return json.loads(Path(str(self.prefix) + ".execution.json").read_text())

    def assert_not_launched_or_reserved(self):
        self.assertFalse(self.launch.exists())
        for suffix in (".jsonl", ".err", ".final.txt", ".execution.json", ".tmp"):
            self.assertFalse(Path(str(self.prefix) + suffix).exists())

    def configure_source_filter(self, field="clean", canonical=False):
        (self.repo / ".gitattributes").write_text("source.txt filter=review-fixture\n")
        self.git("add", ".gitattributes")
        self.git("commit", "-qm", "declare source filter")
        self.head = self.git("rev-parse", "HEAD").stdout.strip()
        self.report["reviewed_commit"] = self.head
        self.set_events([self.terminal()])
        marker = self.base / "filter executed"
        script = self.base / "configured filter.py"
        body = "#!/usr/bin/env python3\nimport pathlib, sys\npathlib.Path(" + repr(str(marker)) + ").touch()\n"
        if field == "process":
            # Deliberately exit after the sentinel; no filter protocol emulator.
            body += "raise SystemExit(1)\n"
        else:
            body += "content = sys.stdin.buffer.read()\n"
            body += "sys.stdout.buffer.write(b'candidate\\n' if " + repr(canonical) + " else content)\n"
        script.write_text(body)
        self.git("config", "filter.review-fixture." + field, shlex.join([sys.executable, str(script)]))
        self.git("config", "filter.review-fixture.required", "true")
        return marker

    def test_valid_review_keeps_findings_separate_from_acceptance(self):
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        data = self.metadata()
        self.assertEqual(data["raw_exit_status"], 0)
        self.assertEqual(data["before_head"], self.head)
        self.assertEqual(data["after_head"], self.head)
        self.assertEqual(data["report"]["findings"], self.report["findings"])
        self.assertEqual(data["acceptance"], "NOT_DECIDED")
        self.assertEqual(data["effective_provider_tier"]["status"], "unverified")
        self.assertEqual(json.loads(Path(str(self.prefix) + ".final.txt").read_text()), self.report)
        self.assertEqual(self.git("status", "--porcelain").stdout, "")

    def test_registered_detached_worktree_is_reviewed_without_new_worktree(self):
        worktree = self.base / "registered worktree"
        self.git("worktree", "add", "--detach", str(worktree), self.head)
        self.repo = worktree
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.metadata()["before_head"], self.head)
        self.assertEqual(self.git("status", "--porcelain").stdout, "")
        self.assertEqual(self.git("worktree", "list", "--porcelain").stdout.count("worktree "), 2)

    def test_enforced_arguments_and_private_artifacts(self):
        result = self.run_wrapper("--max-steps", "7")
        self.assertEqual(result.returncode, 0, result.stderr)
        launched = json.loads(self.launch.read_text())
        argv = launched["argv"]
        self.assertEqual(argv[0], "exec")
        self.assertIn("--max-tool-output-bytes", argv)
        for flag, value in {"--provider": "meta", "--model": "muse-spark-1.3",
                            "--reasoning-effort": "max", "--contributor-mode": "on",
                            "--workspace": str(self.repo), "--worktree": "off",
                            "--approval-mode": "never", "--max-model-steps": "7",
                            "--max-tool-output-bytes": "65536",
                            "--prompt-file": str(self.prompt)}.items():
            self.assertEqual(argv[argv.index(flag) + 1], value)
        for flag in ("--json", "--disable-write", "--disable-shell", "--disable-web-tools",
                     "--disable-reminders", "--disable-request-user-input", "--trust-workspace"):
            self.assertIn(flag, argv)
        for flag in ("--yolo", "--disable-sandbox", "--disable-approval"):
            self.assertNotIn(flag, argv)
        self.assertEqual(launched["cwd"], str(self.repo))
        self.assertEqual(stat.S_IMODE(Path(launched["tmpdir"]).stat().st_mode), 0o700)
        for suffix in (".jsonl", ".err", ".final.txt", ".execution.json"):
            self.assertEqual(stat.S_IMODE(Path(str(self.prefix) + suffix).stat().st_mode), 0o600)

    def test_dry_run_records_plan_without_starting_model(self):
        result = self.run_wrapper("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.launch.exists())
        self.assertEqual(self.metadata()["execution_state"], "DRY_RUN")
        self.assertIsNone(self.metadata()["raw_exit_status"])
        self.assertIsNone(self.metadata()["report"])

    def test_child_failure_is_preserved_even_with_completed_terminal(self):
        self.env["FAKE_EXIT"] = "75"
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertEqual(self.metadata()["raw_exit_status"], 75)
        self.assertNotEqual(self.metadata()["execution_state"], "REVIEW_DELIVERED")

    def test_child_signal_uses_conventional_status_and_records_raw_signal(self):
        self.env["FAKE_SIGNAL"] = "1"
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 143, result.stderr)
        self.assertEqual(self.metadata()["raw_exit_status"], -15)

    def test_invalid_terminal_populations_never_report_success(self):
        populations = {
            "missing": [],
            "failed": [self.terminal(kind="failed", terminal="failed")],
            "mismatched": [self.terminal(terminal="failed")],
            "wrong type": [self.terminal(kind="failed")],
            "duplicate": [self.terminal(), self.terminal()],
            "contradictory": [self.terminal(), self.terminal(kind="failed", terminal="failed")],
            "empty": [{"payload_type": "run.terminal.completed", "payload": {
                "terminal": "completed", "text": "", "reason": None, "run_stream": "review-stream"}}],
            "malformed payload": [{"payload_type": "run.terminal.completed", "payload": []}],
        }
        for name, events in populations.items():
            with self.subTest(name=name):
                self.prefix = self.base / name
                self.set_events(events)
                result = self.run_wrapper()
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertTrue(self.metadata()["evidence_errors"])

    def test_malformed_stream_rejected_even_if_terminal_is_valid(self):
        bad_lines = (b'{broken', b'\xff', ("[" * 1500 + "0" + "]" * 1500).encode())
        for index, bad_line in enumerate(bad_lines):
            with self.subTest(index=index):
                self.prefix = self.base / ("bad stream " + str(index))
                self.events.write_bytes(bad_line + b'\n' + json.dumps(self.terminal()).encode() + b'\n')
                result = self.run_wrapper()
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertEqual(self.metadata()["raw_exit_status"], 0)

    def test_terminal_requires_a_valid_run_binding(self):
        variants = (("run_stream", None), ("run_stream", {"kind": "session", "id": "run-1"}),
                    ("run_stream", {"kind": "run", "id": ""}), ("command_id", ""),
                    ("kind", "other"))
        for index, (field, value) in enumerate(variants):
            with self.subTest(field=field, value=value):
                self.prefix = self.base / ("bad run binding " + str(index))
                event = self.terminal()
                event["payload"][field] = value
                self.set_events([event])
                self.assertEqual(self.run_wrapper().returncode, 3)

    def test_invalid_json_reports_rejected(self):
        variants = []
        for key, value in (("status", "PASS"), ("reviewed_commit", self.head[:12]),
                           ("reviewed_commit", "0" * 40), ("summary", " "),
                           ("findings", [{"severity": "warning", "message": "issue"}]),
                           ("findings", [{"severity": "minor", "message": ""}]),
                           ("findings", {}), ("concerns", "none")):
            variants.append(dict(self.report, **{key: value}))
        variants.append({"status": "REVIEW_COMPLETE"})
        for index, report in enumerate(variants):
            with self.subTest(index=index):
                self.prefix = self.base / ("bad report " + str(index))
                self.set_events([self.terminal(report)])
                self.assertEqual(self.run_wrapper().returncode, 3)

    def test_non_json_and_duplicate_keys_in_report_refuse(self):
        for index, text in enumerate(("Review complete", '{"status":"REVIEW_COMPLETE","status":"PASS"}', "\ud800")):
            with self.subTest(text=text):
                self.prefix = self.base / ("bad text " + str(index))
                event = self.terminal()
                event["payload"]["text"] = text
                self.set_events([event])
                self.assertEqual(self.run_wrapper().returncode, 3)

    def test_changed_head_invalidates_otherwise_valid_review(self):
        self.env["FAKE_CHANGE_HEAD"] = "1"
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertNotEqual(self.metadata()["before_head"], self.metadata()["after_head"])

    def test_dirty_tracked_source_refuses_before_launch_or_artifacts(self):
        for staged in (False, True):
            with self.subTest(staged=staged):
                self.prefix = self.base / ("dirty source " + str(staged))
                (self.repo / "source.txt").write_text("changed before review\n")
                if staged:
                    self.git("add", "source.txt")
                result = self.run_wrapper()
                self.assertEqual(result.returncode, 64, result.stderr)
                self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), self.head)
                self.assert_not_launched_or_reserved()
                (self.repo / "source.txt").write_text("candidate\n")
                self.git("add", "source.txt")

    def test_untracked_source_refuses_before_launch_or_artifacts(self):
        (self.repo / "new source.txt").write_text("untracked source\n")
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), self.head)
        self.assert_not_launched_or_reserved()

    def test_source_mutation_with_unchanged_head_invalidates_review(self):
        for name in ("source.txt", "new source.txt"):
            with self.subTest(name=name):
                self.prefix = self.base / ("postrun " + name)
                self.env["FAKE_WRITE_PATH"] = name
                result = self.run_wrapper()
                self.assertEqual(result.returncode, 3, result.stderr)
                record = self.metadata()
                self.assertEqual(record["before_head"], self.head)
                self.assertEqual(record["after_head"], self.head)
                self.assertEqual(record["execution_state"], "INVALID_EVIDENCE")
                self.assertEqual(record["report"], self.report)
                self.assertTrue(record["evidence_errors"])
                self.assertTrue(Path(str(self.prefix) + ".jsonl").read_text())
                if name == "source.txt":
                    (self.repo / name).write_text("candidate\n")
                else:
                    (self.repo / name).unlink()

    def test_dirty_completion_preserves_failed_child_status(self):
        self.env.update(FAKE_WRITE_PATH="source.txt", FAKE_EXIT="75")
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertEqual(self.metadata()["raw_exit_status"], 75)
        self.assertTrue(self.metadata()["evidence_errors"])

    def test_ignored_private_inputs_and_outputs_remain_allowed(self):
        (self.repo / ".gitignore").write_text("/.scopebase/\n")
        self.git("add", ".gitignore")
        self.git("commit", "-qm", "ignore private review state")
        self.head = self.git("rev-parse", "HEAD").stdout.strip()
        self.report["reviewed_commit"] = self.head
        self.set_events([self.terminal()])
        private = self.repo / ".scopebase"
        private.mkdir(mode=0o700)
        self.prompt = private / "prompt.txt"
        self.prompt.write_text("Review the immutable candidate.\n")
        self.prefix = private / "review"
        self.env["FAKE_WRITE_PATH"] = ".scopebase/private-note.txt"
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.metadata()["execution_state"], "REVIEW_DELIVERED")
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all").stdout, "")

    def test_source_check_does_not_execute_configured_fsmonitor(self):
        marker = self.base / "fsmonitor executed"
        hook = self.base / "fsmonitor hook"
        hook.write_text("#!/usr/bin/env python3\nfrom pathlib import Path\nPath(" +
                        repr(str(marker)) + ").touch()\n")
        hook.chmod(0o700)
        self.git("config", "core.fsmonitor", str(hook))
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())

    def test_source_check_does_not_execute_configured_clean_filter(self):
        marker = self.configure_source_filter()
        source = self.repo / "source.txt"
        before = source.stat()
        os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns + 2_000_000_000))
        result = self.run_wrapper("--dry-run")
        self.assertFalse(marker.exists(), "Git status executed the configured clean filter")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.launch.exists())
        self.assertEqual(source.read_bytes(), b"candidate\n")

    def test_source_check_does_not_execute_configured_process_filter(self):
        marker = self.configure_source_filter(field="process")
        source = self.repo / "source.txt"
        before = source.stat()
        os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns + 2_000_000_000))
        result = self.run_wrapper("--dry-run")
        self.assertFalse(marker.exists(), "Git status executed the configured process filter")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.launch.exists())

    def test_canonicalizing_filter_cannot_hide_dirty_source_before_review(self):
        marker = self.configure_source_filter(canonical=True)
        (self.repo / "source.txt").write_bytes(b"different\n")
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assert_not_launched_or_reserved()
        self.assertFalse(marker.exists())
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), self.head)
        self.assertEqual((self.repo / "source.txt").read_bytes(), b"different\n")

    def test_canonicalizing_filter_cannot_hide_dirty_source_after_review(self):
        marker = self.configure_source_filter(canonical=True)
        self.env.update(FAKE_WRITE_PATH="source.txt", FAKE_WRITE_CONTENT="different\n")
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertFalse(marker.exists())
        record = self.metadata()
        self.assertEqual(record["raw_exit_status"], 0)
        self.assertEqual(record["before_head"], self.head)
        self.assertEqual(record["after_head"], self.head)
        self.assertFalse(record["source_clean_after"])
        self.assertEqual(record["execution_state"], "INVALID_EVIDENCE")
        self.assertEqual((self.repo / "source.txt").read_bytes(), b"different\n")

    def test_prompt_limit_uses_utf8_bytes_at_n_and_n_plus_one(self):
        cases = ((b"a" * 65536, 0), (b"a" * 65537, 64),
                 (("é" * 32768).encode("utf-8"), 0),
                 (("é" * 32768 + "a").encode("utf-8"), 64))
        for index, (content, expected) in enumerate(cases):
            with self.subTest(index=index, byte_count=len(content)):
                self.prefix = self.base / ("prompt boundary " + str(index))
                self.prompt.write_bytes(content)
                self.launch.unlink(missing_ok=True)
                result = self.run_wrapper()
                self.assertEqual(result.returncode, expected, result.stderr)
                if expected == 64:
                    self.assert_not_launched_or_reserved()

    def test_unrelated_runtime_events_do_not_count_as_terminals_or_confirm_tier(self):
        event = {"payload_type": "runtime.session", "payload": {"event": {"details": {
            "phase": "model_completed", "facet": {"detail": {"model": "muse-spark-1.3-contributor"}}}}}}
        self.set_events([event, self.terminal()])
        self.assertEqual(self.run_wrapper().returncode, 0)
        self.assertEqual(self.metadata()["effective_provider_tier"]["status"], "unverified")

    def test_each_existing_or_symlink_artifact_refuses_without_clobber(self):
        for index, suffix in enumerate((".jsonl", ".err", ".final.txt", ".execution.json", ".tmp")):
            for symlink in (False, True):
                with self.subTest(suffix=suffix, symlink=symlink):
                    self.prefix = self.base / ("collision " + str(index) + str(symlink))
                    artifact = Path(str(self.prefix) + suffix)
                    target = self.base / ("target " + str(index))
                    target.write_text("preserved")
                    if symlink:
                        artifact.symlink_to(target)
                    else:
                        artifact.write_text("preserved")
                    result = self.run_wrapper()
                    self.assertEqual(result.returncode, 64, result.stderr)
                    self.assertEqual(target.read_text(), "preserved")
                    self.assertEqual(artifact.read_text(), "preserved")
                    self.assertFalse(self.launch.exists())

    def test_symlink_output_parent_refuses(self):
        link = self.base / "linked directory"
        link.symlink_to(self.repo, target_is_directory=True)
        self.prefix = link / "result"
        self.assertEqual(self.run_wrapper().returncode, 64)
        self.assertFalse(self.launch.exists())

    def test_unknown_flags_and_step_bounds_are_usage_errors(self):
        for extra in (("--provider", "echo"), ("--yolo",), ("--max-steps", "33"),
                      ("--max-steps", "0"), ("--max-steps", "no")):
            with self.subTest(extra=extra):
                self.assertEqual(self.run_wrapper(*extra).returncode, 64)
                self.assertFalse(self.launch.exists())

    def test_relative_paths_and_empty_prompt_refuse(self):
        for index in range(3):
            paths = [str(self.repo), str(self.prompt), str(self.prefix)]
            paths[index] = "relative"
            self.assertEqual(self.run_wrapper(paths=paths).returncode, 64)
        self.prompt.write_text("  \n")
        self.assertEqual(self.run_wrapper().returncode, 64)
        self.assertFalse(self.launch.exists())

    def test_prefix_reservation_is_single_winner_under_real_concurrency(self):
        command = ["bash", str(WRAPPER), str(self.repo), str(self.prompt), str(self.prefix)]
        first = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        second = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        first.communicate(timeout=10)
        second.communicate(timeout=10)
        self.assertEqual(sorted([first.returncode, second.returncode]), [0, 64])
        self.assertEqual(self.metadata()["report"], self.report)


if __name__ == "__main__":
    unittest.main()
