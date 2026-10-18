import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]


class PlanningDiscoveryTests(unittest.TestCase):
    def test_checker_uses_git_deliverables_and_keeps_tracked_ignored_docs(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Path(temp) / "planning repo"
            fixture.mkdir()
            tracked = subprocess.run(
                ["git", "-C", str(REPO), "ls-files", "-z"],
                check=True,
                stdout=subprocess.PIPE,
            ).stdout.split(b"\0")
            for raw_path in filter(None, tracked):
                relative = Path(raw_path.decode())
                source = REPO / relative
                if source.is_file():
                    target = fixture / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, target)
            checker = fixture / "tools/check_planning_docs.py"
            shutil.copy2(REPO / "tools/check_planning_docs.py", checker)
            subprocess.run(["git", "init", "-q", str(fixture)], check=True)
            subprocess.run(["git", "-C", str(fixture), "add", "-A"], check=True)

            ignored_doc = fixture / ".worktrees/worker with spaces/ignored.md"
            ignored_doc.parent.mkdir(parents=True)
            ignored_doc.write_text("[broken](missing-ignored-target.md)\n")
            result = subprocess.run(
                ["python3", str(checker)], text=True, capture_output=True
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            untracked_doc = fixture / "docs/untracked with spaces.md"
            untracked_doc.write_text("[broken](missing-untracked-target.md)\n")
            result = subprocess.run(
                ["python3", str(checker)], text=True, capture_output=True
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("missing missing-untracked-target.md", result.stdout)
            untracked_doc.unlink()

            tracked_ignored_doc = fixture / ".scopebase/tracked with spaces.md"
            tracked_ignored_doc.parent.mkdir(parents=True)
            tracked_ignored_doc.write_text("[broken](missing-tracked-target.md)\n")
            subprocess.run(
                ["git", "-C", str(fixture), "add", "-f", str(tracked_ignored_doc)],
                check=True,
            )
            result = subprocess.run(
                ["python3", str(checker)], text=True, capture_output=True
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("missing missing-tracked-target.md", result.stdout)


if __name__ == "__main__":
    unittest.main()
