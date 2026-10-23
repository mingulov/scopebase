# SPDX-License-Identifier: Apache-2.0
"""TT08 tail: CI workflow authoring contract.

The GitHub Actions workflow, the local equivalent script, the runner/secret
docs and the recorded local execution log must exist and agree: CI runs the
same `ci_local.sh` coordinator that runs locally, so both drive affected-check
selection through `scopebase-select` over the reviewed selector core, run the
same fast gates plus affected profile gates, and report unavailable required
checks as incomplete. No privileged runners and no secrets are required.
Standard library only, like the other qualification tests.
"""

import json
import os
import re
import stat
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SCRIPT = ROOT / "tools" / "qualification" / "ci_local.sh"
DOC = ROOT / "docs" / "testing" / "ci.md"
LOG = ROOT / "docs" / "testing" / "ci-local-20261023.log"
IMPACT = ROOT / "profiles" / "impact-v1.json"


class CiWorkflowContract(unittest.TestCase):
    def test_workflow_runs_same_local_coordinator(self):
        text = WORKFLOW.read_text()
        for marker in (
            "tools/qualification/ci_local.sh",
            "--changed-file",
            "--full",
            "--run-root",
            "--lock-root",
            "pull_request",
            "schedule",
            "fetch-depth",
            "Cargo.lock",
        ):
            self.assertIn(marker, text, f"workflow must contain {marker!r}")
        self.assertIn("github.event.pull_request.base.sha", text)

    def test_workflow_needs_no_privileged_runners_or_secrets(self):
        text = WORKFLOW.read_text()
        images = re.findall(r"runs-on:\s*([^\s#]+)", text)
        self.assertTrue(images, "workflow must declare runs-on images")
        for image in images:
            self.assertTrue(
                image.startswith("ubuntu-"),
                f"workflow must run on hosted ubuntu, got {image!r}",
            )
        self.assertNotIn("self-hosted", text)
        self.assertNotIn("secrets.", text)

    def test_local_script_runs_same_selection_and_gates(self):
        self.assertTrue(SCRIPT.exists(), "local CI equivalent script must exist")
        mode = os.stat(SCRIPT).st_mode
        self.assertTrue(mode & stat.S_IXUSR, "local script must be executable")
        text = SCRIPT.read_text()
        self.assertIn("scopebase-select", text)
        for subcommand in ("manifest", "select", "resolve", "account", "gate"):
            self.assertIn(
                f'"$SELECT_BIN" {subcommand}',
                text,
                f"local script must run scopebase-select {subcommand}",
            )
        self.assertIn("--offline", text)
        self.assertIn("CARGO_TARGET_DIR", text)

    def test_ci_docs_name_runners_secrets_and_exits(self):
        text = DOC.read_text()
        self.assertIn("ubuntu-latest", text)
        self.assertIn("no secrets", text.lower())
        self.assertIn("ci_local.sh", text)
        self.assertIn("scopebase-select", text)

    def test_impact_map_is_reviewable(self):
        impact = json.loads(IMPACT.read_text())
        for key in (
            "schema_version",
            "requested_profiles",
            "path_rules",
            "default_change",
            "fast_gates",
            "profile_gates",
            "cell_bindings",
        ):
            self.assertIn(key, impact)
        self.assertTrue(impact["requested_profiles"])
        self.assertTrue(impact["fast_gates"])

    def test_local_execution_log_recorded(self):
        text = LOG.read_text()
        for marker in (
            "TT08 tail local execution",
            "select_affected agreement: ok",
            "accounting status=",
            "gate verdict=",
            "fast gates:",
        ):
            self.assertIn(marker, text, f"execution log must record {marker!r}")


if __name__ == "__main__":
    unittest.main()
