# SPDX-License-Identifier: Apache-2.0
"""TT10 H33 executable license-boundary bindings.

The checker (tools/qualification/check_h33.py) and its independent oracle
(tools/qualification/h33_oracle.py) run the H33 source/object/notice text
checks that the TT08 gate set executes per cell. Bad-control vectors live in
tests/vectors/h33_*_bad.json; every mutant must fail its intended semantic
rule in BOTH implementations (agreement), while the real tree passes clean.
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CHECKER = ROOT / "tools" / "qualification" / "check_h33.py"
ORACLE = ROOT / "tools" / "qualification" / "h33_oracle.py"
VECTORS = ROOT / "tools" / "qualification" / "tests" / "vectors"
BUNDLE = ROOT / "crates" / "scopebase-conformance" / "delivery"


def run(program, *args, cwd=ROOT):
    proc = subprocess.run(
        [sys.executable, str(program), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=300,
    )
    return proc.returncode, proc.stdout, proc.stderr


def load_vectors(name):
    return json.loads((VECTORS / name).read_bytes())["cases"]


def write_tree(tmp, files):
    root = Path(tmp)
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8"))


CLOSURE_MINI = (
    '{"kind":"h33-source-closure-v1","own_grant":"Apache-2.0",'
    '"runtime_carriers":[],"schema_version":1,"third_party_inputs":[]}'
)
CARGO_MINI = (
    '[package]\nname = "foo"\nversion = "0.1.0"\nedition = "2021"\n'
    'license = "Apache-2.0"\n'
)
APACHE_MINI = "Apache License\nVersion 2.0\nvector placeholder\n"


class SourceClosureTests(unittest.TestCase):
    def test_positive_real_tree(self):
        code, out, err = run(CHECKER, "source-closure", "--root", ".")
        self.assertEqual(code, 0, f"checker failed on real tree: {err}")
        self.assertIn("PASS", out)

    def test_oracle_positive_real_tree(self):
        code, out, err = run(ORACLE, "source-closure", "--root", ".")
        self.assertEqual(code, 0, f"oracle failed on real tree: {err}")
        self.assertIn("PASS", out)

    def test_bad_controls_fail_intended_rule_in_both(self):
        for case in load_vectors("h33_source_bad.json"):
            with self.subTest(case=case["id"]):
                with tempfile.TemporaryDirectory() as tmp:
                    write_tree(tmp, case["files"])
                    code, _, err = run(
                        CHECKER, "source-closure", "--root", tmp
                    )
                    self.assertEqual(
                        code, 1, f"{case['id']}: checker passed a mutant"
                    )
                    self.assertIn(case["expect"], err)
                    ocode, _, oerr = run(
                        ORACLE, "source-closure", "--root", tmp
                    )
                    self.assertEqual(
                        ocode, 1, f"{case['id']}: oracle passed a mutant"
                    )
                    self.assertIn(case["expect"], oerr)

    def test_listed_third_party_grant_passes(self):
        # A non-own grant WITH a closure record is the documented path.
        files = {
            "crates/foo/Cargo.toml": CARGO_MINI,
            "crates/foo/LICENSE-APACHE": APACHE_MINI,
            "crates/foo/src/lib.rs": "// SPDX-License-Identifier: Apache-2.0\n",
            "crates/foo/src/gpl.rs": "// SPDX-License-Identifier: GPL-2.0-only\n",
        }
        import hashlib

        digest = hashlib.sha256(files["crates/foo/src/gpl.rs"].encode()).hexdigest()
        files["fixtures/h33/source-closure.json"] = json.dumps(
            {
                "schema_version": 1,
                "kind": "h33-source-closure-v1",
                "own_grant": "Apache-2.0",
                "third_party_inputs": [
                    {
                        "path": "crates/foo/src/gpl.rs",
                        "sha256": digest,
                        "grant": "GPL-2.0-only",
                        "role": "test",
                    }
                ],
                "runtime_carriers": [],
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, files)
            for program in (CHECKER, ORACLE):
                code, _, err = run(program, "source-closure", "--root", tmp)
                self.assertEqual(code, 0, f"{program.name}: {err}")

    def test_buried_spdx_literal_is_not_a_grant(self):
        # SPDX text past the header window (vectors, quotes) is not a grant.
        # The real tree proves this too: tools/planning/tests/test_traceability.py
        # embeds a GPL-3.0-or-later literal at line 34 and the positive passes.
        body = "".join(f"// filler {n}\n" for n in range(30))
        body += "// SPDX-License-Identifier: GPL-3.0-or-later\n"
        files = {
            "crates/foo/Cargo.toml": CARGO_MINI,
            "crates/foo/LICENSE-APACHE": APACHE_MINI,
            "crates/foo/src/lib.rs": "// SPDX-License-Identifier: Apache-2.0\n",
            "crates/foo/src/vectors.rs": body,
            "fixtures/h33/source-closure.json": CLOSURE_MINI,
        }
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, files)
            for program in (CHECKER, ORACLE):
                code, _, err = run(program, "source-closure", "--root", tmp)
                self.assertEqual(code, 0, f"{program.name}: {err}")


class ObjectLicenseTests(unittest.TestCase):
    def test_positive_real_tree(self):
        code, out, err = run(CHECKER, "final-object-license", "--root", ".")
        self.assertEqual(code, 0, f"checker failed on real tree: {err}")
        self.assertIn("PASS", out)

    def test_oracle_positive_real_tree(self):
        code, out, err = run(ORACLE, "final-object-license", "--root", ".")
        self.assertEqual(code, 0, f"oracle failed on real tree: {err}")
        self.assertIn("PASS", out)

    def test_bad_controls_fail_intended_rule_in_both(self):
        import hashlib

        lic_o = (ROOT / "fixtures/bpf/isa/objects/lic.o").read_bytes()
        base_o = (ROOT / "fixtures/bpf/isa/objects/base.o").read_bytes()
        lic_ll = (ROOT / "fixtures/bpf/isa/sources/lic.ll").read_bytes()
        expected = (ROOT / "fixtures/bpf/isa/expected.json").read_bytes()
        real_manifest = json.loads(
            (ROOT / "fixtures/h33/object-license.json").read_bytes()
        )
        for case in load_vectors("h33_object_bad.json"):
            with self.subTest(case=case["id"]):
                data = bytearray(lic_o if case["base"] == "lic.o" else base_o)
                if case["truncate"] is not None:
                    data = data[: case["truncate"]]
                if case["patch_find_hex"] is not None:
                    find = bytes.fromhex(case["patch_find_hex"])
                    idx = bytes(data).find(find)
                    self.assertNotEqual(
                        idx, -1, f"{case['id']}: patch anchor missing"
                    )
                    repl = bytes.fromhex(case["patch_replace_hex"])
                    data[idx : idx + len(find)] = repl
                manifest = json.loads(json.dumps(real_manifest))
                entry = manifest["objects"][0]
                entry["path"] = "obj.o"
                entry["source"] = "src.ll"
                entry["emitter_record"] = "expected.json"
                entry["source_sha256"] = hashlib.sha256(lic_ll).hexdigest()
                entry.update(case["manifest"])
                if case["repin"]:
                    entry["sha256"] = hashlib.sha256(bytes(data)).hexdigest()
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / "obj.o").write_bytes(bytes(data))
                    (root / "src.ll").write_bytes(lic_ll)
                    (root / "expected.json").write_bytes(expected)
                    (root / "manifest.json").write_text(json.dumps(manifest))
                    code, _, err = run(
                        CHECKER,
                        "final-object-license",
                        "--root",
                        tmp,
                        "--manifest",
                        "manifest.json",
                    )
                    self.assertEqual(
                        code, 1, f"{case['id']}: checker passed a mutant"
                    )
                    self.assertIn(case["expect"], err)
                    ocode, _, oerr = run(
                        ORACLE,
                        "final-object-license",
                        "--root",
                        tmp,
                        "--manifest",
                        "manifest.json",
                    )
                    self.assertEqual(
                        ocode, 1, f"{case['id']}: oracle passed a mutant"
                    )
                    self.assertIn(case["expect"], oerr)


class InstalledNoticesTests(unittest.TestCase):
    def test_positive_real_bundle(self):
        code, out, err = run(
            CHECKER, "installed-notices", "--bundle", str(BUNDLE)
        )
        self.assertEqual(code, 0, f"checker failed on real bundle: {err}")
        self.assertIn("PASS", out)

    def test_oracle_positive_real_bundle(self):
        code, out, err = run(
            ORACLE, "installed-notices", "--bundle", str(BUNDLE)
        )
        self.assertEqual(code, 0, f"oracle failed on real bundle: {err}")
        self.assertIn("PASS", out)

    def test_bad_controls_fail_intended_rule_in_both(self):
        import hashlib

        for case in load_vectors("h33_notices_bad.json"):
            with self.subTest(case=case["id"]):
                with tempfile.TemporaryDirectory() as tmp:
                    bundle = Path(tmp) / "bundle"
                    shutil.copytree(BUNDLE, bundle)
                    for rel in case["remove"]:
                        (bundle / rel).unlink()
                    for rel, content in case["add"].items():
                        target = bundle / rel
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_text(content)
                    if case.get("append_byte"):
                        target = bundle / case["append_byte"]
                        with target.open("ab") as stream:
                            stream.write(b"X")
                    if case.get("strip_marker"):
                        (bundle / case["strip_marker"]).write_bytes(
                            b"no license marker in these bytes\n"
                        )
                    manifest_path = bundle / "fixture-manifest.json"
                    manifest = json.loads(manifest_path.read_bytes())
                    if case.get("drop_pin"):
                        manifest["files"] = [
                            f
                            for f in manifest["files"]
                            if f["path"] != case["drop_pin"]
                        ]
                    for rel in (case.get("edit_manifest") or {}).get(
                        "pin_add", []
                    ):
                        data = (bundle / rel).read_bytes()
                        manifest["files"].append(
                            {
                                "path": rel,
                                "length": str(len(data)),
                                "sha256": hashlib.sha256(data).hexdigest(),
                            }
                        )
                    edit = case.get("edit_notices")
                    if edit:
                        notices_path = bundle / "THIRD-PARTY-NOTICES.md"
                        text = notices_path.read_text()
                        start = text.index("```json") + len("```json")
                        end = text.index("```", start)
                        entries = json.loads(text[start:end])
                        for entry in entries:
                            if entry["name"] == edit["name"]:
                                entry[edit["field"]] = edit["value"]
                        notices_path.write_text(
                            text[:start]
                            + json.dumps(entries)
                            + text[end:]
                        )
                    if case["repin_edited"]:
                        by_path = {f["path"]: f for f in manifest["files"]}
                        for rel in (
                            ["THIRD-PARTY-NOTICES.md"]
                            if edit
                            else [case["strip_marker"]]
                        ):
                            data = (bundle / rel).read_bytes()
                            by_path[rel]["length"] = str(len(data))
                            by_path[rel]["sha256"] = hashlib.sha256(
                                data
                            ).hexdigest()
                    manifest_path.write_text(json.dumps(manifest, indent=1))
                    code, _, err = run(
                        CHECKER,
                        "installed-notices",
                        "--bundle",
                        str(bundle),
                    )
                    self.assertEqual(
                        code, 1, f"{case['id']}: checker passed a mutant"
                    )
                    self.assertIn(case["expect"], err)
                    ocode, _, oerr = run(
                        ORACLE,
                        "installed-notices",
                        "--bundle",
                        str(bundle),
                    )
                    self.assertEqual(
                        ocode, 1, f"{case['id']}: oracle passed a mutant"
                    )
                    self.assertIn(case["expect"], oerr)


class CatalogBindingTests(unittest.TestCase):
    EXECUTABLE = {
        "H33.source-closure": "source-closure",
        "H33.final-object-license": "final-object-license",
        "H33.installed-notices": "installed-notices",
    }

    def test_registrations_pin_actual_bytes(self):
        import hashlib

        catalog = json.loads((ROOT / "profiles" / "cases-v1.json").read_bytes())
        by_id = {(c["id"], c["version"]): c for c in catalog["cases"]}
        for case_id, entrypoint in self.EXECUTABLE.items():
            with self.subTest(case=case_id):
                case = by_id[(case_id, 1)]
                self.assertEqual(
                    case["implementation_status"], "REGISTERED_EXECUTABLE"
                )
                reg = case["registration"]
                self.assertTrue(reg["oracle_basis"])
                self.assertTrue(reg["control_assertion"])
                seen = set()
                for name in (
                    "executable",
                    "fixture",
                    "oracle",
                    "bad_control",
                ):
                    artifact = reg[name]
                    digest = hashlib.sha256(
                        (ROOT / artifact["path"]).read_bytes()
                    ).hexdigest()
                    self.assertEqual(artifact["sha256"], digest, name)
                    seen.add(
                        (
                            artifact["path"],
                            artifact["sha256"],
                            artifact["entrypoint"],
                        )
                    )
                self.assertEqual(len(seen), 4)
                self.assertEqual(reg["executable"]["entrypoint"], entrypoint)
                self.assertEqual(reg["oracle"]["entrypoint"], entrypoint)

    def test_catalog_is_legal_evolution_of_frozen_envelope(self):
        # The live catalog must validate with byte-verified registrations and
        # differ from the frozen TT01 envelope only by revision + the three
        # H33 registration flips.
        frozen = (
            ROOT / "crates/scopebase-testkit/tests/fixtures/catalog/cases-v1.json"
        )
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/qualification/check_catalog.py"),
                str(ROOT / "profiles/cases-v1.json"),
                "--baseline",
                str(frozen),
                "--artifact-root",
                str(ROOT),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        summary = json.loads(proc.stdout)
        self.assertTrue(summary["structurally_valid"])
        self.assertTrue(summary["registrations_verified"])


class ImpactWiringTests(unittest.TestCase):
    def test_h33_cells_bound_or_exactly_skipped(self):
        impact = json.loads((ROOT / "profiles/impact-v1.json").read_bytes())
        bindings = impact["cell_bindings"]
        for cell, subcommand in (
            ("h33-source-closure", "source-closure"),
            ("h33-final-object-license", "final-object-license"),
            ("h33-installed-notices", "installed-notices"),
        ):
            with self.subTest(cell=cell):
                self.assertIn("argv", bindings[cell])
                argv = bindings[cell]["argv"]
                self.assertEqual(argv[0], "python3")
                self.assertIn("check_h33.py", argv[1])
                self.assertIn(subcommand, argv)
        reason = bindings["h33-license-admission"]["unavailable"]
        self.assertIn("TT05", reason)
        self.assertIn("NOT_RUN", reason)


if __name__ == "__main__":
    unittest.main()
