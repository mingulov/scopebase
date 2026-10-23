# SPDX-License-Identifier: Apache-2.0
"""TT05 kernel-cell admission checks for tools/qualification/admit_object.py.

TDD: authored before the tool and observed failing (FileNotFoundError:
missing tools/qualification/kernel_common.py) prior to implementation.
"""
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HELPERS = Path(__file__).resolve().parent / "tt05_helpers.py"
hspec = importlib.util.spec_from_file_location("tt05_helpers", HELPERS)
h = importlib.util.module_from_spec(hspec)
sys.modules["tt05_helpers"] = h
hspec.loader.exec_module(h)

common = h.load("kernel_common", "tools/qualification/kernel_common.py")
admit = h.load("admit_object", "tools/qualification/admit_object.py")


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.obj = self.root / "demo.bpf.o"
        self.obj.write_bytes(h.build_elf())
        self.manifest = self.root / "manifest.json"
        self.manifest.write_bytes(h.manifest_bytes([h.object_entry(self.obj)]))
        self.profile = self.root / "profile.json"
        self.profile.write_bytes(h.profile_bytes())

    def tearDown(self):
        self.tmp.cleanup()

    def test_admit_valid_object(self):
        admission = admit.admit_object(str(self.manifest), str(self.obj), str(self.profile))
        expect = hashlib.sha256(self.obj.read_bytes()).hexdigest()
        self.assertEqual(admission["status"], "admitted")
        self.assertEqual(admission["object"]["sha256"], expect)
        self.assertEqual(admission["object"]["id"], "tt05-demo-object")
        self.assertEqual(admission["manifest_sha256"], hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        self.assertEqual(admission["object"]["license_observed"], "GPL")
        # Admission records identity only: no build/rebuild fields exist.
        flat = json.dumps(admission)
        for forbidden in ("build", "compile", "rebuild", "cc_argv", "clang"):
            self.assertNotIn(forbidden, flat)

    def test_loaded_bytes_match_admitted_object(self):
        admission = admit.admit_object(str(self.manifest), str(self.obj), str(self.profile))
        # Deliberately modified bytes no longer match the admitted digest.
        tampered = self.root / "tampered.bpf.o"
        blob = bytearray(self.obj.read_bytes())
        blob[64] ^= 0xFF
        tampered.write_bytes(bytes(blob))
        with self.assertRaises(common.KernelError) as ctx:
            admit.admit_object(str(self.manifest), str(tampered), str(self.profile))
        self.assertIn("uninventoried-object", str(ctx.exception))
        # The admitted digest still pins the original bytes exactly.
        self.assertEqual(
            admission["object"]["sha256"],
            hashlib.sha256(self.obj.read_bytes()).hexdigest(),
        )
        self.assertNotEqual(
            admission["object"]["sha256"],
            hashlib.sha256(tampered.read_bytes()).hexdigest(),
        )

    def test_modified_manifest_refuses(self):
        raw = bytearray(self.manifest.read_bytes())
        raw[-3] ^= 0x01
        bad = self.root / "bad-manifest.json"
        bad.write_bytes(bytes(raw))
        with self.assertRaises(common.KernelError):
            admit.admit_object(str(bad), str(self.obj), str(self.profile))

    def test_uninventoried_id_refuses(self):
        other = self.root / "other.bpf.o"
        other.write_bytes(h.build_elf(license_text=b"Apache-2.0"))
        with self.assertRaises(common.KernelError) as ctx:
            admit.admit_object(str(self.manifest), str(other), str(self.profile))
        self.assertIn("uninventoried-object", str(ctx.exception))

    def test_ambiguous_duplicate_hash_refuses(self):
        first = h.object_entry(self.obj, id="first-object")
        second = h.object_entry(self.obj, id="second-object")
        dup = self.root / "dup-manifest.json"
        dup.write_bytes(h.manifest_bytes([first, second]))
        with self.assertRaises(common.KernelError) as ctx:
            admit.admit_object(str(dup), str(self.obj), str(self.profile))
        self.assertIn("ambiguous-object", str(ctx.exception))

    def test_kind_contradiction_refuses(self):
        entry = h.object_entry(self.obj, kind="exec")
        wrong = self.root / "wrong-kind.json"
        wrong.write_bytes(h.manifest_bytes([entry]))
        with self.assertRaises(common.KernelError) as ctx:
            admit.admit_object(str(wrong), str(self.obj), str(self.profile))
        self.assertIn("kind-contradicts-object", str(ctx.exception))

    def test_exec_object_admits_with_exec_kind(self):
        obj = self.root / "exec.bpf.o"
        obj.write_bytes(h.build_elf(mutate="et-exec"))
        entry = h.object_entry(obj, kind="exec")
        manifest = self.root / "exec-manifest.json"
        manifest.write_bytes(h.manifest_bytes([entry]))
        admission = admit.admit_object(str(manifest), str(obj), str(self.profile))
        self.assertEqual(admission["object"]["kind"], "exec")

    def test_big_endian_parses(self):
        obj = self.root / "be.bpf.o"
        obj.write_bytes(h.build_elf(mutate="be-data"))
        entry = h.object_entry(obj)
        manifest = self.root / "be-manifest.json"
        manifest.write_bytes(h.manifest_bytes([entry]))
        admission = admit.admit_object(str(manifest), str(obj), str(self.profile))
        self.assertEqual(admission["object"]["license_observed"], "GPL")

    def test_non_elf_refuses(self):
        blob = self.root / "not-elf.o"
        blob.write_bytes(b"definitely not an ELF object file...." * 4)
        entry = h.object_entry(blob)
        manifest = self.root / "notelf-manifest.json"
        manifest.write_bytes(h.manifest_bytes([entry]))
        with self.assertRaises(common.KernelError) as ctx:
            admit.admit_object(str(manifest), str(blob), str(self.profile))
        self.assertIn("object-not-elf", str(ctx.exception))

    def test_wrong_machine_refuses(self):
        obj = self.root / "x86.o"
        obj.write_bytes(h.build_elf(mutate="x86-machine"))
        entry = h.object_entry(obj)
        manifest = self.root / "x86-manifest.json"
        manifest.write_bytes(h.manifest_bytes([entry]))
        with self.assertRaises(common.KernelError) as ctx:
            admit.admit_object(str(manifest), str(obj), str(self.profile))
        self.assertIn("object-not-bpf", str(ctx.exception))

    def test_declared_license_missing_from_object_refuses(self):
        obj = self.root / "nolic.o"
        obj.write_bytes(h.build_elf(mutate="no-license"))
        entry = h.object_entry(obj)
        manifest = self.root / "nolic-manifest.json"
        manifest.write_bytes(h.manifest_bytes([entry]))
        with self.assertRaises(common.KernelError) as ctx:
            admit.admit_object(str(manifest), str(obj), str(self.profile))
        self.assertIn("license", str(ctx.exception))

    def test_declared_license_mismatch_refuses(self):
        obj = self.root / "gpl.o"
        obj.write_bytes(h.build_elf(license_text=b"GPL"))
        entry = h.object_entry(obj, license_declared="Apache-2.0")
        manifest = self.root / "lic-mismatch.json"
        manifest.write_bytes(h.manifest_bytes([entry]))
        with self.assertRaises(common.KernelError) as ctx:
            admit.admit_object(str(manifest), str(obj), str(self.profile))
        self.assertIn("license", str(ctx.exception))

    def test_unlisted_license_refuses(self):
        obj = self.root / "prop.o"
        obj.write_bytes(h.build_elf(license_text=b"Proprietary"))
        entry = h.object_entry(obj, license_declared="Proprietary")
        manifest = self.root / "prop-manifest.json"
        manifest.write_bytes(h.manifest_bytes([entry]))
        with self.assertRaises(common.KernelError) as ctx:
            admit.admit_object(str(manifest), str(obj), str(self.profile))
        self.assertIn("license", str(ctx.exception))

    def test_profile_name_mismatch_refuses(self):
        profile = self.root / "other-profile.json"
        profile.write_bytes(h.profile_bytes(name="bpfel-v3"))
        with self.assertRaises(common.KernelError) as ctx:
            admit.admit_object(str(self.manifest), str(self.obj), str(profile))
        self.assertIn("profile-mismatch", str(ctx.exception))

    def test_unknown_manifest_field_refuses(self):
        doc = json.loads(self.manifest.read_text())
        doc["objects"][0]["surprise"] = 1
        bad = self.root / "unknown-field.json"
        bad.write_text(json.dumps(doc))
        with self.assertRaises(common.KernelError) as ctx:
            admit.admit_object(str(bad), str(self.obj), str(self.profile))
        self.assertIn("unknown-field", str(ctx.exception))

    def test_duplicate_manifest_field_refuses(self):
        raw = self.manifest.read_text().replace('"kind": "rel"', '"kind": "rel", "kind": "rel"', 1)
        dup = self.root / "dup-field.json"
        dup.write_text(raw)
        with self.assertRaises(common.KernelError) as ctx:
            admit.admit_object(str(dup), str(self.obj), str(self.profile))
        self.assertIn("duplicate-field", str(ctx.exception))

    def test_uppercase_sha_refuses(self):
        entry = h.object_entry(self.obj)
        entry["sha256"] = entry["sha256"].upper()
        bad = self.root / "upper-sha.json"
        bad.write_bytes(h.manifest_bytes([entry]))
        with self.assertRaises(common.KernelError) as ctx:
            admit.admit_object(str(bad), str(self.obj), str(self.profile))
        self.assertIn("sha256", str(ctx.exception))

    def test_symlinked_object_refuses(self):
        link = self.root / "link.o"
        link.symlink_to(self.obj)
        with self.assertRaises(common.KernelError) as ctx:
            admit.admit_object(str(self.manifest), str(link), str(self.profile))
        self.assertIn("symlink", str(ctx.exception))

    def test_cli_admits_and_refuses(self):
        out = self.root / "admission.json"
        tool = h.ROOT / "tools/qualification/admit_object.py"
        proc = subprocess.run(
            [sys.executable, str(tool), str(self.manifest), str(self.obj),
             str(self.profile), "--output", str(out)],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(out.read_text())["status"], "admitted")
        tampered = self.root / "tampered.bpf.o"
        blob = bytearray(self.obj.read_bytes())
        blob[70] ^= 0x01
        tampered.write_bytes(bytes(blob))
        out2 = self.root / "refused.json"
        proc = subprocess.run(
            [sys.executable, str(tool), str(self.manifest), str(tampered),
             str(self.profile), "--output", str(out2)],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("uninventoried-object", proc.stderr)
        self.assertFalse(out2.exists())


if __name__ == "__main__":
    unittest.main()
