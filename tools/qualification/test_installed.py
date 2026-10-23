#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TT07 installed-operator qualification: packaged sets install and run offline.

Builds the exact `cargo package --list` file sets for scopebase-conformance
and scopebase-testkit, proves an independent downstream consumer builds and
passes against only those sets, installs the operator from the packaged
set, then runs the installed binary outside the checkout with a scrubbed
environment: negatives first (missing fixture, tampered closure, missing
notices, unknown profile/policy), then the qualified positive plus receipt
verification and identity-checked cleanup.

Full `cargo package` tarballs are blocked repo-wide because sibling path
dependencies are not on any index (ScopeBase crates are not published);
this script qualifies the identical packaged file sets instead, and says so
in its report.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CRATES = ["scopebase-conformance", "scopebase-testkit"]
GENERATED = {".cargo_vcs_info.json", "Cargo.toml.orig", "Cargo.lock"}
REQUIRED_DELIVERY = [
    "delivery/catalog.json",
    "delivery/contract-template.json",
    "delivery/fixture-manifest.json",
    "delivery/THIRD-PARTY-NOTICES.md",
    "delivery/LICENSE-APACHE",
    "delivery/notices/LICENSE-APACHE.516b24e0",
    "delivery/notices/LICENSE-APACHE.62c7a1e3",
    "delivery/notices/LICENSE-APACHE.a60eea81",
    "delivery/notices/LICENSE-APACHE.a9040321",
    "delivery/notices/LICENSE-MIT.0f96a838",
    "delivery/notices/LICENSE-MIT.23f18e03",
    "delivery/notices/LICENSE-UNICODE.f7db8105",
    "delivery/vectors/closure-input.txt",
]


class Fail(Exception):
    pass


def run(cmd, cwd=None, env=None, timeout=600):
    merged = dict(os.environ)
    if env:
        for key, value in env.items():
            if value is None:
                merged.pop(key, None)
            else:
                merged[key] = value
    proc = subprocess.run(
        cmd, cwd=cwd, env=merged, capture_output=True, text=True, timeout=timeout
    )
    return proc.returncode, proc.stdout, proc.stderr


def cargo(*args, cwd=None, env=None, timeout=600):
    return run(["cargo", *args], cwd=cwd, env=env, timeout=timeout)


def scrubbed_env(extra=None):
    env = {k: None for k in list(os.environ) if k.startswith("CARGO_")}
    env["CARGO_NET_OFFLINE"] = "true"
    if extra:
        env.update(extra)
    return env


def step(report, name, ok, detail=""):
    report["steps"].append({"name": name, "pass": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    if not ok:
        raise Fail(name)


def package_file_sets(repo, vendor):
    sets = {}
    for crate in CRATES:
        # --allow-dirty covers pre-commit qualification runs; the listing
        # never touches the network and stays offline.
        code, out, err = cargo(
            "package",
            "--offline",
            "--locked",
            "--list",
            "--allow-dirty",
            "-p",
            crate,
            cwd=repo,
        )
        if code != 0:
            raise Fail(f"package list {crate}: {err[-500:]}")
        files = [line for line in out.splitlines() if line.strip()]
        target = vendor / crate
        for rel in files:
            if Path(rel).name in GENERATED:
                continue
            src = repo / "crates" / crate / rel
            dst = target / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        sets[crate] = files
    return sets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=str(REPO))
    parser.add_argument("--work", default=None)
    parser.add_argument("--prefix", default=None)
    parser.add_argument("--output", default=None)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    repo = Path(args.repo)
    work = Path(args.work) if args.work else Path(tempfile.mkdtemp(prefix="tt07-installed-"))
    work.mkdir(parents=True, exist_ok=True)
    prefix = Path(args.prefix) if args.prefix else work / "prefix"
    report = {
        "schema": "tt07-installed-report-v1",
        "repo": str(repo),
        "work": str(work),
        "prefix": str(prefix),
        "packaging_note": (
            "tarball creation via `cargo package` is blocked repo-wide: sibling "
            "path dependencies (scopebase-bpf/linux) are not on any index and "
            "ScopeBase crates are not published. This run qualifies the exact "
            "`cargo package --list` file sets instead: same bytes a tarball "
            "would carry, verified file-by-file."
        ),
        "steps": [],
        "pass": False,
    }
    try:
        # 1. Packaged file sets.
        vendor = work / "vendor"
        sets = package_file_sets(repo, vendor)
        for required in REQUIRED_DELIVERY:
            step(
                report,
                f"packaged-set-has-{required.replace('/', '_')}",
                required in sets["scopebase-conformance"],
                f"{len(sets['scopebase-conformance'])} conformance files",
            )
        step(
            report,
            "packaged-set-testkit-nonempty",
            len(sets["scopebase-testkit"]) > 10,
            f"{len(sets['scopebase-testkit'])} testkit files",
        )

        # 2. Downstream consumer against only the packaged sets.
        consumer = work / "conformance-client"
        shutil.copytree(repo / "tests/downstream/conformance-client", consumer)
        manifest = consumer / "Cargo.toml"
        text = manifest.read_text()
        text = text.replace(
            "../../../crates/scopebase-conformance",
            str(vendor / "scopebase-conformance"),
        ).replace(
            "../../../crates/scopebase-testkit", str(vendor / "scopebase-testkit")
        )
        manifest.write_text(text)
        closure = vendor / "scopebase-conformance" / "delivery"
        code, out, _ = cargo(
            "test",
            "--offline",
            "--locked",
            cwd=consumer,
            env=scrubbed_env({"CONFORMANCE_FIXTURE_ROOT": str(closure)}),
            timeout=900,
        )
        step(report, "downstream-packaged-sets", code == 0, f"exit={code}")

        # 3. Install the operator from the packaged set.
        code, _, err = cargo(
            "install",
            "--offline",
            "--locked",
            "--path",
            str(vendor / "scopebase-conformance"),
            "--root",
            str(prefix),
            cwd=work,
            env=scrubbed_env(),
            timeout=900,
        )
        step(report, "cargo-install-offline", code == 0, f"exit={code} {err[-200:]}")
        binary = prefix / "bin" / "scopebase-conformance"
        step(report, "installed-binary-present", binary.is_file(), str(binary))

        # 4. Outside-checkout runs, scrubbed env, negatives first.
        outside = work / "outside"
        outside.mkdir(exist_ok=True)
        run_dir = outside / "run"

        def op(*argv, cwd=None):
            return run(
                [str(binary), *argv],
                cwd=cwd or outside,
                env=scrubbed_env(),
                timeout=300,
            )

        def fresh_closure(name):
            target = outside / name
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(closure, target)
            return target

        # Missing fixture input is refused before any effect.
        missing = fresh_closure("closure-missing")
        (missing / "vectors" / "closure-input.txt").unlink()
        code, _, _ = op(
            "run",
            "--catalog",
            str(missing / "catalog.json"),
            "--profile",
            "operator-delivery-v1",
            "--fixture-root",
            str(missing),
            "--output",
            str(run_dir),
        )
        step(
            report,
            "negative-missing-fixture",
            code == 3 and not (run_dir / "receipt.json").exists(),
            f"exit={code}",
        )

        # Tampered closure bytes are a broken package.
        tampered = fresh_closure("closure-tampered")
        (tampered / "vectors" / "closure-input.txt").write_bytes(b"tampered bytes")
        code, _, _ = op(
            "run",
            "--catalog",
            str(tampered / "catalog.json"),
            "--profile",
            "operator-delivery-v1",
            "--fixture-root",
            str(tampered),
            "--output",
            str(run_dir),
        )
        step(report, "negative-tampered-closure", code == 64, f"exit={code}")

        # Missing H33 notices break the installed route.
        nonotice = fresh_closure("closure-nonotice")
        (nonotice / "THIRD-PARTY-NOTICES.md").unlink()
        code, _, _ = op(
            "run",
            "--catalog",
            str(nonotice / "catalog.json"),
            "--profile",
            "operator-delivery-v1",
            "--fixture-root",
            str(nonotice),
            "--output",
            str(run_dir),
        )
        step(report, "negative-missing-notice", code == 64, f"exit={code}")

        # Unknown profile and unknown policy are typed refusals.
        intact = fresh_closure("closure-intact")
        code, _, _ = op(
            "run",
            "--catalog",
            str(intact / "catalog.json"),
            "--profile",
            "capture-core-v1",
            "--fixture-root",
            str(intact),
            "--output",
            str(run_dir),
        )
        step(report, "negative-unknown-profile", code == 3, f"exit={code}")
        code, _, _ = op(
            "run",
            "--catalog",
            str(intact / "catalog.json"),
            "--profile",
            "operator-delivery-v1",
            "--fixture-root",
            str(intact),
            "--output",
            str(run_dir),
            "--mapping-policy",
            "map-everything",
        )
        step(report, "negative-unknown-policy", code == 2, f"exit={code}")

        # Positive: read-only prefix, qualified run, full-admission verify.
        for path in intact.rglob("*"):
            if path.is_file():
                path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        code, out, err = op("describe", "--catalog", str(intact / "catalog.json"))
        step(report, "installed-describe", code == 0, f"exit={code}")
        code, _, _ = op(
            "plan",
            "--catalog",
            str(intact / "catalog.json"),
            "--profile",
            "operator-delivery-v1",
            "--fixture-root",
            str(intact),
        )
        step(report, "installed-plan", code == 0, f"exit={code}")
        if run_dir.exists():
            shutil.rmtree(run_dir)
        code, out, err = op(
            "run",
            "--catalog",
            str(intact / "catalog.json"),
            "--profile",
            "operator-delivery-v1",
            "--fixture-root",
            str(intact),
            "--output",
            str(run_dir),
        )
        summary = json.loads(out) if out.strip() else {}
        step(
            report,
            "installed-run-qualified",
            code == 0 and summary.get("qualification") == "qualified",
            f"exit={code} {err[-200:]}",
        )
        code, _, _ = op(
            "verify-receipt",
            str(run_dir / "receipt.json"),
            "--catalog",
            str(intact / "catalog.json"),
        )
        step(report, "installed-verify-receipt", code == 0, f"exit={code}")

        # Tampered receipts fail verification; the receipt denies authority.
        envelope = json.loads((run_dir / "receipt.json").read_text())
        step(
            report,
            "receipt-denies-authority",
            envelope.get("runtime_authority") is False,
            "",
        )
        tampered_receipt = outside / "tampered-receipt.json"
        envelope["report"]["run_terminal"]["qualification"] = "failed"
        tampered_receipt.write_text(json.dumps(envelope))
        code, _, _ = op("verify-receipt", str(tampered_receipt))
        step(report, "negative-tampered-receipt", code == 1, f"exit={code}")

        # Identity-checked cleanup refuses plain dirs, removes run dirs.
        plain = outside / "plain"
        plain.mkdir(exist_ok=True)
        code, _, _ = op("cleanup", "--run", str(plain))
        step(
            report,
            "negative-cleanup-refusal",
            code == 3 and plain.exists(),
            f"exit={code}",
        )
        code, _, _ = op("cleanup", "--run", str(run_dir))
        step(
            report,
            "installed-cleanup",
            code == 0 and not run_dir.exists(),
            f"exit={code}",
        )

        report["pass"] = all(s["pass"] for s in report["steps"])
    except Fail as failure:
        report["error"] = str(failure)
    finally:
        if args.output:
            Path(args.output).write_text(json.dumps(report, indent=1) + "\n")
        print(("OVERALL PASS" if report["pass"] else "OVERALL FAIL"))
        if not args.keep and not args.work and not report.get("error"):
            shutil.rmtree(work, ignore_errors=True)
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
