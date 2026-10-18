# SPDX-License-Identifier: Apache-2.0
"""Test-only structural check; requires Python 3.11+. Never invokes Cargo."""
import sys
if sys.version_info < (3, 11):
    sys.stderr.write("PACKAGE_BOUNDARY:INPUT\n")
    raise SystemExit(2)
import tomllib
from pathlib import Path

try:
    if len(sys.argv) != 2:
        raise ValueError()
    with Path(sys.argv[1]).open("rb") as stream:
        contents = stream.read(65_537)
    if len(contents) > 65_536:
        raise ValueError()
    manifest = tomllib.loads(contents.decode("utf-8"))
except (OSError, ValueError):
    sys.stderr.write("PACKAGE_BOUNDARY:INPUT\n")
    raise SystemExit(2)


def refuse(reason):
    sys.stderr.write("PACKAGE_BOUNDARY:" + reason + "\n")
    raise SystemExit(1)


# This is a package development-test assertion, not a dependency resolver or the
# repository's source/script/notice admission checker. Expected values are fixed
# by CP01, never learned from the manifest under test.
if any(key in manifest for key in ("workspace", "patch", "replace")):
    refuse("OVERRIDE")
package = manifest.get("package", {})
if not isinstance(package, dict):
    refuse("PACKAGE_METADATA")
if "links" in package or package.get("build") is not False or Path(sys.argv[1]).with_name("build.rs").exists():
    refuse("BUILD_INPUT")
expected_package = {
    "name": "scopebase-capture", "version": "0.1.0", "edition": "2021",
    "rust-version": "1.88.0", "license": "Apache-2.0", "publish": False,
    "readme": "README.md",
}
for key, value in expected_package.items():
    if type(package.get(key)) is not type(value) or package[key] != value:
        refuse("PACKAGE_METADATA")
if manifest.get("features") != {"default": [], "json": ["dep:serde", "dep:serde_json"]}:
    refuse("FEATURES")
expected_dependencies = {
    name: {"version": version, "default-features": False, "features": ["std"], "optional": True}
    for name, version in (("serde", "=1.0.229"), ("serde_json", "=1.0.151"))
}
# Strict bool identity also rejects TOML integer 0/1, which compare equal to
# Python bools but are not Cargo boolean dependency controls.
dependencies = manifest.get("dependencies")
if not isinstance(dependencies, dict) or dependencies.keys() != expected_dependencies.keys():
    refuse("DEPENDENCIES")
for name, expected in expected_dependencies.items():
    dependency = dependencies[name]
    if not isinstance(dependency, dict) or dependency != expected:
        refuse("DEPENDENCIES")
    if dependency.get("optional") is not True or dependency.get("default-features") is not False:
        refuse("DEPENDENCIES")
if manifest.get("build-dependencies"):
    refuse("BUILD_INPUT")
if manifest.get("dev-dependencies"):
    refuse("DEPENDENCIES")
targets = manifest.get("target", {})
if not isinstance(targets, dict):
    refuse("DEPENDENCIES")
for target in targets.values():
    if not isinstance(target, dict):
        refuse("DEPENDENCIES")
    if target.get("build-dependencies"):
        refuse("BUILD_INPUT")
    if target.get("dependencies") or target.get("dev-dependencies"):
        refuse("DEPENDENCIES")
