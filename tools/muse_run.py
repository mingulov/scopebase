#!/usr/bin/env python3
"""Guarded supplementary Muse review with separate execution/review/acceptance.

Protocol: Muse Code 1.4.10 `exec --json`, run.terminal.completed payloads.
Only an explicit invocation runs a model. Fixed CLI flags retain the default
sandbox, but are not an OS security boundary or an attestation of plugins.
Effective provider tier remains unverified: requested Contributor mode and
ordinary model_completed events do not establish provider runtime attribution.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys


MAX_PROMPT_BYTES = 65536
MAX_TOOL_OUTPUT_BYTES = 65536


class UsageError(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise UsageError(message)


def open_directory(path):
    """Open an existing absolute directory, refusing symlink components."""
    if not path.is_absolute() or ".." in path.parts:
        raise UsageError("paths must be absolute without '..'")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def head(worktree):
    result = subprocess.run(["git", "-C", str(worktree), "rev-parse", "--verify", "HEAD^{commit}"],
                            text=True, capture_output=True, check=True)
    value = result.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value):
        raise UsageError("Git did not return a full commit object ID")
    return value


def source_status(worktree):
    """Observe tracked/untracked source without running filters/fsmonitor/hooks.

    Ignored private review inputs/outputs stay outside this cleanliness check.
    Optional Git index refresh writes are disabled for this read-only check.
    """
    configured = subprocess.run(
        ["git", "-C", str(worktree), "config", "--name-only", "--get-regexp", r"^filter\..*\.[^.]+$"],
        capture_output=True, text=True)
    if configured.returncode not in (0, 1):
        configured.check_returncode()
    # A clean/process filter can execute a shell command or canonicalize changed
    # source back to the indexed bytes. Disable each configured driver locally.
    overrides = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"]
    for driver in sorted({key.rsplit(".", 1)[0] for key in configured.stdout.splitlines()}):
        for field, value in (("clean", ""), ("smudge", ""), ("process", ""), ("required", "false")):
            overrides.extend(["-c", driver + "." + field + "=" + value])
    result = subprocess.run(
        ["git", "--no-optional-locks", *overrides,
         "-C", str(worktree), "status", "--porcelain=v1", "-z", "--untracked-files=all",
         "--ignore-submodules=none"], capture_output=True, check=True)
    return result.stdout


def json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def strict_json(text):
    def invalid(value):
        raise ValueError("invalid JSON constant: " + value)
    return json.loads(text, object_pairs_hook=json_object, parse_constant=invalid)


def validate_report(text, candidate):
    report = strict_json(text)
    if not isinstance(report, dict) or report.get("status") != "REVIEW_COMPLETE":
        raise ValueError("report must have status REVIEW_COMPLETE")
    if report.get("reviewed_commit") != candidate:
        raise ValueError("review report does not match the full candidate SHA")
    if not isinstance(report.get("summary"), str) or not report["summary"].strip():
        raise ValueError("review summary must be nonempty text")
    if not isinstance(report.get("findings"), list) or not isinstance(report.get("concerns"), list):
        raise ValueError("findings and concerns must be arrays")
    for finding in report["findings"]:
        if not isinstance(finding, dict) or finding.get("severity") not in (
                "critical", "important", "minor", "idea"):
            raise ValueError("finding has invalid severity")
        if not isinstance(finding.get("message"), str) or not finding["message"].strip():
            raise ValueError("finding message must be nonempty text")
    return report


def evidence(stream, candidate):
    errors, terminals = [], []
    stream.seek(0)
    for number, line in enumerate(stream, 1):
        if not line.strip():
            continue
        try:
            event = strict_json(line)
            if not isinstance(event, dict):
                raise ValueError("event must be an object")
            kind = event.get("payload_type")
            if not isinstance(kind, str):
                raise ValueError("event must have a payload_type")
            if kind.startswith("run.terminal."):
                terminals.append(event)
        except (ValueError, RecursionError) as error:
            errors.append("stream line " + str(number) + ": " + str(error))
    terminal, report, final_text = None, None, ""
    if len(terminals) != 1:
        errors.append("expected exactly one terminal event, found " + str(len(terminals)))
    else:
        terminal = terminals[0]
        payload = terminal.get("payload")
        if (terminal["payload_type"] != "run.terminal.completed" or not isinstance(payload, dict)
                or payload.get("terminal") != "completed"):
            errors.append("terminal event type and payload must both be completed")
        elif not isinstance(payload.get("text"), str) or not payload["text"].strip():
            errors.append("completed terminal text must be nonempty")
        elif (payload.get("kind") != "run_terminal" or not isinstance(payload.get("command_id"), str)
              or not payload["command_id"].strip() or not isinstance(payload.get("run_stream"), dict)
              or payload["run_stream"].get("kind") != "run"
              or not isinstance(payload["run_stream"].get("id"), str)
              or not payload["run_stream"]["id"].strip()):
            errors.append("terminal must identify its command and run stream")
        else:
            final_text = payload["text"]
            try:
                final_text.encode("utf-8")
                report = validate_report(final_text, candidate)
            except UnicodeError as error:
                errors.append("terminal text is not valid Unicode: " + str(error))
                # The original escaped payload stays in .jsonl and metadata.
                final_text = final_text.encode("utf-8", errors="backslashreplace").decode("utf-8")
            except (ValueError, RecursionError) as error:
                errors.append(str(error))
    return terminal, report, final_text, errors


class Artifacts:
    """Exclusive reservation plus dirfd-relative, private nonclobber files.

    Partial attempts are preserved if setup fails; a later attempt needs a new
    prefix. The .tmp directory is the reservation and the child's TMPDIR.
    """

    suffixes = (".jsonl", ".err", ".final.txt", ".execution.json")

    def __init__(self, prefix):
        self.parent_fd = open_directory(prefix.parent)
        self.files = {}
        self.tmp = str(prefix) + ".tmp"
        try:
            for suffix in (*self.suffixes, ".tmp"):
                try:
                    os.stat(prefix.name + suffix, dir_fd=self.parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise UsageError("artifact target already exists: " + str(prefix) + suffix)
            os.mkdir(prefix.name + ".tmp", 0o700, dir_fd=self.parent_fd)
            for suffix in self.suffixes:
                fd = os.open(prefix.name + suffix, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW,
                             0o600, dir_fd=self.parent_fd)
                self.files[suffix] = os.fdopen(fd, "w+", encoding="utf-8")
        except BaseException:
            self.close()
            raise

    def close(self):
        for stream in self.files.values():
            stream.close()
        os.close(self.parent_fd)


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument("worktree", type=Path)
    parser.add_argument("promptfile", type=Path)
    parser.add_argument("outprefix", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--max-steps", type=int, default=32)
    artifacts = None
    try:
        args = parser.parse_args(argv)
        if not 1 <= args.max_steps <= 32:
            raise UsageError("max-steps must be between 1 and 32")
        for path in (args.worktree, args.promptfile, args.outprefix):
            if not path.is_absolute() or ".." in path.parts:
                raise UsageError("WORKTREE, PROMPTFILE and OUTPREFIX must be absolute paths without '..'")
        worktree_fd = open_directory(args.worktree)
        os.close(worktree_fd)
        prompt_parent = open_directory(args.promptfile.parent)
        try:
            prompt_fd = os.open(args.promptfile.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                dir_fd=prompt_parent)
            with os.fdopen(prompt_fd, "rb") as prompt:
                if not stat.S_ISREG(os.fstat(prompt.fileno()).st_mode):
                    raise UsageError("prompt must be a regular file")
                prompt_bytes = prompt.read(MAX_PROMPT_BYTES + 1)
                if len(prompt_bytes) > MAX_PROMPT_BYTES:
                    raise UsageError("prompt exceeds the 65536-byte UTF-8 limit")
                if not prompt_bytes.decode("utf-8").strip():
                    raise UsageError("prompt must be nonempty UTF-8 text")
        finally:
            os.close(prompt_parent)
        before = head(args.worktree)
        top = subprocess.run(["git", "-C", str(args.worktree), "rev-parse", "--show-toplevel"],
                             text=True, capture_output=True, check=True).stdout.strip()
        if top != str(args.worktree):
            raise UsageError("WORKTREE must be the Git worktree root")
        if source_status(args.worktree):
            raise UsageError("WORKTREE must have clean tracked and nonignored untracked source")
        executable = shutil.which("muse")
        if executable is None:
            raise UsageError("Muse CLI is not on PATH")
        version = subprocess.run([executable, "--version"], text=True, capture_output=True, check=True).stdout.strip()
        command = [executable, "exec", "--json", "--provider", "meta", "--model", "muse-spark-1.3",
                   "--reasoning-effort", "max", "--contributor-mode", "on", "--workspace", str(args.worktree),
                   "--worktree", "off", "--disable-write", "--disable-shell", "--disable-web-tools",
                   "--disable-reminders", "--disable-request-user-input", "--approval-mode", "never",
                   "--trust-workspace", "--max-model-steps", str(args.max_steps),
                   "--max-tool-output-bytes", str(MAX_TOOL_OUTPUT_BYTES), "--prompt-file", str(args.promptfile)]
        artifacts = Artifacts(args.outprefix)
        record = {
            "schema_version": 1, "execution_state": "DRY_RUN" if args.dry_run else "RUNNING",
            "acceptance": "NOT_DECIDED", "argv": command, "cli_version": version,
            "requested": {"provider": "meta", "model": "muse-spark-1.3", "reasoning_effort": "max",
                          "contributor_mode": "on", "max_model_steps": args.max_steps,
                          "max_tool_output_bytes": MAX_TOOL_OUTPUT_BYTES},
            "effective_provider_tier": {"status": "unverified", "value": None,
                                        "reason": "No matching successful provider-runtime evidence verified"},
            "worktree": str(args.worktree), "promptfile": str(args.promptfile),
            "prompt_sha256": hashlib.sha256(prompt_bytes).hexdigest(),
            "tmpdir": artifacts.tmp, "before_head": before, "after_head": before,
            "source_clean_before": True, "source_clean_after": None,
            "raw_exit_status": None, "returned_exit_status": 0, "terminal": None,
            "report": None, "evidence_errors": [],
        }
        if not args.dry_run:
            try:
                child = subprocess.run(command, cwd=args.worktree,
                                       env=dict(os.environ, TMPDIR=artifacts.tmp),
                                       stdout=artifacts.files[".jsonl"], stderr=artifacts.files[".err"])
                record["raw_exit_status"] = child.returncode
                record["returned_exit_status"] = child.returncode if child.returncode >= 0 else 128 - child.returncode
            except OSError as error:
                record["returned_exit_status"] = 127
                record["evidence_errors"].append("Muse launch failed: " + str(error))
            try:
                record["after_head"] = head(args.worktree)
            except (OSError, subprocess.CalledProcessError, UsageError) as error:
                record["after_head"] = None
                record["evidence_errors"].append("Cannot read final HEAD: " + str(error))
            try:
                record["source_clean_after"] = not source_status(args.worktree)
                if not record["source_clean_after"]:
                    record["evidence_errors"].append("Tracked or nonignored untracked source changed during review")
            except (OSError, subprocess.CalledProcessError) as error:
                record["evidence_errors"].append("Cannot read final source status: " + str(error))
            try:
                terminal, report, final_text, errors = evidence(artifacts.files[".jsonl"], before)
            except UnicodeError as error:
                terminal, report, final_text, errors = None, None, "", ["invalid UTF-8 stream: " + str(error)]
            record["terminal"], record["report"] = terminal, report
            record["evidence_errors"].extend(errors)
            artifacts.files[".final.txt"].write(final_text)
            if record["after_head"] != before:
                record["evidence_errors"].append("HEAD changed during review")
            if record["returned_exit_status"]:
                record["execution_state"] = "PROCESS_FAILED"
            elif record["evidence_errors"]:
                record["execution_state"] = "INVALID_EVIDENCE"
                record["returned_exit_status"] = 3
            else:
                record["execution_state"] = "REVIEW_DELIVERED"
        json.dump(record, artifacts.files[".execution.json"], indent=2, ensure_ascii=True)
        artifacts.files[".execution.json"].write("\n")
        print(json.dumps({"execution_state": record["execution_state"],
                          "execution_record": str(args.outprefix) + ".execution.json",
                          "acceptance": "NOT_DECIDED"}))
        return record["returned_exit_status"]
    except (UsageError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print("muse-run: " + str(error), file=sys.stderr)
        return 64
    finally:
        if artifacts is not None:
            artifacts.close()


if __name__ == "__main__":
    sys.exit(main())
