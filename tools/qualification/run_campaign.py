#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TT06 campaign runner: bounded fault/property/model/fuzz/sanitizer execution.

Manifest names target, seed/corpus, version, limits, domain contract and artifact.
run_campaign(manifest_path, campaign_id, output_root, root=None) -> CampaignResult.

Verdicts distinguish exhausted finite search (EXHAUSTED), time-bounded
exploration (TIME_BOUNDED), target crash (CRASH) and unmet prerequisites
(PREREQUISITE_UNMET), plus FAILED (semantic assertion failed after valid setup),
SETUP_ERROR (setup failed: never satisfies an expected FAILED bad control),
BOUND_EXCEEDED (deterministic work bound overrun) and INVALID_MANIFEST.

A campaign matches only when the observed verdict equals the declared
expected_verdict. Matching a bad-control campaign requires setup_ok plus a
failed semantic assertion; crashes and setup errors do not match FAILED.

Memory bounds are declared and observed (peak child RSS, sampled max) but not
enforced; an overrun is recorded as observed.memory_overrun without changing
the deterministic verdict. Cgroup-backed enforcement is future work.
Target commands receive {result} (partial/final result path) and {output}
(output root) substitutions and run without a shell. Each invocation uses a
unique result path bound to its own pid and uuid, and a timeout retires the
whole child process group before any result is accepted, so a surviving
late writer can never poison a later invocation's result.
Exit codes: 0 gate-pass (verdict matches expectation on a complete run),
1 executed but mismatched or incomplete, 2 manifest/usage error.
PREREQUISITE_UNMET is an incomplete diagnostic: it never gate-passes.
Sanitizer campaigns additionally require the bound `cargo +<toolchain> miri
run` target form; an unbound sanitizer target is refused without execution
and no Miri verdict is accepted from it.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

try:
    import resource

    def _peak_children_rss_bytes():
        # ru_maxrss is KiB on Linux; sampled maximum over waited-for children.
        return resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024
except ImportError:  # pragma: no cover - non-POSIX hosts
    def _peak_children_rss_bytes():
        return None

SCHEMA_VERSION = 1
VALID_KINDS = frozenset({'state-model', 'property', 'fuzz', 'fault-schedule', 'sanitizer'})
VALID_VERDICTS = frozenset({'EXHAUSTED', 'TIME_BOUNDED', 'CRASH', 'FAILED',
                             'SETUP_ERROR', 'PREREQUISITE_UNMET', 'BOUND_EXCEEDED'})
LIMIT_FIELDS = ('time_secs', 'max_work_items', 'max_memory_bytes')
CAMPAIGN_FIELDS = frozenset({'id', 'kind', 'target', 'seed', 'corpus', 'version',
                              'limits', 'domain_contract', 'artifact',
                              'expected_verdict', 'prerequisites'})
TARGET_FIELDS = frozenset({'argv', 'env'})
ID_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*\Z', re.ASCII)
MAX_MANIFEST_BYTES = 1048576
MAX_RESULT_BYTES = 1048576
# Bound for reaping a killed campaign process group: SIGKILLed members die
# in milliseconds, so anything still holding the pipes past this is treated
# as unretired custody and the result is refused, never awaited forever.
REAP_TIMEOUT_SECS = 30


class CampaignManifestError(ValueError):
    pass


def _fail(msg):
    raise CampaignManifestError(msg)


def _strict_id(value, what):
    if type(value) is not str or not ID_RE.fullmatch(value) or len(value) > 128:
        _fail(f'{what} must match [A-Za-z0-9._-] (<=128 chars)')


def _strict_text(value, what, max_bytes=4096, nonempty=True):
    if type(value) is not str or len(value.encode()) > max_bytes:
        _fail(f'{what} must be text (<= {max_bytes} bytes)')
    if nonempty and not value:
        _fail(f'{what} must be nonempty')


def _strict_bounds(limits):
    if type(limits) is not dict or set(limits) != set(LIMIT_FIELDS):
        _fail('limits must hold exactly time_secs, max_work_items, max_memory_bytes')
    for name in LIMIT_FIELDS:
        value = limits[name]
        if type(value) is bool or type(value) is not int or value <= 0:
            _fail(f'limits.{name} must be a positive integer')


def load_manifest(path):
    raw = Path(path).read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        _fail('manifest exceeds 1 MiB bound')
    try:
        data = json.loads(raw)
    except ValueError:
        _fail('manifest is not valid JSON')
    if type(data) is not dict or set(data) != {'schema_version', 'campaigns'}:
        _fail('manifest must hold exactly schema_version and campaigns')
    if data['schema_version'] != SCHEMA_VERSION:
        _fail(f'unsupported schema_version (want {SCHEMA_VERSION})')
    if type(data['campaigns']) is not list or not data['campaigns']:
        _fail('campaigns must be a nonempty list')
    seen = set()
    for entry in data['campaigns']:
        validate_campaign(entry)
        if entry['id'] in seen:
            _fail(f'duplicate campaign id {entry["id"]!r}')
        seen.add(entry['id'])
    return data


def validate_campaign(entry):
    if type(entry) is not dict or set(entry) - CAMPAIGN_FIELDS:
        _fail('campaign holds unknown fields')
    for required in ('id', 'kind', 'target', 'seed', 'version',
                     'limits', 'domain_contract', 'artifact', 'expected_verdict'):
        if required not in entry:
            _fail(f'campaign misses required field {required}')
    _strict_id(entry['id'], 'campaign id')
    if entry['kind'] not in VALID_KINDS:
        _fail(f'unknown campaign kind {entry["kind"]!r}')
    target = entry['target']
    if type(target) is not dict or set(target) - TARGET_FIELDS or 'argv' not in target:
        _fail('target must hold argv and optional env only')
    argv = target['argv']
    if type(argv) is not list or not argv or any(type(a) is not str or not a for a in argv):
        _fail('target.argv must be a nonempty string list')
    if 'env' in target and (type(target['env']) is not dict
                            or any(type(k) is not str or type(v) is not str
                                   for k, v in target['env'].items())):
        _fail('target.env must be a string map')
    if type(entry['seed']) is bool or type(entry['seed']) is not int or entry['seed'] < 0:
        _fail('seed must be a nonnegative integer')
    if 'corpus' in entry:
        _strict_text(entry['corpus'], 'corpus', nonempty=True)
    _strict_text(entry['version'], 'version')
    _strict_bounds(entry['limits'])
    _strict_text(entry['domain_contract'], 'domain_contract')
    _strict_text(entry['artifact'], 'artifact')
    if '/' in entry['artifact'] or entry['artifact'] in ('.', '..'):
        _fail('artifact must be a bare filename')
    if entry['expected_verdict'] not in VALID_VERDICTS:
        _fail(f'unknown expected_verdict {entry["expected_verdict"]!r}')
    prereqs = entry.get('prerequisites', [])
    if type(prereqs) is not list or any(type(p) is not str or not p for p in prereqs):
        _fail('prerequisites must be a string list')
    return entry


def get_campaign(manifest, campaign_id):
    for entry in manifest['campaigns']:
        if entry['id'] == campaign_id:
            return entry
    _fail(f'unknown campaign id {campaign_id!r}')


@dataclass
class CampaignResult:
    campaign_id: str
    kind: str
    target: dict
    seed: int
    version: str
    limits: dict
    expected_verdict: str
    verdict: str
    match: bool
    setup_ok: bool
    assertion: str
    work_items: int
    completed: bool
    observed: dict
    detail: str
    schema_version: int = SCHEMA_VERSION

    @property
    def qualifies(self):
        # Only an exhausted finite search matching its declaration qualifies
        # the declared finite claim; no verdict certifies universal support.
        return self.match and self.verdict == 'EXHAUSTED'

    @property
    def gate(self):
        # Command-gate status: 'pass' only for a matched complete run.
        # PREREQUISITE_UNMET is an incomplete diagnostic and never passes,
        # even when it matches its documented expectation. CUSTODY_UNCONFIRMED
        # is a runner-integrity failure and always fails the gate, whatever
        # any manifest declares (no manifest may expect it either).
        if self.verdict == 'PREREQUISITE_UNMET':
            return 'incomplete'
        if self.verdict == 'CUSTODY_UNCONFIRMED':
            return 'fail'
        return 'pass' if self.match else 'fail'

    def to_json(self):
        return {
            'schema_version': self.schema_version,
            'campaign_id': self.campaign_id,
            'kind': self.kind,
            'target': self.target,
            'seed': self.seed,
            'version': self.version,
            'limits': dict(self.limits),
            'expected_verdict': self.expected_verdict,
            'verdict': self.verdict,
            'match': self.match,
            'gate': self.gate,
            'qualifies': self.qualifies,
            'setup_ok': self.setup_ok,
            'assertion': self.assertion,
            'work_items': self.work_items,
            'completed': self.completed,
            'observed': dict(self.observed),
            'detail': self.detail,
        }


def _read_target_result(path):
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return None
    if len(raw) > MAX_RESULT_BYTES:
        return {'setup_ok': False, 'assertion': 'error', 'work_items': 0,
                'detail': 'target result exceeds 1 MiB bound'}
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if type(data) is not dict:
        return None
    setup_ok = data.get('setup_ok')
    assertion = data.get('assertion')
    work = data.get('work_items', 0)
    if type(setup_ok) is not bool or assertion not in ('pass', 'fail', 'error'):
        return None
    if type(work) is bool or type(work) is not int or work < 0:
        return None
    detail = data.get('detail', '')
    if type(detail) is not str:
        return None
    return {'setup_ok': setup_ok, 'assertion': assertion,
            'work_items': work, 'detail': detail[:2048]}


def _resolve_program(argv0, root):
    candidate = Path(argv0)
    if len(candidate.parts) > 1:
        absolute = candidate if candidate.is_absolute() else root / candidate
        if absolute.is_file() and os.access(absolute, os.X_OK):
            return str(absolute)
        return None
    found = shutil.which(argv0)
    if found:
        return found
    local = root / argv0
    if local.is_file() and os.access(local, os.X_OK):
        return str(local)
    return None


def _sanitizer_bound(argv):
    # A sanitizer campaign is bound only to the actual Miri driver form:
    # `cargo +<toolchain> miri run ...`. Anything else (in particular a plain
    # `cargo run`) is unbound: it must not execute as a Miri campaign and no
    # Miri verdict may be accepted from it.
    return (len(argv) >= 4
            and os.path.basename(argv[0]) == 'cargo'
            and argv[1].startswith('+') and len(argv[1]) > 1
            and argv[2] == 'miri' and argv[3] == 'run')


def run_campaign(manifest_path, campaign_id, output_root, root=None):
    manifest = load_manifest(manifest_path)
    entry = get_campaign(manifest, campaign_id)
    out_root = Path(output_root)
    out_root.mkdir(parents=True, exist_ok=True)
    repo_root = Path(root) if root is not None else Path(manifest_path).resolve().parent.parent
    limits = entry['limits']
    target = entry['target']
    # Invocation-bound result path: a late writer surviving from an earlier
    # invocation can never share this path, so it cannot poison this run.
    result_path = out_root / f'{campaign_id}.{os.getpid()}.{uuid.uuid4().hex}.partial.json'
    # Hygiene for pre-bound runners: their fixed path is never read here.
    try:
        (out_root / f'{campaign_id}.partial.json').unlink()
    except OSError:
        pass

    def finish(verdict, setup_ok=False, assertion='error', work_items=0,
               completed=False, observed=None, detail=''):
        observed = observed or {}
        result = CampaignResult(
            campaign_id=campaign_id, kind=entry['kind'],
            target={'argv': list(target['argv']), 'env': dict(target.get('env', {}))},
            seed=entry['seed'], version=entry['version'],
            limits=dict(limits), expected_verdict=entry['expected_verdict'],
            verdict=verdict, match=verdict == entry['expected_verdict'],
            setup_ok=setup_ok, assertion=assertion, work_items=work_items,
            completed=completed, observed=observed, detail=detail[:2048])
        (out_root / f'{campaign_id}.json').write_text(
            json.dumps(result.to_json(), indent=1, sort_keys=True) + '\n')
        return result

    def discard_partial():
        # The invocation-bound partial served its purpose once folded into
        # the CampaignResult; remove it so output roots do not accumulate
        # per-invocation files. Best effort: the unique path is unreadable
        # by any other invocation either way.
        try:
            result_path.unlink()
        except OSError:
            pass

    if entry['kind'] == 'sanitizer' and not _sanitizer_bound(target['argv']):
        return finish('PREREQUISITE_UNMET', observed={'elapsed_secs': 0.0},
                      detail='sanitizer target is not a bound Miri command '
                             '(want: cargo +<toolchain> miri run ...); refusing '
                             'to run or accept a Miri verdict from it')
    for prereq in entry.get('prerequisites', []):
        if shutil.which(prereq) is None:
            return finish('PREREQUISITE_UNMET', observed={'elapsed_secs': 0.0},
                          detail=f'prerequisite not on PATH: {prereq}')
    argv = [a.replace('{result}', str(result_path)).replace('{output}', str(out_root))
            for a in target['argv']]
    program = _resolve_program(argv[0], repo_root)
    if program is None:
        return finish('PREREQUISITE_UNMET', observed={'elapsed_secs': 0.0},
                      detail=f'target program not found or not executable: {target["argv"][0]}')
    argv[0] = program
    env = dict(os.environ)
    env.update(target.get('env', {}))
    env['CAMPAIGN_RESULT_FILE'] = str(result_path)
    rss_before = _peak_children_rss_bytes()
    start = time.monotonic()
    # New session per invocation so a timeout can retire the whole child
    # process group (a `cargo run` grandchild included), not just the direct
    # child. POSIX-only; elsewhere the direct child is still killed.
    use_session = os.name == 'posix' and hasattr(os, 'killpg')
    proc = subprocess.Popen(argv, env=env, cwd=str(repo_root),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=use_session)
    try:
        _, stderr = proc.communicate(timeout=limits['time_secs'])
    except subprocess.TimeoutExpired:
        # Retire child-process custody before accepting any result: killing
        # only the direct child would leave grandchildren alive to write
        # into a later invocation. Retirement must be CONFIRMED before any
        # partial is read: a silent killpg failure plus an unbounded reap
        # could hang forever or, worse, gate-pass a TIME_BOUNDED result
        # while writers are still alive. Any doubt fails closed with a
        # gate-failing SETUP_ERROR and the partial discarded unread.
        retired = False
        stderr = ''
        if use_session:
            killed = False
            try:
                os.killpg(proc.pid, signal.SIGKILL)
                killed = True
            except ProcessLookupError:
                killed = True  # group already gone: nothing left to retire
            except (PermissionError, OSError):
                try:
                    proc.kill()  # best effort; grandchildren may survive
                except OSError:
                    pass
                killed = False
            # Bounded reap on every path: drains pipes and reaps the direct
            # child even when the kill itself failed, so no path leaves an
            # unreaped child behind. The fail-closed result below is kept
            # whenever retirement itself is unconfirmed.
            try:
                _, stderr = proc.communicate(timeout=REAP_TIMEOUT_SECS)
                reaped = True
            except subprocess.TimeoutExpired:
                reaped = False
            if killed and reaped:
                # Pipes drained: every group member that held them is
                # dead. Confirm the group itself is gone (signal 0);
                # a surviving group keeps the result refused. A brief
                # grace poll absorbs zombie-reaping lag: a SIGKILLed
                # member can linger as an unreaped zombie for
                # milliseconds after its pipes close, and zombies still
                # answer signal 0. Anything present past the grace is
                # treated as live custody, never assumed reaped.
                for _ in range(20):
                    try:
                        os.killpg(proc.pid, 0)
                    except ProcessLookupError:
                        retired = True
                        break
                    except (PermissionError, OSError):
                        retired = False
                        break
                    time.sleep(0.1)
        else:
            # POSIX-only group retirement; elsewhere the direct child is
            # still killed, with a bounded reap. A failed kill must not
            # skip the reap (which would leave pipes open and the child
            # unreaped): the reap runs regardless and retirement is
            # decided by what it observes. Grandchild survival past the
            # kill is a documented platform limit; invocation-bound
            # result paths still isolate this run's record.
            try:
                proc.kill()
            except OSError:
                pass
            try:
                _, stderr = proc.communicate(timeout=REAP_TIMEOUT_SECS)
            except subprocess.TimeoutExpired:
                retired = False
            else:
                retired = True
        if not retired:
            discard_partial()
            elapsed = time.monotonic() - start
            return finish('CUSTODY_UNCONFIRMED',
                          observed={'elapsed_secs': round(elapsed, 3),
                                    'exit_code': None},
                          detail='process-group retirement unconfirmed; '
                                 'partial result refused')
        elapsed = time.monotonic() - start
        partial = _read_target_result(result_path) or {}
        discard_partial()
        peak = _peak_children_rss_bytes()
        observed = {'elapsed_secs': round(elapsed, 3),
                    'peak_rss_bytes': peak,
                    'memory_overrun': peak is not None and peak > limits['max_memory_bytes'],
                    'exit_code': None}
        return finish('TIME_BOUNDED', setup_ok=bool(partial.get('setup_ok', False)),
                      assertion=partial.get('assertion', 'error'),
                      work_items=int(partial.get('work_items', 0)),
                      completed=False, observed=observed,
                      detail=partial.get('detail') or
                      f'time bound {limits["time_secs"]}s exhausted; exploration incomplete')
    elapsed = time.monotonic() - start
    peak = _peak_children_rss_bytes()
    if rss_before is not None and peak is not None:
        peak = max(peak - 0, peak)  # sampled max over waited children; never negative
    observed = {'elapsed_secs': round(elapsed, 3),
                'peak_rss_bytes': peak,
                'memory_overrun': peak is not None and peak > limits['max_memory_bytes'],
                'exit_code': proc.returncode}
    reported = _read_target_result(result_path)
    discard_partial()
    if reported is None:
        if proc.returncode != 0:
            return finish('CRASH', observed=observed,
                          detail=f'target exited {proc.returncode} without a result record; '
                                 f'stderr tail: {stderr[-512:]}')
        return finish('SETUP_ERROR', observed=observed,
                      detail='target exited 0 without writing a result record')
    setup_ok = reported['setup_ok']
    assertion = reported['assertion']
    work_items = reported['work_items']
    detail = reported['detail']
    if not setup_ok:
        return finish('SETUP_ERROR', setup_ok=False, assertion=assertion,
                      work_items=work_items, observed=observed,
                      detail=detail or 'target reported setup failure')
    if proc.returncode != 0:
        return finish('CRASH', setup_ok=True, assertion=assertion,
                      work_items=work_items, observed=observed,
                      detail=f'{detail or "target failed after valid setup"}; '
                             f'exit={proc.returncode} stderr tail: {stderr[-512:]}')
    if work_items > limits['max_work_items']:
        return finish('BOUND_EXCEEDED', setup_ok=True, assertion=assertion,
                      work_items=work_items, completed=False, observed=observed,
                      detail=f'work_items {work_items} exceeds max_work_items '
                             f'{limits["max_work_items"]}')
    if assertion == 'fail':
        return finish('FAILED', setup_ok=True, assertion='fail',
                      work_items=work_items, completed=False, observed=observed,
                      detail=detail or 'semantic assertion failed after valid setup')
    if assertion == 'error':
        return finish('SETUP_ERROR', setup_ok=True, assertion='error',
                      work_items=work_items, observed=observed,
                      detail=detail or 'target reported error after valid setup')
    if work_items >= limits['max_work_items']:
        return finish('EXHAUSTED', setup_ok=True, assertion='pass',
                      work_items=work_items, completed=True, observed=observed,
                      detail=detail or
                      f'finite search exhausted: {work_items} work items')
    return finish('TIME_BOUNDED', setup_ok=True, assertion='pass',
                  work_items=work_items, completed=False, observed=observed,
                  detail=detail or
                  f'exploration stopped below work bound ({work_items}/'
                  f'{limits["max_work_items"]}); scope recorded, not qualified')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Run one TT06 qualification campaign.')
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--campaign', required=True)
    parser.add_argument('--output-root', required=True)
    parser.add_argument('--root', default=None)
    args = parser.parse_args(argv)
    try:
        result = run_campaign(args.manifest, args.campaign, args.output_root, root=args.root)
    except CampaignManifestError as exc:
        print(f'campaign manifest error: {exc}', file=sys.stderr)
        return 2
    except OSError as exc:
        print(f'campaign io error: {exc}', file=sys.stderr)
        return 2
    print(json.dumps(result.to_json(), indent=1, sort_keys=True))
    return 0 if result.gate == 'pass' else 1


if __name__ == '__main__':
    sys.exit(main())
