# SPDX-License-Identifier: Apache-2.0
"""Exact accepted common.py excerpts for the standalone fixture-access check.

See process-provenance.json. No repository path/import is needed at runtime.
"""
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time

MAX_LOG = 4 * 1024 * 1024


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def run(argv, cwd, env, logs, timeout=600):
    """Capture bounded logs and retain launch/retirement facts on I/O errors."""
    logs = Path(logs); logs.parent.mkdir(parents=True, exist_ok=True)
    paths = {n: logs.with_suffix('.' + n) for n in ('stdout','stderr')}
    start=time.monotonic(); reason=None; errors=[]; outputs={}; proc=None; select=None
    counts={n:0 for n in paths}; code=None; retired=False; resources_closed=True
    def error(stage, exception):
        nonlocal reason
        errors.append({'stage':stage,'exception':type(exception).__name__,
                       'message':str(exception)[:512],'errno':getattr(exception,'errno',None)})
        if reason is None: reason='INTERRUPTED' if isinstance(exception,KeyboardInterrupt) else 'INTERNAL_ERROR'
    def kill():
        try: os.killpg(proc.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        except BaseException as exception: error('group-kill',exception)
    try:
        for name,path in paths.items(): outputs[name]=path.open('xb')
        proc=subprocess.Popen([str(v) for v in argv],cwd=cwd,env=env,stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        select=selectors.DefaultSelector()
        for name in paths:
            stream=getattr(proc,name); os.set_blocking(stream.fileno(),False)
            select.register(stream,selectors.EVENT_READ,name)
        deadline=start+timeout
        while select.get_map():
            if time.monotonic()>=deadline:
                reason='TIMEOUT'; break
            for key,_ in select.select(min(.1,max(0,deadline-time.monotonic()))):
                data=os.read(key.fileobj.fileno(),65536)
                if not data:
                    select.unregister(key.fileobj); key.fileobj.close(); continue
                name=key.data; remaining=MAX_LOG-counts[name]; chunk=data[:remaining]
                written=outputs[name].write(chunk)
                if written!=len(chunk): raise OSError('short log write')
                counts[name]+=written
                if len(data)>remaining:
                    reason='LOG_BOUND'; break
            if reason: break
    except BaseException as exception:
        # Before launch there is no child custody to invent. Close any newly
        # opened files below, and propagate the original setup failure.
        if proc is None: raise
        error('collect',exception)
    finally:
        if proc is not None:
            if reason: kill()
            try: code=proc.wait(timeout=2)
            except BaseException as exception:
                error('wait',exception); kill()
                try: code=proc.wait(timeout=2)
                except BaseException as retry: error('wait-after-kill',retry)
            # Reaping the direct child cannot certify surviving descendants.
            try: os.killpg(proc.pid,0)
            except ProcessLookupError: retired=code is not None
            except BaseException as exception:
                error('group-check',exception); kill()
            else: kill()
            if code is None: code=proc.returncode
        if select is not None:
            try: select.close()
            except BaseException as exception:
                error('selector-close',exception); resources_closed=False
        if proc is not None:
            for stream in (proc.stdout,proc.stderr):
                try:
                    if stream and not stream.closed: stream.close()
                except BaseException as exception:
                    error('pipe-close',exception); resources_closed=False
        for stream in outputs.values():
            try: stream.close()
            except BaseException as exception:
                error('log-close',exception); resources_closed=False
    captured={}
    for name,path in paths.items():
        entry={'path':str(path),'sha256':None,'bytes':None}
        try: entry['bytes']=path.stat().st_size
        except BaseException as exception: error('log-stat-'+name,exception)
        try: entry['sha256']=sha(path)
        except BaseException as exception: error('log-hash-'+name,exception)
        captured[name]=entry
    return {'exit_code':code,'reason_code':reason,
            'cleanup':'complete' if retired and resources_closed else 'unresolved',
            'duration_ms':round((time.monotonic()-start)*1000),'command':[str(a) for a in argv],
            'cwd':str(cwd),'process_group':proc.pid,'logs':captured,'errors':errors}


def stdout(result):
    return Path(result['logs']['stdout']['path']).read_text(errors='replace')


def rust_refusal(output, code, contains, source_root=None, *, expected_primary=None):
    """Match a compiler diagnostic, optionally at an exact owned source line.

    Without an expected location, retain PP09's legacy source-text check.
    This predicate does not validate command retirement, lock or cleanup facts;
    callers must retain those checks through Execution/accept_refusal.
    """
    root = Path(source_root).resolve() if source_root is not None else None
    expected_file = None
    expected_line = None
    if expected_primary is not None:
        if root is None or not isinstance(expected_primary, tuple) or len(expected_primary) != 2:
            return False
        name, expected_line = expected_primary
        if not isinstance(name, str) or type(expected_line) is not int or expected_line <= 0:
            return False
        path = Path(name)
        if path.is_absolute() or not name or '\x00' in name or '..' in path.parts:
            return False
        expected_file = (root / path).resolve()
        if not expected_file.is_relative_to(root) or not expected_file.is_file():
            return False
        try:
            if expected_line > len(expected_file.read_text().splitlines()):
                return False
        except (OSError, UnicodeError):
            return False
    for line in output.splitlines():
        try:
            obj = json.loads(line)
            msg = obj.get('message', {})
            spans = msg.get('spans', [])
            if (obj.get('reason') != 'compiler-message' or (msg.get('code') or {}).get('code') != code
                    or contains not in msg.get('message', '')):
                continue
            for span in spans:
                if not span.get('is_primary') or not span.get('file_name', '').endswith('.rs'):
                    continue
                if root is None:
                    return True
                file = Path(span['file_name'])
                if not file.is_absolute():
                    file = root / file
                file = file.resolve()
                if not file.is_relative_to(root) or not file.is_file():
                    continue
                number = span.get('line_start', 0)
                if type(number) is not int or number <= 0:
                    continue
                if expected_file is not None:
                    if file == expected_file and number == expected_line:
                        return True
                else:
                    lines = file.read_text().splitlines()
                    if number <= len(lines) and contains in lines[number-1]:
                        return True
        except (ValueError, TypeError, AttributeError, OSError, UnicodeError):
            continue
    return False
