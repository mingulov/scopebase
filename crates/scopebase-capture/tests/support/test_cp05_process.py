#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owned tiny-child failure checks. Run with --output-dir ABS_NEW_OUTPUT.

Records/logs remain in the caller's fresh output. No compiler or library test
result is inferred from these harness checks. Controller runs use one outer
lease; these tests never acquire an inner lease.
"""
from __future__ import annotations
import argparse
import contextlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
import check_cp05_controls as helper
import cp05_bounded_process as accepted_process

OUTPUT = None
RECORDS = []


class Custody(unittest.TestCase):
    def invoke(self, fault=None, *, unreserved=False, payload=None, timeout=2):
        root=OUTPUT/self.id().rsplit('.',1)[-1];root.mkdir()
        stem=root/'child';record={};checkpoints=[];children=[];fired=[]
        entry=dict(case=self.id(),fault=fault,reserved=not unreserved,record=record,
                   checkpoints=checkpoints,owned_children=[],harness_cleanup=[])
        RECORDS.append(entry)
        def checkpoint():
            checkpoints.append(json.loads(json.dumps(record)))
            (root/'record.json').write_text(json.dumps(entry,indent=2)+'\n')
        process=getattr(helper,'process',accepted_process)
        real_popen=subprocess.Popen;real_read=os.read;real_killpg=os.killpg
        real_open=Path.open;real_sha=process.sha;real_digest=helper.digest
        real_wait=subprocess.Popen.wait
        def launch(*args,**kwargs):
            child=real_popen(*args,**kwargs);children.append(child);entry['owned_children'].append(child.pid);return child
        def read(fd,size):
            if children and fd in (children[0].stdout.fileno(),children[0].stderr.fileno()):
                fired.append('read');raise OSError('CP05 owned collection read fault')
            return real_read(fd,size)
        class Log:
            def __init__(self,stream):self.stream=stream
            def __getattr__(self,name):return getattr(self.stream,name)
            def write(self,data):
                if fault=='write':
                    self.stream.write(data[:3]);fired.append('write');raise OSError('CP05 owned log write fault')
                return self.stream.write(data)
            def close(self):
                self.stream.close()
                if fault=='close':fired.append('close');raise OSError('CP05 owned log close fault')
        def open_log(path,mode='r',*args,**kwargs):
            stream=real_open(path,mode,*args,**kwargs)
            return Log(stream) if mode=='xb' and path.suffix=='.stdout' else stream
        def hash_fault(path):
            if Path(path).suffix=='.stdout':fired.append('hash');raise OSError('CP05 owned log hash fault')
            return real_sha(path)
        def old_hash_fault(path):
            if Path(path).suffix=='.stdout':fired.append('hash');raise OSError('CP05 owned log hash fault')
            return real_digest(path)
        def wait(child,*args,**kwargs):
            if not fired:fired.append('wait');raise OSError('CP05 owned wait fault')
            return real_wait(child,*args,**kwargs)
        def group(group,sig):
            if sig==0:fired.append('group-check');raise OSError('CP05 owned group observation fault')
            return real_killpg(group,sig)
        if fault=='lease':stem.with_suffix('.lease.json').write_text('{bad JSON')
        argv=[sys.executable,'-c',payload or 'import time; print("CP05 owned child",flush=True); time.sleep(.02)']
        if fault=='setup':argv=[str(root/'missing-executable')]
        try:
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(process.subprocess,'Popen',side_effect=launch))
                if fault=='selector':stack.enter_context(patch.object(process.selectors.DefaultSelector,'select',side_effect=OSError('CP05 owned selector fault')))
                if fault=='read':stack.enter_context(patch.object(process.os,'read',side_effect=read))
                if fault in ('write','close'):stack.enter_context(patch.object(Path,'open',open_log))
                if fault=='hash':
                    stack.enter_context(patch.object(process,'sha',side_effect=hash_fault))
                    stack.enter_context(patch.object(helper,'digest',side_effect=old_hash_fault))
                if fault=='wait':stack.enter_context(patch.object(real_popen,'wait',wait))
                if fault=='group':stack.enter_context(patch.object(process.os,'killpg',side_effect=group))
                if unreserved:
                    result=helper.execute(argv,root,dict(PATH='/usr/bin:/bin'),stem,None)
                else:
                    result=helper.execute(argv,root,dict(PATH='/usr/bin:/bin'),stem,None,
                                          record=record,checkpoint=checkpoint,timeout=timeout)
                entry['returned']=True;entry['result']=result
            if not unreserved:
                self.assertIs(result,record)
                self.assertIsNone(checkpoints[0]['process_group'])
                self.assertEqual(checkpoints[0]['cleanup'],'not_started')
            self.assertEqual(helper.process_complete(result),fault is None and payload is None,
                             'fault/refusal cannot qualify as a completed semantic command')
            if fault=='setup':
                self.assertIsNone(result['process_group']);self.assertEqual(result['cleanup'],'not_started')
                self.assertEqual(result['reason_code'],'SETUP_FAILURE')
            else:
                self.assertEqual(result['process_group'],children[0].pid)
                self.assertIsNotNone(result['exit_code'])
                self.assertIn('stdout',result['logs']);self.assertIn('stderr',result['logs'])
            return result,fired,checkpoints
        except BaseException as exc:
            entry['exception']=dict(type=type(exc).__name__,message=str(exc));raise
        finally:
            for child in children:
                if child.poll() is None:
                    try:real_killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    child.wait(timeout=2)
                retired=False;deadline=time.monotonic()+2
                while time.monotonic()<deadline:
                    try:real_killpg(child.pid,0)
                    except ProcessLookupError:retired=True;break
                    try:real_killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    time.sleep(.01)
                entry['harness_cleanup'].append(dict(pid=child.pid,reaped=child.poll() is not None,group_retired=retired))
                self.assertTrue(retired,'owned test group cleanup remains unresolved')
            checkpoint()

    def test_hash_error_returns_pid_logs_and_primary_error(self):
        # This also reproduces the old collector's actual post-spawn loss:
        # hashing raised after child retirement, before a row could return.
        row,fired,_=self.invoke('hash',unreserved=True)
        self.assertIn('hash',fired);self.assertEqual(row['reason_code'],'INTERNAL_ERROR')
        self.assertEqual(row['cleanup'],'complete');self.assertIsNone(row['logs']['stdout']['sha256'])
        self.assertTrue(any(e['stage']=='log-hash-stdout' for e in row['errors']))

    def test_collection_error_preserves_reserved_child(self):
        row,fired,checkpoints=self.invoke('read')
        self.assertIn('read',fired);self.assertEqual(row['reason_code'],'INTERNAL_ERROR')
        self.assertEqual(row['cleanup'],'complete');self.assertTrue(any(e['stage']=='collect' for e in row['errors']))
        self.assertTrue(any(r['process_group']==row['process_group'] for r in checkpoints))

    def test_selector_failure_preserves_custody(self):
        row,_,_=self.invoke('selector');self.assertEqual(row['reason_code'],'INTERNAL_ERROR')
        self.assertEqual(row['cleanup'],'complete');self.assertTrue(row['errors'])

    def test_partial_log_write_preserves_primary_error(self):
        row,fired,_=self.invoke('write');self.assertIn('write',fired)
        self.assertEqual(row['reason_code'],'INTERNAL_ERROR');self.assertEqual(row['cleanup'],'complete')
        self.assertEqual(Path(row['stdout']).stat().st_size,3)

    def test_wait_error_is_retained_after_reaping(self):
        row,fired,_=self.invoke('wait');self.assertIn('wait',fired)
        self.assertEqual(row['reason_code'],'INTERNAL_ERROR');self.assertEqual(row['cleanup'],'complete')
        self.assertTrue(any(e['stage']=='wait' for e in row['errors']))

    def test_log_close_error_remains_unresolved(self):
        row,fired,_=self.invoke('close');self.assertIn('close',fired)
        self.assertEqual(row['reason_code'],'INTERNAL_ERROR');self.assertEqual(row['cleanup'],'unresolved')
        self.assertTrue(any(e['stage']=='log-close' for e in row['errors']))

    def test_group_observation_failure_remains_unresolved(self):
        row,fired,_=self.invoke('group');self.assertIn('group-check',fired)
        self.assertEqual(row['reason_code'],'INTERNAL_ERROR');self.assertEqual(row['cleanup'],'unresolved')
        self.assertTrue(any(e['stage']=='group-check' for e in row['errors']))

    def test_lease_parse_error_retains_completed_command(self):
        row,_,checkpoints=self.invoke('lease')
        self.assertEqual((row['exit_code'],row['cleanup']),(0,'complete'))
        self.assertEqual(row['reason_code'],'INTERNAL_ERROR')
        self.assertTrue(any(e['stage']=='lease-record' for e in row['errors']))
        self.assertTrue(any(r.get('process_group')==row['process_group'] and r.get('exit_code')==0 for r in checkpoints))

    def test_setup_failure_invents_no_child(self):
        row,_,_=self.invoke('setup');self.assertTrue(any(e['stage']=='setup' for e in row['errors']))

    def test_normal_child_has_complete_result(self):
        row,_,_=self.invoke();self.assertEqual((row['exit_code'],row['cleanup'],row['reason_code']),(0,'complete',None))
        self.assertIn('CP05 owned child',Path(row['stdout']).read_text())

    def test_timeout_retires_owned_child(self):
        row,_,_=self.invoke(payload='import time; time.sleep(2)',timeout=.05)
        self.assertEqual(row['reason_code'],'TIMEOUT');self.assertEqual(row['cleanup'],'complete')

    def test_log_bound_is_numeric_and_nonqualifying(self):
        bound=accepted_process.MAX_LOG
        row,_,_=self.invoke(payload=f'import os; os.write(1,b"x"*{bound+65536})')
        self.assertEqual(row['reason_code'],'LOG_BOUND');self.assertEqual(row['cleanup'],'complete')
        self.assertEqual(row['logs']['stdout']['bytes'],bound)


def main():
    global OUTPUT
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--case',help='One unittest method name for a focused repair check')
    args=parser.parse_args();OUTPUT=args.output_dir
    source=Path(__file__).resolve().parents[2]
    if not OUTPUT.is_absolute() or '..' in OUTPUT.parts or OUTPUT.exists() or not helper.no_symlinks(OUTPUT) or OUTPUT.resolve().is_relative_to(source):parser.error('fresh absolute output outside package required')
    OUTPUT.mkdir(parents=True,mode=0o700)
    suite=(unittest.TestLoader().loadTestsFromName(args.case,Custody) if args.case else unittest.TestLoader().loadTestsFromTestCase(Custody))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    (OUTPUT/'report.json').write_text(json.dumps(dict(status='PASS' if result.wasSuccessful() else 'FAIL',tests_run=result.testsRun,failures=len(result.failures),errors=len(result.errors),records=RECORDS),indent=2)+'\n')
    return 0 if result.wasSuccessful() else 1


if __name__=='__main__':sys.exit(main())
