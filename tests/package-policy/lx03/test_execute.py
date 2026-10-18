# SPDX-License-Identifier: Apache-2.0
"""Exercise the real bounded adapter loop with owned deterministic command results."""
import contextlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

_spec = importlib.util.spec_from_file_location('lx03_execute', Path(__file__).with_name('execute.py'))
adapter = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adapter)


class CollectorAbortTests(unittest.TestCase):
    def collect(self, first):
        with tempfile.TemporaryDirectory(prefix='lx03-adapter-') as temp:
            root = Path(temp)/'source';root.mkdir()
            output = Path(temp)/'output'
            stderr = Path(temp)/'stderr';stderr.write_text('ordinary semantic mismatch')
            (root/'Cargo.lock').write_text('owned lock')
            calls=[];executions=[]
            matrix={'cargo_inputs':{},'members':[{'id':'scopebase-linux'},{'id':'scopebase-capture'}],
                    'toolchains':[{'id':'msrv','root':'/unused-compiler'}]}
            spec=[{'id':'negative','toolchain':'msrv','cwd':str(root),'argv':['test','--offline','--locked'],'failure':['intended semantic marker']},
                  {'id':'next','toolchain':'msrv','cwd':str(root),'argv':['test','--offline','--locked']}]
            class Execution:
                def __init__(self,*args,**kwargs):
                    self.by_id={};self.report={'rows':[]};self.aborted=None;executions.append(self)
                def reserve(self,ident,**kwargs):
                    row={'id':ident,'status':'NOT_RUN'};self.by_id[ident]=row;self.report['rows'].append(row)
                def step(self,ident,action):
                    row=self.by_id[ident]
                    try:
                        value=action(row);row['status']='PASS';return value
                    except adapter.p.PolicyError as error:
                        row.update(status='FAIL',reason_code=error.code,invalid_result=error.detail);raise
                def attach(self,row,result):row['attached_result']=result
                def write(self,path):path.write_text(json.dumps(self.report));return 1
                def abort(self,error,path):self.aborted=error.code;self.report['abort']=error.code;return self.write(path)
                def finish(self,path):return self.write(path)
            def command(argv,cwd,env,logs):
                calls.append(Path(logs).name)
                return {**({'reason_code':None,'cleanup':'complete','exit_code':0} if len(calls)>1 else first),
                        'logs':{'stderr':{'path':str(stderr)}}}
            def read_json(path):return spec if Path(path).name=='spec.json' else matrix
            with contextlib.ExitStack() as stack:
                for name,value in {'Execution':Execution,'read_json':read_json,'stage_inputs':lambda *args:{'staged_inputs':[]},
                    'clean_env':lambda *args:{},'tree_digest':lambda *args:'tree','sha':lambda *args:'sha',
                    'run':command,'stdout':lambda result:'ordinary semantic mismatch'}.items():
                    stack.enter_context(patch.object(adapter.p,name,value))
                stack.enter_context(patch.object(adapter.sys,'argv',['execute.py','--root',str(root),'--output',str(output),'--mode','controls','--spec',str(root/'spec.json')]))
                adapter.main()
            receipt=json.loads((output/'report.json').read_text())
            return calls,executions[0].aborted,receipt

    def test_invalid_command_stops_before_next_control_and_retains_abort(self):
        for result in [
            {'reason_code':'INTERRUPTED','cleanup':'complete','exit_code':-2},
            {'reason_code':'TIMEOUT','cleanup':'complete','exit_code':-9},
            {'reason_code':None,'cleanup':'unresolved','exit_code':101},
            {'reason_code':'CLEANUP_UNRESOLVED','cleanup':'unresolved','exit_code':101},
            {'reason_code':None,'cleanup':'complete','exit_code':None},
            {'reason_code':None,'cleanup':'complete','exit_code':0},
        ]:
            with self.subTest(result=result):
                calls,abort,receipt=self.collect(result)
                self.assertEqual(calls,['negative'],'invalid execution must never start next control')
                self.assertEqual(abort,'EXPECTED_FAILURE_NOT_REACHED')
                self.assertEqual(receipt['rows'][0]['invalid_result'],{**result,'logs':receipt['rows'][0]['invalid_result']['logs']})
                self.assertEqual(receipt['rows'][1]['status'],'NOT_RUN')
                self.assertEqual(receipt['abort'],abort)

    def test_ordinary_semantic_mismatch_keeps_failure_and_runs_continuation_twin(self):
        calls,abort,receipt=self.collect({'reason_code':None,'cleanup':'complete','exit_code':101})
        self.assertEqual(calls,['negative','next'])
        self.assertIsNone(abort)
        self.assertEqual(receipt['rows'][0]['reason_code'],'WRONG_RED')
        self.assertEqual(receipt['rows'][0]['status'],'FAIL','semantic mismatch must never become PASS')
        self.assertEqual(receipt['rows'][1]['status'],'PASS')


if __name__=='__main__':unittest.main()
