# SPDX-License-Identifier: Apache-2.0
"""Delivered entrypoints must not create bytecode in an unpacked subject."""
import os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]/'crates/scopebase-bpf/tests/fixtures/bp02'
class SubjectImmutability(unittest.TestCase):
 def test_documented_helper_help_keeps_subject_unchanged(self):
  with tempfile.TemporaryDirectory(prefix='bp02-helper-')as out:
   root=Path(out)
   for name in ['run_mutants.py','run_live.py','run_consumers.py']:shutil.copyfile(ROOT/name,root/name)
   before={p.name:p.read_bytes()for p in root.iterdir()};env={k:v for k,v in os.environ.items()if k!='PYTHONDONTWRITEBYTECODE'}
   for name in ['run_mutants.py','run_live.py','run_consumers.py']:
    result=subprocess.run([sys.executable,root/name,'--help'],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);self.assertEqual(result.returncode,0,result.stdout)
   self.assertEqual({p.name:p.read_bytes()for p in root.iterdir()},before)
 def test_missing_entrypoint_policy_is_detected(self):
  with tempfile.TemporaryDirectory(prefix='bp02-helper-control-')as out:
   root=Path(out)
   for name in ['run_mutants.py','run_consumers.py']:shutil.copyfile(ROOT/name,root/name)
   script=root/'run_mutants.py';script.write_text(script.read_text().replace('sys.dont_write_bytecode = True',''))
   env={k:v for k,v in os.environ.items()if k!='PYTHONDONTWRITEBYTECODE'};r=subprocess.run([sys.executable,script,'--help'],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);self.assertEqual(r.returncode,0)
   self.assertTrue((root/'__pycache__').is_dir(),'known-bad local import must mutate subject and fail the unchanged-subject oracle')
if __name__=='__main__':unittest.main()
