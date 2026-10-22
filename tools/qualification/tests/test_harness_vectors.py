# SPDX-License-Identifier: Apache-2.0
import importlib.util,pathlib,unittest,tempfile,shutil
spec=importlib.util.spec_from_file_location('harness_vectors',pathlib.Path(__file__).parents[1]/'check_harness_vectors.py')
m=importlib.util.module_from_spec(spec)
class VectorTests(unittest.TestCase):
 def test_independent_literals(self):
  spec.loader.exec_module(m)
  root=pathlib.Path(__file__).parents[3]/'crates/scopebase-testkit/tests/fixtures/harness'
  self.assertEqual(m.check(root)['sum'],'5')
 def test_wrong_value_control_and_restored(self):
  spec.loader.exec_module(m)
  root=pathlib.Path(__file__).parents[3]/'crates/scopebase-testkit/tests/fixtures/harness'
  with tempfile.TemporaryDirectory() as d:
   shutil.copytree(root,pathlib.Path(d)/'h');p=pathlib.Path(d)/'h'
   (p/'operands.bytes').write_bytes(b'2\n4\n')
   with self.assertRaises(ValueError):m.check(p)
   (p/'operands.bytes').write_bytes(b'2\n3\n');self.assertEqual(m.check(p)['sum'],'5')
