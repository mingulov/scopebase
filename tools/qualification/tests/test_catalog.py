# SPDX-License-Identifier: Apache-2.0
import copy,hashlib,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('catalog_checker',ROOT/'tools/qualification/check_catalog.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
FIX=ROOT/'crates/scopebase-testkit/tests/fixtures/catalog'
def read(name):return json.loads((FIX/(name+'.json')).read_bytes())
def check(v,**kw):return c.validate(json.dumps(v).encode(),**kw)
class CatalogTests(unittest.TestCase):
 def invalid(self,v,kind,**kw):
  with self.assertRaisesRegex(c.CatalogInvalid,kind):check(v,**kw)
 def test_literal_inventory_and_revision_acceptance(self):
  for name in ['cases-v1','revision-a','revision-b']:c.validate((FIX/(name+'.json')).read_bytes())
 def test_revision_controls(self):
  b=read('revision-b');v=copy.deepcopy(b);v['cases'].append(copy.deepcopy(v['cases'][0]));self.invalid(v,'DuplicateId')
  for revision,expected in [(0,'InvalidVersion'),(True,'InvalidVersion'),(1.0,'InvalidVersion'),(4294967296,'InvalidVersion'),(3,'UnknownReference')]:
   v=copy.deepcopy(b);v['profiles'][1]['required_cases'][0]['case_version']=revision;self.invalid(v,expected)
  check(b,limits={'max_cases':2});self.invalid(b,'LimitExceeded',limits={'max_cases':1})
 def test_strict_boundary(self):
  raw=(FIX/'revision-a.json').read_bytes()
  for mutated,expected in [(raw.replace(b'"schema_version": 1',b'"schema_version": 1, "schema_version": 1'),'DuplicateField'),(raw+b'{}','InvalidJson'),(b'\xff','InvalidJson'),(b'['*33,'LimitExceeded'),(raw.replace(b'H04.revision-fixture',b'H04.bad\\n'),'InvalidId')]:
   with self.subTest(expected=expected):
    with self.assertRaisesRegex(c.CatalogInvalid,expected):c.validate(mutated)
  v=read('revision-a');v['cases'][0]['runnable']=True;self.invalid(v,'UnknownField')
  v=read('revision-a');del v['cases'][0]['registration'];self.invalid(v,'InvalidJson')
 def test_literal_closures(self):
  data=c.validate((FIX/'cases-v1.json').read_bytes())
  native=c.select(data,'native-v1')
  self.assertEqual(native['profiles'],['bpf-host-v1','btf-shape-le-v1','capture-core-v1','compiler-object-v1','mojo-elf-v1','native-v1'])
  self.assertEqual(native['extensions'],['btf-runtime-linkage-v1'])
  self.assertEqual(native['required'],[
   ('H33.final-object-license',1,'h33-final-object-license','T2',('compiler-object-v1',)),
   ('H33.installed-notices',1,'h33-installed-notices','T5',('mojo-elf-v1',)),
   ('H33.license-admission',1,'h33-license-admission','T4',('btf-shape-le-v1',)),
   ('H33.source-closure',1,'h33-source-closure','T0',('compiler-object-v1',))])
  self.assertEqual(c.select(data,'btf-shape-le-v1')['required'],[])
  self.assertEqual(c.select(data,'compiler-object-v1')['required'],[('H33.final-object-license',1,'h33-final-object-license','T2',('compiler-object-v1',)),('H33.source-closure',1,'h33-source-closure','T0',('compiler-object-v1',))])
 def test_baseline_revision_preservation(self):
  a=check(read('revision-a'));b=check(read('revision-b'));c.baseline(b,a)
  for edit in ['old-case','old-profile','tier','remove','unselected']:
   v=read('revision-b');v['catalog_revision']=3
   if edit=='old-case':v['cases'][0]['required_cells'].append('revision-after')
   if edit=='old-profile':v['profiles'][0]['required_cases'][0]['case_version']=2
   if edit=='tier':v['cells'][0]['tier']='T2'
   if edit=='remove':v['cases'].pop(0);v['profiles'].pop(0)
   if edit=='unselected':
    old=read('revision-b');case=copy.deepcopy(old['cases'][0]);case['version']=3;old['cases'].append(case);a=check(old)
   with self.subTest(edit=edit):
    with self.assertRaisesRegex(c.CatalogInvalid,'BaselineRemoved' if edit in ['remove','unselected'] else 'BaselineSemantics'):c.baseline(check(v),a)
 def test_inactive_predicate_preserved(self):
  old=check(read('cases-v1'));v=read('cases-v1');v['catalog_revision']=2;p=next(p for p in v['profiles'] if p['id']=='btf-shape-le-v1');p['required_cases']=[]
  with self.assertRaisesRegex(c.CatalogInvalid,'BaselineSemantics'):c.baseline(check(v),old)
 def test_frozen_transitions(self):
  a=read('revision-a');b=copy.deepcopy(a);b['catalog_revision']=2;b['profiles'][0]['definition_state']='FROZEN';b['profiles'][0]['open_owners']=[]
  c.baseline(check(b),check(a));self.assertTrue(c.select(check(b),'revision-fixture-v1')['definition_complete'])
  a['catalog_revision']=3
  with self.assertRaisesRegex(c.CatalogInvalid,'BaselineState'):c.baseline(check(a),check(b))
  a['profiles'][0]['required_cases']=[];a['profiles'][0]['open_owners']=[];a['profiles'][0]['definition_state']='FROZEN';self.invalid(a,'InvalidDefinition')
 def test_inventory_parity(self):
  data=check(read('cases-v1'))
  trace=json.loads((ROOT/'docs/superpowers/plans/2026-10-17-scopebase-traceability.json').read_bytes());research=json.loads((ROOT/'docs/research/2026-10-17-shared-libraries/regression-catalog.json').read_bytes())
  c.inventory(data,trace,research)
  for kind,ident in [('regression_family','H04'),('user_conformance','UC14'),('public_contract_gap','G22')]:
   v=copy.deepcopy(data);v['obligations']=[o for o in v['obligations'] if (o['kind'],o['id'])!=(kind,ident)]
   with self.assertRaisesRegex(c.CatalogInvalid,'Inventory'):c.inventory(v,trace,research)
 def test_literal_admission_population(self):
  for row in json.loads((FIX/'admission-expectations.json').read_bytes()):
   with self.subTest(fixture=row['file']):
    raw=(FIX/row['file']).read_bytes()
    if row['expected']=='accept':
     try:c.validate(raw)
     except c.CatalogInvalid as error:self.fail('literal acceptance refused: '+str(error))
    else:
     with self.assertRaisesRegex(c.CatalogInvalid,'^'+row['expected']+'$'):c.validate(raw)
 def test_registered_file_bindings(self):
  data=check(read('registered'));self.assertFalse(c.verify_artifacts(data,None,8388608));self.assertTrue(c.verify_artifacts(data,FIX,8388608))
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);(root/'artifacts').mkdir()
   for file in (FIX/'artifacts').iterdir():(root/'artifacts'/file.name).write_bytes(file.read_bytes())
   self.assertTrue(c.verify_artifacts(data,root,8388608))
   target=root/'artifacts/oracle.txt';valid=target.read_bytes()
   for mode,expected in [('digest','ArtifactDigestMismatch'),('missing','ArtifactPathRefused'),('directory','ArtifactNonregular'),('symlink','ArtifactPathRefused'),('fifo','ArtifactNonregular'),('limit','ArtifactLimitExceeded')]:
    if mode=='digest':target.write_bytes(b'wrong sum')
    elif mode=='missing':target.unlink()
    elif mode=='directory':target.unlink();target.mkdir()
    elif mode=='symlink':target.unlink();target.symlink_to(FIX/'artifacts/oracle.txt')
    elif mode=='fifo':target.unlink();os.mkfifo(target)
    with self.subTest(mode=mode):
     with self.assertRaisesRegex(c.CatalogInvalid,expected):c.verify_artifacts(data,root,1 if mode=='limit' else 8388608)
    if target.is_dir():target.rmdir()
    elif target.exists() or target.is_symlink():target.unlink()
    target.write_bytes(valid);self.assertTrue(c.verify_artifacts(data,root,8388608))
   # A symlink in an ancestor must be refused even if its leaf bytes match.
   (root/'link').symlink_to(root/'artifacts',target_is_directory=True)
   v=copy.deepcopy(data);v['cases'][0]['registration']['oracle']['path']='link/oracle.txt'
   with self.assertRaisesRegex(c.CatalogInvalid,'ArtifactPathRefused'):c.verify_artifacts(v,root,8388608)
 def test_frozen_extension_dependency_owners(self):
  v=read('revision-a');v['profiles'][0].update(definition_state='FROZEN',open_owners=[])
  v['extensions']=[{'id':'extra-v1','profile':'revision-fixture-v1','requires_profiles':[],'requires_tasks':['TT01'],'required_cases':[]}]
  v['profiles'].append({'id':'whole-v1','definition_state':'FROZEN','requires_profiles':[],'requires_extensions':['extra-v1'],'required_cases':[],'open_owners':[]})
  plan=c.select(check(v),'whole-v1');self.assertTrue(plan['definition_complete']);self.assertEqual(plan['open_owners'],[])
 def test_exact_description_fallback_and_owner_parity(self):
  data=check(read('cases-v1'));trace=json.loads((ROOT/'docs/superpowers/plans/2026-10-17-scopebase-traceability.json').read_bytes());research=json.loads((ROOT/'docs/research/2026-10-17-shared-libraries/regression-catalog.json').read_bytes());families={f['id']:f['short_contract'] for f in research['cases']}
  for old in trace['source_obligations']:
   got=next(o for o in data['obligations'] if (o['kind'],o['id'])==(old['kind'],old['id']))
   expected=old.get('description',families[old['id']] if old['kind']=='regression_family' else '')
   self.assertEqual(got['description'],expected)
  data['obligations'][0]['owners'].pop()
  with self.assertRaisesRegex(c.CatalogInvalid,'InventoryOwners'):c.inventory(data,trace,research)
 def test_every_global_limit(self):
  a=read('revision-a');raw=json.dumps(a).encode()
  for key,n in [('max_cases',1),('max_profiles',1),('max_extensions',1),('max_obligations',1),('max_cells',2),('max_depth',6),('max_selected_cells',1),('max_edges',8)]:
   with self.subTest(limit=key):
    c.validate(raw,limits={key:n})
    if n>1:
     with self.assertRaisesRegex(c.CatalogInvalid,'LimitExceeded'):c.validate(raw,limits={key:n-1})
  for key in c.CEILINGS:
   for n in [0,c.CEILINGS[key]+1]:
    with self.subTest(limit=key,value=n):
     with self.assertRaisesRegex(c.CatalogInvalid,'InvalidLimits'):c.validate(raw,limits={key:n})
  c.validate(raw,limits={'max_input_bytes':len(raw)})
  with self.assertRaisesRegex(c.CatalogInvalid,'InputTooLarge'):c.validate(raw,limits={'max_input_bytes':len(raw)-1})
 def test_case_semantic_order_is_irrelevant(self):
  old=read('revision-b');v=copy.deepcopy(old);v['catalog_revision']=3;v['cases'][1]['required_cells'].reverse();v['cases'].reverse();v['profiles'].reverse();c.baseline(check(v),check(old))
 def test_cli_summary_and_usage(self):
  command=[sys.executable,'-B',str(ROOT/'tools/qualification/check_catalog.py')]
  result=subprocess.run(command+[str(FIX/'registered.json')],capture_output=True,check=False)
  self.assertEqual(result.returncode,0);out=json.loads(result.stdout);self.assertEqual(set(out),{'schema_version','structurally_valid','definition_complete','qualification','registrations_verified','errors'});self.assertFalse(out['definition_complete']);self.assertFalse(out['registrations_verified']);self.assertEqual(out['qualification'],'not_evaluated')
  result=subprocess.run(command+[str(FIX/'registered.json'),'--artifact-root',str(FIX)],capture_output=True,check=False);self.assertEqual(result.returncode,0);self.assertTrue(json.loads(result.stdout)['registrations_verified'])
  result=subprocess.run(command+[str(FIX/'registered.json'),'--artifact-root',str(FIX/'missing')],capture_output=True,check=False);self.assertEqual(result.returncode,2);self.assertFalse(json.loads(result.stdout)['structurally_valid'])
  result=subprocess.run(command+[str(FIX/'registered.json'),'--traceability','only-one'],capture_output=True,check=False);self.assertEqual(result.returncode,64)
  result=subprocess.run(command+[str(FIX/'direct-cycle.json')],capture_output=True,check=False);self.assertEqual(result.returncode,2);self.assertEqual(json.loads(result.stdout)['errors'],['Cycle'])
 def test_baseline_new_profile_revision_and_evidence_metadata(self):
  a=read('revision-a');b=copy.deepcopy(a);b['catalog_revision']=2;b['profiles'][0]['required_cases']=[]
  with self.assertRaisesRegex(c.CatalogInvalid,'BaselineSemantics'):c.baseline(check(b),check(a))
  b=copy.deepcopy(a);b['catalog_revision']=2;p=copy.deepcopy(a['profiles'][0]);p['id']='revision-fixture-v2';p['required_cases']=[];b['profiles'].append(p);c.baseline(check(b),check(a))
  old=read('registered');v=copy.deepcopy(old);v['catalog_revision']=2;v['cases'][0]['registration']['oracle']['revision']=2;v['cases'][0]['registration']['oracle']['sha256']='a'*64;c.baseline(check(v),check(old))
  self.assertNotEqual(v['cases'][0]['registration']['oracle'],old['cases'][0]['registration']['oracle'])
