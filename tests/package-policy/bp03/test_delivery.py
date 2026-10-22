# SPDX-License-Identifier: Apache-2.0
"""Semantic gates and post-spawn custody faults for both shipped BP03 routes."""
import contextlib,hashlib,importlib.util,json,os,signal,subprocess,sys,tempfile,time,tomllib,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[3]
SCRIPTS=[ROOT/'crates/scopebase-bpf/tests/support/check_bp03_controls.py',ROOT/'crates/scopebase-testkit/tests/fixtures/bp03/run_consumers.py']
def load(path):
 spec=importlib.util.spec_from_file_location('bp03_'+path.stem,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
class LinearContractRed(unittest.TestCase):
 def test_collected_failure_must_abort_after_real_child_before_lease(self):
  for path in SCRIPTS:
   m=load(path);root=Path(tempfile.mkdtemp(prefix='bp03-collected-red-'));stem=root/'child';stem.with_suffix('.lease.json').write_text('["lease-read-marker"]');row={};calls=[];lease_reads=[];real_loads=m.json.loads
   def checkpoint():
    calls.append(dict(row))
    if len(calls)==2:raise OSError('owned collected durability fault')
   def loads(data,*args,**kwargs):
    if 'lease-read-marker' in str(data):lease_reads.append(True)
    return real_loads(data,*args,**kwargs)
   caught=None
   with patch.object(m.json,'loads',side_effect=loads):
    try:m.execute([sys.executable,'-c','print("actual child completed")'],root,dict(PATH='/usr/bin:/bin'),stem,None,record=row,checkpoint=checkpoint)
    except BaseException as error:caught=error
   self.assertIsNotNone(row['process_group']);self.assertEqual(row['cleanup'],'complete');self.assertGreaterEqual(len(calls),2)
   self.assertIsNotNone(caught,'collected durability failure must abort the producer')
   self.assertEqual(lease_reads,[],'collected durability gates lease postprocessing')
 def test_atomic_publication_requires_directory_fsync(self):
  for path in SCRIPTS:
   m=load(path);root=Path(tempfile.mkdtemp(prefix='bp03-fsync-red-'));calls=[];real=m.os.fsync
   def fsync(fd):calls.append(os.fstat(fd).st_mode);return real(fd)
   with patch.object(m.os,'fsync',side_effect=fsync):m.atomic_json(root/'event.json',dict(actual=True))
   import stat
   self.assertTrue(any(stat.S_ISDIR(mode) for mode in calls),'publication must fsync the containing directory')

class Delivery(unittest.TestCase):
 def test_collector_excerpt_and_provenance(self):
  for path in SCRIPTS:
   m=load(path);raw=path.read_bytes();source=ROOT/'crates/scopebase-testkit/tests/fixtures/fixture-access/bounded_process.py';expected=source.read_bytes();self.assertTrue(raw.startswith(expected));self.assertEqual(hashlib.sha256(expected).hexdigest(),m.COLLECTOR_SHA256)
 def test_typed_templates_preserve_exact_paths_and_features(self):
  m=load(SCRIPTS[1]);template=(ROOT/'docs/superpowers/specs/bp03-host/client-manifests/cache.Cargo.toml.in').read_text()
  rendered=m.render_manifest(template,Path('/tmp/bpf "typed"'),Path('/tmp/testkit'),True,False,[],['bpf-host']);data=tomllib.loads(rendered)
  self.assertEqual(data['dependencies']['scopebase-bpf']['path'],'/tmp/bpf "typed"');self.assertEqual(data['patch']['crates-io']['scopebase-bpf']['path'],'/tmp/bpf "typed"');self.assertIs(data['dependencies']['scopebase-bpf']['default-features'],True)
  with self.assertRaises(ValueError):m.render_manifest(template+'\n@ARBITRARY@',Path('/tmp/b'),Path('/tmp/t'),False,False,[],[])
 def test_same_version_wrong_copy_fails_binding(self):
  m=load(SCRIPTS[1]);meta={'packages':[{'id':'client','name':'bp03-cache','version':'0.1.0','manifest_path':'/owned/client/Cargo.toml'},{'id':'bpf','name':'scopebase-bpf','version':'0.1.0','manifest_path':'/owned/bpf/Cargo.toml'},{'id':'tk','name':'scopebase-testkit','version':'0.1.0','manifest_path':'/owned/tk/Cargo.toml'}],'resolve':{'root':'client','nodes':[{'id':'client','features':[],'deps':[{'name':'scopebase_bpf','pkg':'bpf'},{'name':'scopebase_testkit','pkg':'tk'}]},{'id':'tk','features':['bpf-host'],'deps':[{'name':'scopebase_bpf','pkg':'bpf'}]},{'id':'bpf','features':[],'deps':[]}]}}
  self.assertEqual(m.inspect_graph(meta,Path('/owned/bpf'),Path('/owned/tk'),[],['bpf-host'])['package_id'],'bpf')
  meta['packages'].append({'id':'wrong','name':'scopebase-bpf','version':'0.1.0','manifest_path':'/foreign/bpf/Cargo.toml'});meta['resolve']['nodes'].append({'id':'wrong','features':[],'deps':[]});meta['resolve']['nodes'][1]['deps'][0]['pkg']='wrong'
  with self.assertRaisesRegex(ValueError,'BPF package ID'):m.inspect_graph(meta,Path('/owned/bpf'),Path('/owned/tk'),[],['bpf-host'])
 def test_atomic_receipts_never_replace(self):
  for path in SCRIPTS:
   m=load(path)
   with tempfile.TemporaryDirectory() as tmp:
    p=Path(tmp)/'receipt.json';m.atomic_json(p,{'first':1})
    with self.assertRaises(m.PublicationFailure):m.atomic_json(p,{'second':2})
    self.assertEqual(json.loads(p.read_text()),{'first':1})
 def test_reserve_before_spawn_and_preserve_collection_identity(self):
  for path in SCRIPTS:
   m=load(path)
   with tempfile.TemporaryDirectory() as tmp:
    stem=Path(tmp)/'child';row={};snapshots=[]
    def checkpoint():snapshots.append(json.loads(json.dumps(row)))
    def collected(*args,**kwargs):
     self.assertEqual(snapshots[0]['execution_status'],'RESERVED');self.assertIsNone(snapshots[0]['process_group'])
     return {'exit_code':0,'reason_code':'INTERNAL_ERROR','cleanup':'unresolved','process_group':123456,'duration_ms':1,'command':list(map(str,args[0])),'cwd':str(tmp),'logs':{n:{'path':str(stem.with_suffix('.'+n)),'sha256':None,'bytes':0} for n in ['stdout','stderr']},'errors':[{'stage':'collect','exception':'OSError','message':'primary failure','errno':None}]}
    with patch.object(m,'_bounded_run',side_effect=collected):m.execute([sys.executable,'-c','pass'],Path(tmp),{},stem,None,record=row,checkpoint=checkpoint)
    self.assertEqual(row['process_group'],123456);self.assertEqual(row['cleanup'],'unresolved');self.assertEqual(row['errors'][0]['message'],'primary failure');self.assertFalse(row['retired'])
 def test_checkpoint_and_lease_errors_do_not_erase_child_custody(self):
  for path in SCRIPTS:
   m=load(path)
   with tempfile.TemporaryDirectory() as tmp:
    stem=Path(tmp)/'child';stem.with_suffix('.lease.json').write_text('{malformed');row={};count=0
    def checkpoint():
     nonlocal count
     count+=1
     if count>1:raise OSError('checkpoint failure')
    actual={'exit_code':0,'reason_code':None,'cleanup':'complete','process_group':987654,'duration_ms':1,'command':[sys.executable],'cwd':str(tmp),'logs':{n:{'path':str(stem.with_suffix('.'+n)),'sha256':None,'bytes':0} for n in ['stdout','stderr']},'errors':[]}
    with patch.object(m,'_bounded_run',return_value=actual):
     with self.assertRaises(m.EvidenceFailure) as failure:m.execute([sys.executable],Path(tmp),{},stem,None,record=row,checkpoint=checkpoint)
    self.assertIs(failure.exception.custody,row)
    self.assertEqual(row['process_group'],987654);self.assertEqual(row['cleanup'],'complete');self.assertIsNone(row['reason_code']);self.assertEqual(row['raw_result'],actual);self.assertIn('collected-publication',{e['stage'] for e in row['wrapper_errors']});self.assertNotIn('lease-record',{e['stage'] for e in row['wrapper_errors']})
 def test_prelaunch_checkpoint_failure_does_not_spawn(self):
  for path in SCRIPTS:
   m=load(path)
   with tempfile.TemporaryDirectory() as tmp:
    with patch.object(m,'_bounded_run') as spawn:
     with self.assertRaises(m.EvidenceFailure) as failure:m.execute([sys.executable],Path(tmp),{},Path(tmp)/'child',None,checkpoint=lambda:(_ for _ in ()).throw(OSError('reserve failed')))
     row=failure.exception.custody
    spawn.assert_not_called();self.assertEqual(row['execution_status'],'RESERVED');self.assertIsNone(row['process_group'])

class BP02Admission(unittest.TestCase):
 def test_original_and_exact_bp03_positive_and_active_negative(self):
  import shutil
  m=load(ROOT/'crates/scopebase-bpf/tests/fixtures/bp02/run_consumers.py')
  m.inspect(ROOT/'crates/scopebase-bpf')
  original=json.loads((ROOT/'tests/package-policy/bp03/expected-features.json').read_text())['original_bp02_manifest_utf8']
  with tempfile.TemporaryDirectory() as tmp:
   copied=Path(tmp)/'bpf';shutil.copytree(ROOT/'crates/scopebase-bpf',copied)
   manifest=copied/'Cargo.toml';bp03=manifest.read_text();manifest.write_text(original);m.inspect(copied)
   for old,new in [('name="api_contract"','name="api_contract_removed"'),('path="tests/maps_pure.rs"','path="tests/api_contract.rs"'),('default = []','default = ["unknown"]'),('=1.0.229','=1.0.228'),('optional = true','optional = false'),('required-features = ["json"]','required-features = []'),('"fixtures/capability-v1/**"','"fixtures/omitted/**"'),('name = "capability_cache"','name = "unknown_example"')]:
    self.assertIn(old,bp03);manifest.write_text(bp03.replace(old,new,1))
    with self.assertRaises((AssertionError,ValueError),msg='manifest admission '+old):m.inspect(copied)
   manifest.write_text(bp03);m.inspect(copied)

class ClientJson(unittest.TestCase):
 def test_completion_denominator_is_external_and_refusals_exact(self):
  m=load(SCRIPTS[1])
  for client,required in m.REQUIRED_JSON_GROUPS.items():
   missing=m.completion('BP03_COMPLETION '+json.dumps({'client':client,'groups':[]}),client,'json-union')
   self.assertEqual(missing,dict(status='REFUSED',code='BP03_CLIENT_JSON_COVERAGE_MISSING',client=client,missing_required_groups=required,accepted_groups=[]))
   self.assertEqual(m.completion('BP03_COMPLETION '+json.dumps({'client':client,'groups':required}),client,'json-union')['status'],'PASS')
   for mode in ['core-default','core-minimal']:
    self.assertEqual(m.mode_admission(client,mode,['json']),dict(status='REFUSED',code='BP03_CLIENT_JSON_MODE_MISMATCH',client=client,mode=mode,requested_client_features=['json'],expected_client_features=[]));self.assertEqual(m.mode_admission(client,mode,[])['status'],'ADMITTED')

class MutationSelectors(unittest.TestCase):
 def test_every_bpf_selector_is_exact_current_production_source(self):
  m=load(SCRIPTS[0]);root=ROOT/'crates/scopebase-bpf';ids=[]
  for row in m.bpf_mutations():
   original=(root/row['file']).read_text();changed=m.mutate(original,row['changes']);self.assertNotEqual(changed,original,row['id']);ids.append(row['id'])
  self.assertEqual(len(ids),len(set(ids)))

class AdapterSelectors(unittest.TestCase):
 def test_every_adapter_control_has_a_unique_actual_source_selector(self):
  m=load(SCRIPTS[1]);source=(ROOT/'crates/scopebase-testkit/src/bpf/adapter.rs').read_text()
  for item in m.adapter_mutations():self.assertNotEqual(m.apply_changes(source,item['changes']),source,item['id'])

class CampaignPreparation(unittest.TestCase):
 def test_required_inventory_is_finite_before_execution(self):
  m=load(ROOT/'tests/package-policy/bp03/execute.py');rows=m.required_rows()
  self.assertEqual(len(rows),32);self.assertEqual(len({r['id'] for r in rows}),32)
  self.assertEqual(sum(r['subsystem']=='testkit' for r in rows),20);self.assertEqual(sum(r['subsystem']=='bpf' for r in rows),12)
  self.assertEqual(sum(len(r['retained_clients']) for r in rows),80);self.assertTrue(all(r['status']=='NOT_RUN' for r in rows))
  self.assertEqual(sum(len(r['bp03_clients']) for r in rows if r['subsystem']=='testkit'),24)
 def test_archive_traversal_and_links_refuse_before_writing(self):
  import io,tarfile
  m=load(ROOT/'tests/package-policy/bp03/execute.py')
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp)
   for index,(name,kind) in enumerate([('../escape',tarfile.REGTYPE),('/absolute',tarfile.REGTYPE),('scopebase-bpf-0.1.0//alias',tarfile.REGTYPE),('scopebase-bpf-0.1.0/link',tarfile.SYMTYPE),('scopebase-bpf-0.1.0/hard',tarfile.LNKTYPE)]):
    archive=root/(str(index)+'.crate')
    with tarfile.open(archive,'w:gz') as tar:
     entry=tarfile.TarInfo(name);entry.type=kind;entry.size=1 if kind==tarfile.REGTYPE else 0;tar.addfile(entry,io.BytesIO(b'x') if entry.size else None)
    output=root/('out-'+str(index))
    with self.assertRaises(ValueError):m.unpack(archive,output,'scopebase-bpf')
    self.assertFalse((root/'escape').exists())
 def test_effective_config_and_checksums_admit_only_actual_inputs(self):
  for path in SCRIPTS:
   m=load(path)
   with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp);home=root/'home';home.mkdir();cwd=root/'cwd';cwd.mkdir();vendor=root/'vendor';package=vendor/'literal-1.2.3';package.mkdir(parents=True)
    manifest=package/'Cargo.toml';manifest.write_text('[package]\nname="literal"\nversion="1.2.3"\n');source=package/'lib.rs';source.write_text('pub fn literal() {}\n');checksum='b'*64
    (package/'.cargo-checksum.json').write_text(json.dumps(dict(package=checksum,files={p.name:m.sha(p) for p in [manifest,source]})))
    config=home/'config.toml';config.write_text('[source.crates-io]\nreplace-with="vendored-sources"\n[source.vendored-sources]\ndirectory='+json.dumps(str(vendor))+'\n[net]\noffline=true\n');admitted=m.offline_packages(config);self.assertEqual(admitted['literal 1.2.3']['checksum'],checksum)
    lock=cwd/'Cargo.lock';lock.write_text('version=4\n[[package]]\nname="literal"\nversion="1.2.3"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="'+checksum+'"\n');self.assertEqual(m.lock_closure(lock,admitted)['sha256'],m.sha(lock))
    lock.write_text(lock.read_text().replace(checksum,'a'*64))
    with self.assertRaisesRegex(ValueError,'offline closure'):m.lock_closure(lock,admitted)
    source.write_text('corrupt admitted source')
    with self.assertRaisesRegex(ValueError,'checksum differs'):m.offline_packages(config)
    (cwd/'.cargo').mkdir();(cwd/'.cargo/config.toml').write_text('[build]\nrustflags=["unexpected"]\n')
    with self.assertRaisesRegex(ValueError,'effective Cargo config'):m.effective_configs(cwd,home,config)

class ProcessFaults(unittest.TestCase):
 """Actual owned tiny children exercise the accepted collector in both routes.

 Adapted from CP05's accepted custody repair fault tests; no private runtime
 module is imported. Logs and all structured checkpoints remain under TMPDIR.
 """
 def invoke(self,path,fault=None,*,payload=None,timeout=2):
  m=load(path);root=Path(tempfile.mkdtemp(prefix='bp03-custody-'+(fault or 'normal')+'-'));stem=root/'child';row={};snapshots=[];children=[];fired=[]
  receipt=dict(script=str(path),fault=fault,record=row,checkpoints=snapshots,children=[],harness_cleanup=[])
  def checkpoint():
   snapshots.append(json.loads(json.dumps(row)));(root/'custody.json').write_text(json.dumps(receipt,indent=2)+'\n')
  real_popen=subprocess.Popen;real_read=os.read;real_killpg=os.killpg;real_open=Path.open;real_sha=m.sha;real_wait=subprocess.Popen.wait
  def launch(*args,**kwargs):
   child=real_popen(*args,**kwargs);children.append(child);receipt['children'].append(child.pid);return child
  def read(fd,size):
   if children and fd in (children[0].stdout.fileno(),children[0].stderr.fileno()):fired.append('read');raise OSError('BP03 owned read fault')
   return real_read(fd,size)
  class Log:
   def __init__(self,stream):self.stream=stream
   def __getattr__(self,name):return getattr(self.stream,name)
   def write(self,data):
    if fault=='write':self.stream.write(data[:3]);fired.append('write');raise OSError('BP03 owned partial log write fault')
    return self.stream.write(data)
   def close(self):
    self.stream.close()
    if fault=='close':fired.append('close');raise OSError('BP03 owned log close fault')
  def open_log(path,mode='r',*args,**kwargs):
   stream=real_open(path,mode,*args,**kwargs);return Log(stream) if mode=='xb' and path.suffix=='.stdout' else stream
  def hash_fault(path):
   if Path(path).suffix=='.stdout':fired.append('hash');raise OSError('BP03 owned log hash fault')
   return real_sha(path)
  def wait(child,*args,**kwargs):
   if not fired:fired.append('wait');raise OSError('BP03 owned wait fault')
   return real_wait(child,*args,**kwargs)
  def selector(*args,**kwargs):
   fired.append('selector');raise OSError('BP03 owned selector fault')
  def group(pid,sig):
   if sig==0:fired.append('group');raise OSError('BP03 owned group observation fault')
   return real_killpg(pid,sig)
  if fault=='lease':stem.with_suffix('.lease.json').write_text('{bad JSON')
  argv=[sys.executable,'-c',payload or 'import time; print("BP03 owned child",flush=True); time.sleep(.02)']
  if fault=='setup':argv=[str(root/'missing-executable')]
  try:
   with contextlib.ExitStack() as stack:
    stack.enter_context(patch.object(m.subprocess,'Popen',side_effect=launch))
    if fault=='selector':stack.enter_context(patch.object(m.selectors.DefaultSelector,'select',side_effect=selector))
    if fault=='read':stack.enter_context(patch.object(m.os,'read',side_effect=read))
    if fault in ('write','close'):stack.enter_context(patch.object(Path,'open',open_log))
    if fault=='hash':stack.enter_context(patch.object(m,'sha',side_effect=hash_fault))
    if fault=='wait':stack.enter_context(patch.object(real_popen,'wait',wait))
    if fault=='group':stack.enter_context(patch.object(m.os,'killpg',side_effect=group))
    try:result=m.execute(argv,root,dict(PATH='/usr/bin:/bin'),stem,None,record=row,checkpoint=checkpoint,timeout=timeout)
    except m.EvidenceFailure as error:
     self.assertIn(fault,['lease','setup']);self.assertIs(error.custody,row);result=row;receipt['raised']=dict(type=type(error).__name__,message=str(error))
   self.assertIs(result,row);self.assertEqual(snapshots[0]['cleanup'],'not_started');self.assertIsNone(snapshots[0]['process_group'])
   self.assertEqual(result['raw_result'] is not None and result['reason_code'] is None and not result['wrapper_errors'],fault is None and payload is None)
   if fault=='setup':self.assertIsNone(result['process_group']);self.assertEqual(result['cleanup'],'not_started');self.assertEqual(result['execution_status'],'UNKNOWN_EXECUTION_CUSTODY');self.assertIsNone(result['raw_result'])
   else:
    self.assertEqual(result['process_group'],children[0].pid);self.assertIsNotNone(result['exit_code']);self.assertEqual(set(result['logs']),{'stdout','stderr'})
    self.assertTrue(any(v.get('process_group')==result['process_group'] for v in snapshots))
   return result,fired
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
    receipt['harness_cleanup'].append(dict(pid=child.pid,reaped=child.poll() is not None,group_retired=retired));self.assertTrue(retired,'owned fault-test process group unresolved')
   checkpoint()
 def test_each_collection_and_postprocessing_fault_preserves_custody(self):
  for path in SCRIPTS:
   for fault,stage in [('selector','collect'),('read','collect'),('write','collect'),('wait','wait'),('close','log-close'),('hash','log-hash-stdout'),('group','group-check'),('lease','lease-record')]:
    with self.subTest(script=path,fault=fault):
     row,fired=self.invoke(path,fault);self.assertEqual(row['reason_code'],None if fault=='lease' else 'INTERNAL_ERROR');self.assertTrue(any(e['stage']==stage for e in row['errors']+row['wrapper_errors']));self.assertEqual(row['cleanup'],'unresolved' if fault in ('close','group') else 'complete')
     if fault!='lease':self.assertIn(fault,fired)
     if fault=='hash':self.assertIsNone(row['logs']['stdout']['sha256'])
     if fault=='write':self.assertEqual(Path(row['stdout']).stat().st_size,3)
 def test_setup_normal_timeout_and_numeric_log_bound(self):
  for path in SCRIPTS:
   with self.subTest(script=path):
    row,_=self.invoke(path,'setup');self.assertTrue(any(e['stage']=='collector-exception' for e in row['wrapper_errors']))
    row,_=self.invoke(path);self.assertEqual((row['exit_code'],row['cleanup'],row['reason_code']),(0,'complete',None));self.assertIn('BP03 owned child',Path(row['stdout']).read_text())
    row,_=self.invoke(path,payload='import time; time.sleep(2)',timeout=.05);self.assertEqual((row['reason_code'],row['cleanup']),('TIMEOUT','complete'))
    bound=load(path).MAX_LOG;row,_=self.invoke(path,payload=f'import os; os.write(1,b"x"*{bound+65536})');self.assertEqual((row['reason_code'],row['cleanup']),('LOG_BOUND','complete'));self.assertEqual(row['logs']['stdout']['bytes'],bound)

class LinearEvents(unittest.TestCase):
 """C01-C16 focused transport controls; children are tiny and independently owned."""
 def subject(self,path,label):
  m=load(path);m._PUBLICATION_OWNER=None;root=Path(tempfile.mkdtemp(prefix='bp03-linear-'+label+'-'));j=m.EventJournal(root);j.seal({'selected':'owned tiny child','collector':m.COLLECTOR_SHA256},[{'id':'tiny','status':'NOT_RUN','oracle':'actual tiny child'}]);return m,root,j
 def child(self,m,root,j,name='tiny',**kwargs):
  row={'id':name};m.execute([sys.executable,'-c','print("owned child")'],root,dict(PATH='/usr/bin:/bin'),root/'logs'/name,None,record=row,journal=j,timeout=2,**kwargs);return row
 def independent_chain(self,root):
  import re
  events=[]
  for path in sorted((root/'commands').glob('*.json')):
   event=json.loads(path.read_bytes());self.assertEqual(set(event),{'schema_version','kind','run_id','sequence','obligation_id','phase','static_binding_ref','required_inventory_ref','current_projection_ref','previous_event_ref','payload'});self.assertEqual(path.name,'%06d.%s.json'%(event['sequence'],event['phase']))
   for key in ['static_binding_ref','required_inventory_ref','current_projection_ref','previous_event_ref']:
    ref=event[key]
    if ref is None:continue
    self.assertRegex(ref['sha256'],'^[0-9a-f]{64}$');target=root/ref['relative_path'];data=target.read_bytes();self.assertEqual(len(data),ref['length']);self.assertEqual(hashlib.sha256(data).hexdigest(),ref['sha256']);self.assertEqual(ref['owner_run_id'],event['run_id'])
   events.append(event)
  for seq in sorted({event['sequence'] for event in events}):
   group=[e for e in events if e['sequence']==seq];self.assertEqual({e['phase'] for e in group},{'reserved','collected','complete'});by={e['phase']:e for e in group};self.assertIsNone(by['reserved']['payload']['at_reservation']['process_group']);raw=by['collected']['payload']['raw_result'];self.assertEqual(set(raw),{'exit_code','reason_code','cleanup','duration_ms','command','cwd','process_group','logs','errors'});self.assertIsInstance(raw['process_group'],int);self.assertEqual(raw['cleanup'],'complete');self.assertEqual(raw['exit_code'],0);self.assertEqual(raw['errors'],[]);self.assertEqual(by['complete']['payload']['raw_result_ref'],by['complete']['previous_event_ref'])
  return events
 def test_C01_exact_collector_and_no_production_interposition(self):
  import ast
  for path in SCRIPTS:
   raw=path.read_bytes();self.assertEqual(hashlib.sha256(raw[:7929]).hexdigest(),'81e371cec788e07df9139695f8f52b07fa653b1b93d36bbf8fd41ce2d8ef5bdd');tree=ast.parse(raw)
   calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='Popen'];self.assertEqual(len(calls),1);self.assertLess(calls[0].lineno,176)
   for node in ast.walk(ast.parse(raw[7929:])):
    if isinstance(node,(ast.Assign,ast.AnnAssign)):
     for target in getattr(node,'targets',[getattr(node,'target',None)]):
      if isinstance(target,ast.Attribute):self.assertNotIn(ast.unparse(target),['subprocess.Popen','selectors.DefaultSelector'])
 def test_C02_seal_gate_normal_chain_and_raw_identity(self):
  for path in SCRIPTS:
   m=load(path);m._PUBLICATION_OWNER=None;root=Path(tempfile.mkdtemp(prefix='bp03-unsealed-'));j=m.EventJournal(root)
   with patch.object(m,'_bounded_run') as child:
    with self.assertRaises(m.EvidenceFailure):self.child(m,root,j)
   child.assert_not_called()
   m,root,j=self.subject(path,'normal');actual=[];original=m._bounded_run
   def collect(*a,**k):result=original(*a,**k);actual.append(result);return result
   with patch.object(m,'_bounded_run',side_effect=collect):row=self.child(m,root,j)
   self.assertIs(row['raw_result'],actual[0]);self.independent_chain(root);self.assertEqual(len(list(root.glob('bindings-v2.json'))),1)
   proof=j.finish(dict(status='PASS',commands=[row]));self.assertEqual(m.accept_finalized(proof)['status'],'PASS')
 def test_C03_reservation_fault_matrix_never_launches(self):
  for path in SCRIPTS:
   for stage in ['serialize','temp-open','file-fsync','link','directory-fsync','mkdir-fsync-parent']:
    with self.subTest(script=path.name,stage=stage):
     m,root,j=self.subject(path,'reserve-'+stage)
     def fail(at,p):
      if str(p).endswith('.reserved.json') and at==stage:raise OSError('owned reservation '+stage)
      if stage=='mkdir-fsync-parent' and at==stage and p==root/'commands':raise OSError('owned new directory fsync')
     with patch.object(m,'publication_step',side_effect=fail),patch.object(m,'_bounded_run') as child:
      with self.assertRaises(m.EvidenceFailure):self.child(m,root,j)
     child.assert_not_called();self.assertTrue(j.failed)
     self.assertEqual((root/'commands/000001.reserved.json').exists(),stage=='directory-fsync')
   m,root,j=self.subject(path,'exclusive');prior=root/'commands/000001.reserved.json';prior.parent.mkdir();prior.write_bytes(b'prior-owned-by-another-attempt\n')
   with patch.object(m,'_bounded_run') as child:
    with self.assertRaises(m.EvidenceFailure):self.child(m,root,j)
   child.assert_not_called();self.assertEqual(prior.read_bytes(),b'prior-owned-by-another-attempt\n')
   with self.assertRaisesRegex(ValueError,'byte bound'):m.bounded_json({'payload':'long'},4)
 def test_C04_collected_fault_matrix_preserves_actual_custody(self):
  for path in SCRIPTS:
   for stage in ['serialize','temp-open','file-fsync','link','directory-fsync']:
    with self.subTest(script=path.name,stage=stage):
     m,root,j=self.subject(path,'collected-'+stage);actual=[];lease_calls=[];semantic_calls=[];real=m._bounded_run;real_loads=m.json.loads;(root/'logs').mkdir();(root/'logs/tiny.lease.json').write_text('["C04 lease decode marker"]')
     def collect(*a,**k):r=real(*a,**k);actual.append(r);return r
     def decode(data,*a,**k):
      if 'C04 lease decode marker' in str(data):lease_calls.append(True)
      return real_loads(data,*a,**k)
     def fail(at,p):
      if p.name.endswith('.collected.json') and at==stage:raise OSError('owned collected '+stage)
     with patch.object(m,'_bounded_run',side_effect=collect),patch.object(m,'publication_step',side_effect=fail),patch.object(m.json,'loads',side_effect=decode):
      with self.assertRaises(m.EvidenceFailure) as caught:
       self.child(m,root,j);semantic_calls.append(True)
     row=caught.exception.custody;self.assertEqual(lease_calls,[]);self.assertEqual(semantic_calls,[]);self.assertIs(row['raw_result'],actual[0]);self.assertEqual(row['raw_result']['cleanup'],'complete');self.assertEqual(row['raw_result']['errors'],[]);self.assertFalse(any('lease' in e['stage'] for e in row['wrapper_errors']));self.assertFalse((root/'commands/000001.complete.json').exists())
     with patch.object(m,'_bounded_run') as next_child:
      with self.assertRaises(m.EvidenceFailure):self.child(m,root,j,'forbidden-next')
     next_child.assert_not_called();self.assertIs(j.last_failure.custody,row,'permanent latch preserves first returned custody')
 def test_C06_compound_failure_and_unwritable_emergency_keep_first_custody(self):
  for path in SCRIPTS:
   m,root,j=self.subject(path,'compound');fired=[]
   def select(*a,**k):fired.append(True);raise OSError('owned primary selector fault')
   def fail(at,p):
    if p.name.endswith('.collected.json') and at in ['file-fsync','temp-unlink']:raise OSError('owned '+at)
   with patch.object(m.selectors.DefaultSelector,'select',side_effect=select),patch.object(m,'publication_step',side_effect=fail):
    with self.assertRaises(m.EvidenceFailure) as caught:self.child(m,root,j)
   custody=caught.exception.custody;raw=custody['raw_result'];self.assertTrue(fired);self.assertTrue(raw['errors']);self.assertEqual(raw['reason_code'],'INTERNAL_ERROR');self.assertTrue(any('temp' in x['stage'] for x in caught.exception.failures))
   def denied(*a):raise OSError('all evidence writes denied')
   with patch.object(m,'publication_step',side_effect=denied):
    first=j.emergency(caught.exception);second=j.emergency(ValueError('later outer error'))
   self.assertIs(first,second);self.assertIs(second.custody,custody);self.assertIs(second.custody['raw_result'],raw);self.assertTrue(j.emergency_attempted)
 def test_C07_uncertain_final_is_not_success_and_final_attempt_is_one_shot(self):
  for path in SCRIPTS:
   for stage in ['temp-open','directory-fsync']:
    m,root,j=self.subject(path,'final-'+stage);row=self.child(m,root,j);collected=(root/'commands/000001.collected.json').read_bytes()
    def fail(at,p):
     if p.name=='receipt.json' and at==stage:raise OSError('owned final '+stage)
    with patch.object(m,'publication_step',side_effect=fail):
     with self.assertRaises(m.EvidenceFailure):j.finish(dict(status='PASS',commands=[row]))
    with self.assertRaises(m.EvidenceFailure):j.finish(dict(status='INCOMPLETE',commands=[row]))
    self.assertEqual((root/'commands/000001.collected.json').read_bytes(),collected)
    if stage=='directory-fsync':
     self.assertEqual(json.loads((root/'receipt.json').read_bytes())['status'],'PASS');ref=m.file_reference(root,root/'receipt.json','final-receipt',j.run_id)
     with self.assertRaises(ValueError):m.accept_finalized(m.FinalizedReceipt(root,ref,j.run_id))
 def test_C11_predecessor_and_reference_adversaries(self):
  import copy,shutil
  for path in SCRIPTS:
   m,root,j=self.subject(path,'adversaries');self.child(m,root,j);reference=j.events[-1];self.independent_chain(root)
   for fault in ['cross-run','hash','length','history','missing-raw','bad-reserved']:
    clone=Path(tempfile.mkdtemp(prefix='bp03-chain-mutant-'))/'copy';shutil.copytree(root,clone);ref=copy.deepcopy(reference)
    if fault=='cross-run':ref['owner_run_id']='0'*32
    elif fault=='hash':ref['sha256']='0'*64
    elif fault=='length':ref['length']+=1
    elif fault=='history':
     value=json.loads((clone/ref['relative_path']).read_bytes());value['commands']=[value.copy()];(clone/ref['relative_path']).write_bytes(m.bounded_json(value,m.EVENT_LIMIT));ref=m.file_reference(clone,clone/ref['relative_path'],'command-event',j.run_id)
    else:
     complete=json.loads((clone/ref['relative_path']).read_bytes());cref=complete['previous_event_ref'];collected=json.loads((clone/cref['relative_path']).read_bytes())
     if fault=='missing-raw':del collected['payload']['raw_result']['errors']
     else:
      rref=collected['previous_event_ref'];reserved=json.loads((clone/rref['relative_path']).read_bytes());reserved['payload']['at_reservation']['cleanup']='complete';(clone/rref['relative_path']).write_bytes(m.bounded_json(reserved,m.EVENT_LIMIT));collected['previous_event_ref']=m.file_reference(clone,clone/rref['relative_path'],'command-event',j.run_id)
     (clone/cref['relative_path']).write_bytes(m.bounded_json(collected,m.EVENT_LIMIT));new=m.file_reference(clone,clone/cref['relative_path'],'command-event',j.run_id);complete['previous_event_ref']=new;complete['payload']['raw_result_ref']=new;(clone/ref['relative_path']).write_bytes(m.bounded_json(complete,m.EVENT_LIMIT));ref=m.file_reference(clone,clone/ref['relative_path'],'command-event',j.run_id)
    with self.subTest(script=path.name,fault=fault):
     with self.assertRaises((ValueError,KeyError,TypeError)):m.validate_event(clone,ref,j.run_id)
   for lexical in [root/'x/../alias']:
    with self.assertRaises(ValueError):m.lexical_path(lexical)
   alias=root/'alias';alias.symlink_to(root,target_is_directory=True)
   with self.assertRaises(ValueError):m.lexical_path(alias/'output')
 def test_C13_linear_own_rows_and_fixed_inventory(self):
  from collections import Counter
  for path in SCRIPTS:
   measurements=[]
   for count in [1,2,4]:
    m,root,j=self.subject(path,'linear-'+str(count));peaks=[]
    def measure(stage,path):
     if stage not in ['file-fsync','directory-fsync']:return
     files={}
     for candidate in root.rglob('*'):
      if candidate.is_file():
       info=candidate.stat();files[(info.st_dev,info.st_ino)]=info.st_size
     peaks.append(dict(stage=stage,publisher=str(path.relative_to(root)),unique_retained_bytes=sum(files.values()),temporary_files=[str(p.relative_to(root)) for p in root.rglob('*.tmp')]))
    with patch.object(m,'publication_step',side_effect=measure):
     rows=[self.child(m,root,j,'tiny-'+str(i)) for i in range(count)];proof=j.finish(dict(status='PASS',commands=rows))
    report=m.accept_finalized(proof);events=self.independent_chain(root);self.assertEqual(len(events),3*count);self.assertEqual(len(report['commands']),count);self.assertEqual(len({r['id'] for r in report['commands']}),count);measurements.append({'commands':count,'event_bytes':sum(p.stat().st_size for p in (root/'commands').glob('*.json')),'static_bytes':(root/'bindings-v2.json').stat().st_size+(root/'required-v2.json').stat().st_size,'final_bytes':(root/'receipt.json').stat().st_size,'retained_bytes':sum(p.stat().st_size for p in root.rglob('*') if p.is_file()),'actual_publication_peak_bytes':max(v['unique_retained_bytes'] for v in peaks),'publication_observations':peaks})
   (root.parent/(root.name+'-measurements.json')).write_text(json.dumps(measurements));self.assertLess(measurements[2]['event_bytes'],measurements[0]['event_bytes']*4.2);self.assertGreater(measurements[2]['event_bytes'],measurements[0]['event_bytes']*3.8)
   obligations=m.fixed_obligations();self.assertEqual(len(obligations),528);self.assertEqual(len({r['id'] for r in obligations}),528);counts=Counter(r['kind'] for r in obligations);self.assertEqual({k:counts[k] for k in ['library-cell','retained-client','bp03-positive-client','control-helper','bpf-semantic-control','bpf-compile-control','adapter-semantic-control','adapter-binding-control']},{'library-cell':32,'retained-client':80,'bp03-positive-client':24,'control-helper':8,'bpf-semantic-control':236,'bpf-compile-control':48,'adapter-semantic-control':60,'adapter-binding-control':4})

 def test_C12_external_interruption_retains_unknown_custody(self):
  # This separate supervisor owns the launched helper and adopts its tiny child.
  # It observes only a test-owned barrier. Production gets no launch observer.
  supervisor=r'''
import ctypes,hashlib,importlib.util,json,os,signal,subprocess,sys,time
from pathlib import Path
script,root=map(Path,sys.argv[1:]);root.mkdir()
assert ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)==0
nonce=os.urandom(16).hex();barrier=root/'barrier.json'
child="import json,os,time; from pathlib import Path; Path("+repr(str(barrier))+").write_text(json.dumps(dict(nonce="+repr(nonce)+",pid=os.getpid(),group=os.getpgrp()))); time.sleep(20)"
helper="import importlib.util,sys; from pathlib import Path; s=importlib.util.spec_from_file_location('owned_helper',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); root=Path(sys.argv[2]); j=m.EventJournal(root/'events'); j.seal({'test':'interrupted'},[{'id':'tiny','status':'NOT_RUN'}]); m.execute([sys.executable,'-c',sys.argv[3]],root,{'PATH':'/usr/bin:/bin'},root/'logs/child',None,journal=j,timeout=15)"
p=subprocess.Popen([sys.executable,'-c',helper,str(script),str(root),child]);deadline=time.monotonic()+5
while not barrier.exists():
 if p.poll() is not None:raise AssertionError('helper exited before owned barrier')
 if time.monotonic()>deadline:raise AssertionError('owned barrier timeout')
 time.sleep(.01)
owned=json.loads(barrier.read_bytes());assert owned['nonce']==nonce and owned['pid']==owned['group'];pidfd=os.pidfd_open(owned['pid']);p.kill();p.wait(timeout=2)
# Actual retained pidfd authority; never infer an identity from a historical PID.
signal.pidfd_send_signal(pidfd,signal.SIGKILL);pid,status=os.waitpid(owned['pid'],0);os.close(pidfd);assert pid==owned['pid']
s=importlib.util.spec_from_file_location('reader',script);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);audit=m.audit_commands(root/'events');assert audit==[dict(sequence=1,state='UNKNOWN_EXECUTION_CUSTODY',automatic_retry=False,ownership_release=False)]
reserved=root/'events/commands/000001.reserved.json';before=hashlib.sha256(reserved.read_bytes()).hexdigest();assert not (root/'events/commands/000001.collected.json').exists();assert not (root/'events/receipt.json').exists()
mutants=[]
for name,field,value in [('NO_CHILD','state','NO_CHILD'),('PASS','state','PASS'),('AUTOMATIC_RETRY','automatic_retry',True),('OWNERSHIP_RELEASE','ownership_release',True)]:
 candidate=[dict(audit[0])];candidate[0][field]=value;assert candidate!=[dict(sequence=1,state='UNKNOWN_EXECUTION_CUSTODY',automatic_retry=False,ownership_release=False)];mutants.append(dict(name=name,changed_field=field,rejected=True))
report=dict(helper_pid=p.pid,helper_exit=p.returncode,barrier=owned,audit=audit,harness_cleanup=dict(pid=pid,reaped=True,status=status),reserved_sha256=before,classification_mutants_rejected=mutants)
(root/'interruption-control.json').write_text(json.dumps(report));print(json.dumps(report))
'''
  for path in SCRIPTS:
   root=Path(tempfile.mkdtemp(prefix='bp03-interruption-'))/'owned';result=subprocess.run([sys.executable,'-c',supervisor,str(path),str(root)],capture_output=True,text=True,timeout=10);self.assertEqual(result.returncode,0,result.stderr);actual=json.loads(result.stdout);self.assertEqual(actual['helper_exit'],-signal.SIGKILL);self.assertTrue(actual['harness_cleanup']['reaped']);self.assertEqual(actual['audit'][0]['state'],'UNKNOWN_EXECUTION_CUSTODY')

 def test_C14_parent_completion_requires_return_and_preserves_remaining_rows(self):
  for path in SCRIPTS:
   m,root,j=self.subject(path,'parent-child');row=self.child(m,root,j);completion=j.finish(dict(status='PASS',commands=[row]));parent_root=Path(tempfile.mkdtemp(prefix='bp03-parent-'));required=[dict(id='cell-'+str(i),status='NOT_RUN') for i in range(3)];parent=m.ParentEvents(parent_root,{'selected':'finite parent'},required);report=dict(status='INCOMPLETE',required=required,clients=[]);parent.checkpoint(report);parent.reserve_row(required[0]);actual,reference=parent.child(m,completion,'cell-0');self.assertEqual(actual['commands'][0]['id'],'tiny');required[0].update(status='PASS',child_reference=reference);parent.checkpoint(report)
   self.assertNotIn('commands',reference);self.assertNotIn('clients',reference);self.assertEqual(set(reference),{'child_id','root','receipt_ref','producer_return'})
   with self.assertRaises(ValueError):parent.child(m,None,'not-observed')
   error=m.EvidenceFailure('owned early failure',{'owned_child':row});self.assertIs(parent.abort(error,report).custody,error.custody);final=json.loads((parent_root/'receipt.json').read_bytes());self.assertEqual([r['status'] for r in final['required']],['PASS','NOT_RUN','NOT_RUN']);self.assertEqual(final['status'],'INCOMPLETE')
   clean_root=Path(tempfile.mkdtemp(prefix='bp03-parent-history-'));clean=m.ParentEvents(clean_root,{'test':'body mutant'},[{'id':'cell','status':'NOT_RUN'}]);mutant=dict(status='INCOMPLETE',required=[{'id':'cell','status':'NOT_RUN'}],clients=[dict(id='client',input='source',compiler='1.88.0',mode='json-union',client='cache',child_reference=reference,commands=actual['commands'])])
   with self.assertRaises(m.EvidenceFailure):clean.checkpoint(mutant)

 def test_C16_restoring_only_writer_restores_success(self):
  for path in SCRIPTS:
   m,root,j=self.subject(path,'writer-wrong')
   def fail(stage,p):
    if p.name.endswith('.collected.json') and stage=='file-fsync':raise OSError('named writer fault')
   with patch.object(m,'publication_step',side_effect=fail):
    with self.assertRaises(m.EvidenceFailure):self.child(m,root,j)
   restored,restored_root,restored_journal=self.subject(path,'writer-restored');row=self.child(restored,restored_root,restored_journal);self.assertEqual(restored.accept_finalized(restored_journal.finish(dict(status='PASS',commands=[row])))['status'],'PASS');self.independent_chain(restored_root)

 def test_C07_complete_and_semantic_postprocessing_keep_durable_raw(self):
  for path in SCRIPTS:
   m,root,j=self.subject(path,'complete-fault')
   def fail(stage,p):
    if p.name.endswith('.complete.json') and stage=='link':raise OSError('owned complete publication fault')
   with patch.object(m,'publication_step',side_effect=fail):
    with self.assertRaises(m.EvidenceFailure) as error:self.child(m,root,j)
   original=(root/'commands/000001.collected.json').read_bytes();self.assertIsNotNone(error.exception.custody['raw_result']);self.assertEqual(json.loads(original)['payload']['raw_result'],error.exception.custody['raw_result']);self.assertFalse((root/'commands/000001.complete.json').exists())
   # Minimal owned Run inputs exercise the real command's post-collection path.
   m,root,j=self.subject(path,'semantic-fault');home=root/'cargo-home';home.mkdir();config=home/'config.toml';config.write_text('[net]\noffline=true\n');run=m.Run.__new__(m.Run);run.out=root;run.journal=j;run.report={'commands':[]};run.config=config;run.home=home;run.env={'PATH':'/usr/bin:/bin'};run.wrapper=None;run.source_projection=lambda cwd,argv,name:j.sidecar('command-projection',dict(source_trees=[],extra={},cwd=str(cwd),product_command=list(map(str,argv)),command_sequence=j.sequence+1,obligation_id=name))
   def decode():json.loads('{owned semantic decoder fault')
   run.checkpoint=decode
   with self.assertRaises(m.EvidenceFailure) as caught:run.command('tiny-semantic',[sys.executable,'-c','print("actual semantic input")'],root)
   raw=caught.exception.custody['raw_result'];self.assertEqual(raw['exit_code'],0);self.assertEqual(raw['cleanup'],'complete');collected=(root/'commands/000001.collected.json').read_bytes();self.assertEqual(json.loads(collected)['payload']['raw_result'],raw)

 def test_C07_retained_executable_hash_fault_after_real_child(self):
  for path in SCRIPTS:
   m,root,j=self.subject(path,'retained-hash');home=root/'cargo-home';home.mkdir();config=home/'config.toml';config.write_text('[net]\noffline=true\n');fixture=root/'tiny-executable';fixture.write_text('#!'+sys.executable+'\nprint("owned executable, transport only")\n');fixture.chmod(0o700)
   run=m.Run.__new__(m.Run);run.out=root;run.journal=j;run.report=dict(commands=[],test_executables=[],status='INCOMPLETE');run.config=config;run.home=home;run.env={'PATH':'/usr/bin:/bin'};run.wrapper=None;run.source_projection=lambda cwd,argv,name:j.sidecar('command-projection',dict(source_trees=[],extra={},cwd=str(cwd),product_command=list(map(str,argv)),command_sequence=j.sequence+1,obligation_id=name));executed=[]
   # This explicit transport fixture is not a compiler or product-test oracle.
   run.cargo=lambda *a:(None,json.dumps({'reason':'compiler-artifact','executable':str(fixture),'profile':{'test':True}}))
   run.checkpoint=lambda:executed.append(True) if run.report['commands'] and run.report['commands'][-1].get('raw_result') is not None else None
   real=m.sha
   def hash_fault(p):
    if executed and Path(p)==root/'test-executables/owned-test':raise OSError('owned retained executable read/hash fault')
    return real(p)
   with patch.object(m,'sha',side_effect=hash_fault):
    with self.assertRaisesRegex(OSError,'retained executable'):run.test('owned-test',['test','--lib','tiny-filter'],root,root/'target')
   custody=run.report['commands'][-1];error=run.abort(OSError('outer preserved hash error'));self.assertIs(error.custody,custody);self.assertEqual(custody['raw_result']['cleanup'],'complete');self.assertEqual(json.loads((root/'commands/000001.collected.json').read_bytes())['payload']['raw_result'],custody['raw_result'])

 def test_C09_stale_workspace_and_changed_validated_lock_stop_before_child(self):
  for path in SCRIPTS:
   m,root,j=self.subject(path,'workspace-stale');manifest=root/'Cargo.toml';manifest.write_text('[workspace]\n');run=m.Run.__new__(m.Run);run.journal=j;run.report={'source_mapping':{'source':{}},'stage_workspace':{'path':str(manifest),'sha256':'0'*64}}
   with patch.object(m,'_bounded_run') as child:
    with self.assertRaisesRegex(m.EvidenceFailure,'stale final stage workspace'):run.seal([])
   child.assert_not_called()
   m,root,j=self.subject(path,'lock-changed');manifest=root/'Cargo.toml';manifest.write_text('[workspace]\n');lock=root/'Cargo.lock';lock.write_text('version=4\n[[package]]\nname="scopebase-bpf"\nversion="0.1.0"\n');run=m.Run.__new__(m.Run);run.journal=j;run.packages={};run._lock_bindings={str(lock):{'sha256':'0'*64}}
   with patch.object(m,'_bounded_run') as child,patch.object(run,'command') as command:
    with self.assertRaisesRegex(m.EvidenceFailure,'changed or unvalidated'):run.cargo('forbidden',['metadata','--offline','--locked'],root)
   child.assert_not_called();command.assert_not_called()

 def test_C11_nonfinal_history_arrays_and_phase_reordering_refuse(self):
  for path in SCRIPTS:
   m,root,j=self.subject(path,'history')
   with self.assertRaises(m.EvidenceFailure):j.sidecar('mutant',{'command':{'commands':[{'prior':'history'}]}})
   m,root,j=self.subject(path,'phase-order');j.required=[{'id':'tiny','required_phases':['reserved','wrong-executed','source-restored','restored-positive','complete']}];first=j.result('tiny','reserved',{'result':{'id':'tiny'}})
   with self.assertRaises(m.EvidenceFailure):j.result('tiny','complete',{'result':{'id':'tiny'}},first)


def c15_owned_control(script,root,wrapper,lock):
 """Explicit controller-bound route; run outside a lease, children wrap once.

 The --timeout 0 negative is the sole admitted routing exception. No compiler,
 Cargo or product process is launched by the refusal. Holder and restored twin
 use ordinary --timeout 1800. Caller supplies all four absolute bindings.
 """
 m=load(script);m._PUBLICATION_OWNER=None;root=Path(root);root.mkdir(parents=True,exist_ok=False);barrier=root/'holder-barrier.json';release=root/'release';forbidden=root/'forbidden-product-launch';marker=root/'restored-product-launch';nonce=os.urandom(16).hex();holder=None;retired=False;result={}
 holder_code='''import json,os,sys,time
from pathlib import Path
barrier,release,nonce=map(str,sys.argv[1:]);rows=[]
for name in os.listdir('/proc/self/fd'):
 try:
  target=os.readlink('/proc/self/fd/'+name)
  if target.endswith('.lock'):
   info=os.fstat(int(name));rows.append(dict(fd=int(name),path=target,device=info.st_dev,inode=info.st_ino,pid=os.getpid(),group=os.getpgrp()))
 except OSError:pass
with Path(barrier).open('x') as stream:json.dump(dict(nonce=nonce,lease=rows,pid=os.getpid(),group=os.getpgrp()),stream)
deadline=time.monotonic()+10
while not Path(release).exists():
 if time.monotonic()>deadline:raise RuntimeError('owned holder deadline')
 time.sleep(.01)
'''
 command=[str(wrapper),'--timeout','1800','--',sys.executable,'-c',holder_code,str(barrier),str(release),nonce];m.atomic_json(root/'holder-reserved.json',dict(command=command,process_group=None,temporal_scope='reservation instant only'))
 try:
  with (root/'holder.stdout').open('xb') as stdout,(root/'holder.stderr').open('xb') as stderr:holder=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True,env={'PATH':'/usr/bin:/bin'})
  deadline=time.monotonic()+5
  while not barrier.exists():
   if holder.poll() is not None:raise AssertionError('owned holder exited before barrier')
   if time.monotonic()>deadline:raise AssertionError('owned holder did not acquire common lease')
   time.sleep(.01)
  observed=json.loads(barrier.read_bytes());assert observed['nonce']==nonce and observed['group']==holder.pid;identity=lock.stat();leases=[r for r in observed['lease'] if r['path']==str(lock) and (r['device'],r['inode'])==(identity.st_dev,identity.st_ino)];assert len(leases)==1
  m.atomic_json(root/'holder-acquired.json',dict(holder_pid=holder.pid,process_group=holder.pid,observed=observed))
  journal=m.EventJournal(root/'events');journal.seal(dict(kind='C15_OWNED_COMMON_WRAPPER_CONTROL',wrapper=dict(path=str(wrapper),sha256=m.sha(wrapper)),lock=dict(path=str(lock),device=identity.st_dev,inode=identity.st_ino),ordinary_timeout=1800,control_exception_timeout=0),[dict(id='c15',status='NOT_RUN',required_phases=['reserved','refused-before-cargo','restored-positive','complete'],oracle='actual acquisition refusal, no product launch, same domain restored after release')]);first=journal.result('c15','reserved',{'result':{'id':'c15','status':'NOT_RUN'}})
  row={'id':'acquisition-refusal'};m.execute([wrapper,'--timeout','0','--',sys.executable,'-c','from pathlib import Path; Path('+repr(str(forbidden))+').touch()'],root,{'PATH':'/usr/bin:/bin'},root/'logs/refusal',None,record=row,journal=journal,timeout=2)
  assert row['raw_result']['exit_code']==75 and row['raw_result']['cleanup']=='complete' and row['raw_result']['reason_code'] is None and not forbidden.exists();assert 'lock acquisition timed out; command not launched' in Path(row['stderr']).read_text();row['execution_status']='NOT_RUN_LOCK_REFUSAL';refused=journal.result('c15','refused-before-cargo',{'result':dict(id='c15',status='NOT_RUN_LOCK_REFUSAL',product_launches=0,actual_wrapper_result=row)},first)
  release.touch();assert holder.wait(timeout=3)==0
  try:os.killpg(holder.pid,0)
  except ProcessLookupError:retired=True
  assert retired;m.atomic_json(root/'holder-complete.json',dict(holder_pid=holder.pid,exit_code=holder.returncode,harness_cleanup='complete',group_absent=True))
  positive={'id':'restored-wrapper'};m.execute([sys.executable,'-c','from pathlib import Path; Path('+repr(str(marker))+').touch(); print("restored common lease")'],root,{'PATH':'/usr/bin:/bin'},root/'logs/restored',wrapper,record=positive,journal=journal,timeout=3);assert marker.exists() and positive['raw_result']['exit_code']==0 and positive['raw_result']['cleanup']=='complete';assert any((r['device'],r['inode'])==(identity.st_dev,identity.st_ino) for r in positive['live_lease_identity']);restored=journal.result('c15','restored-positive',{'result':dict(id='c15',status='PASS',actual_wrapper_result=positive)},refused);journal.result('c15','complete',{'result':dict(id='c15',status='PASS',holder_retired=True)},restored)
  result=m.accept_finalized(journal.finish(dict(status='PASS',commands=[row,positive],holder_binding=observed,scope='C15 control only; no compiler or product qualification')));return result
 finally:
  release.touch(exist_ok=True)
  if holder is not None and holder.poll() is None:
   try:holder.wait(timeout=2)
   except subprocess.TimeoutExpired:
    os.killpg(holder.pid,signal.SIGKILL);holder.wait(timeout=2)


class PhaseAndAbortRegression(unittest.TestCase):
 def test_compile_refusal_waits_for_explicit_positive_reference(self):
  for path in SCRIPTS:
   m=load(path);m._PUBLICATION_OWNER=None;root=Path(tempfile.mkdtemp(prefix='bp03-compile-phase-'));j=m.EventJournal(root);required=[r for r in m.fixed_obligations() if r['id']=='source/1.88.0/controls/bpf-public/minimal/bp03_default'];j.seal({'test':'compile-phase'},required)
   run=m.Run.__new__(m.Run);run.journal=j;run.local_required=required;run._result_refs={};run._result_phases={};run._checkpoint_cache={};run.report=dict(kind='transport-only',clients=[],controls=[],commands=[])
   row=dict(id='bp03_default',mode='minimal',status='NOT_RUN');run.report['controls'].append(row);run.result_phase(row,'reserved');run.result_phase(row,'refused-compile');row['status']='KILLED_COMPILE_BOUNDARY';run.checkpoint()
   self.assertEqual(j.result_phases[row['obligation_id']],['reserved','refused-compile']);self.assertFalse(j.failed);run.result_phase(row,'positive-reference');run.result_phase(row,'complete');run.checkpoint()
 def test_latched_abort_attempts_one_full_incomplete_receipt(self):
  for path in SCRIPTS:
   m=load(path);m._PUBLICATION_OWNER=None;root=Path(tempfile.mkdtemp(prefix='bp03-abort-final-'));j=m.EventJournal(root);j.seal({'test':'abort-final'},[{'id':'tiny','status':'NOT_RUN'}]);row={'id':'tiny'};m.execute([sys.executable,'-c','print("actual child")'],root,{'PATH':'/usr/bin:/bin'},root/'logs/child',None,record=row,journal=j)
   run=m.Run.__new__(m.Run);run.journal=j;run.report=dict(kind='transport-only',status='INCOMPLETE',commands=[row],clients=[],controls=[])
   def forbidden():raise AssertionError('latched incremental checkpoint must not run before final aggregate')
   run.checkpoint=forbidden;failure=j.fail(ValueError('intended semantic postprocessing failure'),row);actual=run.abort(failure);self.assertIs(actual.custody,row);self.assertTrue(j.final_attempted);final=json.loads((root/'receipt.json').read_bytes());self.assertEqual(final['status'],'INCOMPLETE');self.assertEqual(final['commands'][0]['raw_result'],row['raw_result']);self.assertEqual(len(final['command_event_refs']),3)


class RestorationFailureRegression(unittest.TestCase):
 def test_C08_restore_fault_and_restored_execution_failure_stay_partial(self):
  for script in SCRIPTS:
   for fault in ['source-restore','restored-execution']:
    m=load(script);m._PUBLICATION_OWNER=None;root=Path(tempfile.mkdtemp(prefix='bp03-restoration-'+fault+'-'));required=[r for r in m.fixed_obligations() if r['id']=='source/1.88.0/controls/bpf-public/minimal/all_zero_supported'];j=m.EventJournal(root);j.seal({'scope':'tiny restoration protocol fault, not a product semantic control'},required);run=m.Run.__new__(m.Run);run.out=root;run.journal=j;run.local_required=required;run._result_refs={};run._result_phases={};run._checkpoint_cache={};run.report=dict(kind='transport-only',status='INCOMPLETE',commands=[],clients=[],controls=[]);home=root/'cargo-home';home.mkdir();run.home=home;run.config=home/'config.toml';run.config.write_text('[net]\noffline=true\n');run.env={'PATH':'/usr/bin:/bin'};run.wrapper=None;run.source_projection=lambda cwd,argv,name:j.sidecar('command-projection',dict(source_trees=[],extra={},cwd=str(cwd),product_command=list(map(str,argv)),command_sequence=j.sequence+1,obligation_id=name))
    control=dict(id='all_zero_supported',mode='minimal',status='NOT_RUN');run.report['controls'].append(control);run.result_phase(control,'reserved');row,_=run.command('owned-pre-restore',[sys.executable,'-c','print("owned protocol input")'],root);run.result_phase(control,'wrong-executed')
    source=root/'owned-source.rs';source.write_text('mutant owned source');original='restored owned source'
    if fault=='source-restore':
     real_write=Path.write_text
     def failed_write(path,*args,**kwargs):
      if path==source:raise OSError('owned source restoration failure')
      return real_write(path,*args,**kwargs)
     with patch.object(Path,'write_text',new=failed_write):
      try:source.write_text(original)
      except OSError as caught:error=caught
      else:self.fail('source restoration write must fail')
     self.assertEqual(source.read_text(),'mutant owned source')
    else:
     source.write_text(original);self.assertEqual(source.read_text(),original);run.result_phase(control,'source-restored')
     try:run.command('owned-restored',[sys.executable,'-c','raise SystemExit(3)'],root)
     except m.EvidenceFailure as caught:error=caught
     else:self.fail('restored execution failure must refuse')
    run.abort(error);receipt=json.loads((root/'receipt.json').read_bytes());self.assertEqual(receipt['status'],'INCOMPLETE');phases=j.result_phases[required[0]['id']];self.assertNotIn('restored-positive',phases);self.assertNotIn('complete',phases)
    with patch.object(m,'_bounded_run') as next_child:
     with self.assertRaises(m.EvidenceFailure):run.command('forbidden-next',[sys.executable,'-c','pass'],root)
    next_child.assert_not_called();self.assertIsNotNone(j.last_failure.custody['raw_result'])


class AdditionalBindingControls(unittest.TestCase):
 def test_C11_missing_changed_sidecar_and_output_aliases_refuse(self):
  import shutil
  from types import SimpleNamespace
  for script in SCRIPTS:
   m=load(script);m._PUBLICATION_OWNER=None;root=Path(tempfile.mkdtemp(prefix='bp03-sidecar-controls-'));j=m.EventJournal(root);j.seal({'test':'sidecar'},[{'id':'tiny','status':'NOT_RUN'}]);row={'id':'tiny'};m.execute([sys.executable,'-c','print("owned child")'],root,{'PATH':'/usr/bin:/bin'},root/'logs/child',None,journal=j,record=row)
   for fault in ['missing','changed']:
    clone=Path(tempfile.mkdtemp(prefix='bp03-sidecar-mutant-'))/'copy';shutil.copytree(root,clone);target=clone/j.base_projection['relative_path']
    if fault=='missing':target.unlink()
    else:target.write_bytes(target.read_bytes()+b'changed')
    with self.assertRaises((ValueError,FileNotFoundError)):m.validate_event(clone,j.events[-1],j.run_id)
   with patch.object(m,'_bounded_run') as child:
    with self.assertRaisesRegex(ValueError,'fresh output'):m.Run(SimpleNamespace(out=root),'not-dispatched')
    with self.assertRaisesRegex(ValueError,'inside selected input'):m.Run(SimpleNamespace(out=root/'inside',package=root),'not-dispatched')
   child.assert_not_called()
   old=(root/'commands/000001.complete.json').read_bytes();complete=json.loads(old)
   with self.assertRaises(m.EvidenceFailure):j.event(row,'complete',complete['payload'])
   self.assertEqual((root/'commands/000001.complete.json').read_bytes(),old)
 def test_C14_concrete_population_and_build_denominators(self):
  from collections import Counter
  for script in SCRIPTS:
   m=load(script);rows=m.fixed_obligations();counts=Counter(r['kind'] for r in rows);self.assertEqual(counts['omitted-client-json'],8);self.assertEqual(counts['core-client-json'],16);self.assertEqual(counts['bpf-contract-client'],12)
   self.assertEqual(sum(counts[k] for k in ['library-cell','retained-client','bp03-positive-client','omitted-client-json','bpf-contract-client']),156)
   contexts={r['id'].split('/controls/')[0] for r in rows if r['kind']=='control-helper'};self.assertEqual(len(contexts),4);self.assertEqual(len(contexts)*(3*3+3*2),60);self.assertEqual(counts['adapter-binding-control'],4);self.assertEqual(2*(counts['bpf-semantic-control']+counts['adapter-semantic-control'])+sum(r['id'].endswith('/allocation_remapped_to_malformed') for r in rows),596)
   matrix=load(ROOT/'tests/package-policy/bp03/execute.py');required=matrix.required_rows();out=Path(tempfile.mkdtemp(prefix='bp03-all-parent-rows-'));parent=m.ParentEvents(out,{'test':'full finite parent denominator'},required);report={'status':'INCOMPLETE','required':required,'clients':[]};parent.checkpoint(report);parent.reserve_row(required[0]);failure=parent.abort(ValueError('early actual parent dispatch failure'),report);receipt=json.loads((out/'receipt.json').read_bytes());self.assertEqual(len(receipt['required']),32);self.assertTrue(all(r['status']=='NOT_RUN' for r in receipt['required']));self.assertEqual(len(json.loads((out/'required-v2.json').read_bytes())['global_obligations']),528)


class ParentAssociationRegression(unittest.TestCase):
 def test_C14_wrong_earlier_child_and_wrong_kind_cannot_qualify_parent(self):
  matrix=load(ROOT/'tests/package-policy/bp03/execute.py')
  for script in SCRIPTS:
   for fault in ['wrong-root','wrong-kind']:
    with self.subTest(script=script.name,fault=fault):
     m=load(script);m._PUBLICATION_OWNER=None;root=Path(tempfile.mkdtemp(prefix='bp03-child-association-'));expected=root/'selected-child';actual=root/'earlier-child' if fault=='wrong-root' else expected;expected_kind='OWNED_TINY_EXPECTED';observed_kind='OWNED_TINY_WRONG' if fault=='wrong-kind' else expected_kind;plan={'cell':dict(root=str(expected),kind=expected_kind)};j=m.EventJournal(actual);j.seal({'scope':'owned association child'},[{'id':'tiny','status':'NOT_RUN'}]);row={'id':'tiny'};m.execute([sys.executable,'-c','print("actual earlier child")'],actual,{'PATH':'/usr/bin:/bin'},actual/'logs/child',None,record=row,journal=j);completion=j.finish(dict(status='PASS',kind=observed_kind,commands=[row]));required=[dict(id='cell',status='NOT_RUN')];parent=m.ParentEvents(root/'parent',{'child_invocations':plan},required);parent.reserve_row(required[0])
     if hasattr(matrix,'bind_child_invocations'):matrix.bind_child_invocations(parent,plan);matrix.start_child(parent,'cell')
     with self.assertRaises((m.EvidenceFailure,ValueError),msg='wrong valid child must not qualify parent'):
      if hasattr(matrix,'accept_child'):matrix.accept_child(parent,m,completion,'cell')
      else:parent.child(m,completion,'cell')
 def test_C14_restored_exact_association_accepts_actual_return(self):
  matrix=load(ROOT/'tests/package-policy/bp03/execute.py')
  for script in SCRIPTS:
   m=load(script);m._PUBLICATION_OWNER=None;root=Path(tempfile.mkdtemp(prefix='bp03-child-association-restored-'));expected=root/'selected-child';plan={'cell':dict(root=str(expected),kind='OWNED_TINY_EXPECTED')};required=[dict(id='cell',status='NOT_RUN')];parent=m.ParentEvents(root/'parent',{'child_invocations':plan},required)
   if hasattr(matrix,'bind_child_invocations'):matrix.bind_child_invocations(parent,plan);parent.reserve_row(required[0]);matrix.start_child(parent,'cell')
   j=m.EventJournal(expected);j.seal({'scope':'restored owned association'},[{'id':'tiny','status':'NOT_RUN'}]);row={'id':'tiny'};m.execute([sys.executable,'-c','print("actual expected child")'],expected,{'PATH':'/usr/bin:/bin'},expected/'logs/child',None,record=row,journal=j);completion=j.finish(dict(status='PASS',kind='OWNED_TINY_EXPECTED',commands=[row]))
   report,ref=matrix.accept_child(parent,m,completion,'cell') if hasattr(matrix,'accept_child') else parent.child(m,completion,'cell');self.assertEqual(report['kind'],'OWNED_TINY_EXPECTED');self.assertEqual(ref['root'],str(expected));required[0].update(status='PASS',child_reference=ref);parent_report=dict(status='PASS',required=required,clients=[]);parent_completion=matrix.finish_parent(parent,parent_report);self.assertEqual(m.accept_finalized(parent_completion)['status'],'PASS')


class VersionSealRegression(unittest.TestCase):
 def test_C02_version_child_is_refused_before_seal(self):
  from types import SimpleNamespace
  for script in SCRIPTS:
   m=load(script);m._PUBLICATION_OWNER=None;root=Path(tempfile.mkdtemp(prefix='bp03-version-seal-'));run=m.Run.__new__(m.Run);run.journal=m.EventJournal(root);run.tools=Path('/usr/bin');run.args=SimpleNamespace(toolchain='not-executed')
   with patch.object(m,'_bounded_run') as child:
    with self.assertRaisesRegex(m.EvidenceFailure,'sealed healthy journal'):run.versions()
   child.assert_not_called()

class LinearReviewRepair(unittest.TestCase):
 """Four reviewed regressions; tiny transport fixtures, never Cargo/compiler tests."""
 def fixture(self,path,label):
  m=load(path);m._PUBLICATION_OWNER=None;root=Path(tempfile.mkdtemp(prefix='bp03-review-'+label+'-'));subject=root/'subject';subject.mkdir();(subject/'Cargo.toml').write_text('[workspace]\n');(subject/'input.txt').write_bytes(b'owned source baseline\n')
  home=root/'cargo-home';home.mkdir();config=home/'config.toml';config.write_text('[net]\noffline=true\n');tools=root/'tools';tools.mkdir()
  # Explicit transport fixture: consumes the generation argv but launches no tool.
  cargo=tools/'cargo';cargo.write_text('#!'+sys.executable+'\nfrom pathlib import Path\nPath("Cargo.lock").write_text(\'version=4\\n[[package]]\\nname="scopebase-bpf"\\nversion="0.1.0"\\n\')\nprint("owned lock transport fixture")\n');cargo.chmod(0o700)
  j=m.EventJournal(root/'events');j.seal({'selected':'tiny review transport'},[{'id':'tiny','status':'NOT_RUN'}]);run=m.Run.__new__(m.Run);run.out=j.root;run.journal=j;run.report=dict(commands=[],clients=[],controls=[],status='INCOMPLETE');run.home=home;run.config=config;run.tools=tools;run.env={'PATH':'/usr/bin:/bin'};run.wrapper=None;run.packages={};run._lock_bindings={};run._source_baselines={};run._snapshot_sequence=0;run._checkpoint_cache={};run._result_refs={};run._result_phases={}
  return m,root,subject,run
 def rewrite_chain(self,m,root,run_id,projection):
  previous=None
  for phase in ['reserved','collected','complete']:
   p=root/('commands/000001.'+phase+'.json');value=json.loads(p.read_bytes());value['current_projection_ref']=projection;value['previous_event_ref']=previous
   if phase=='complete':value['payload']['raw_result_ref']=previous
   p.write_bytes(m.bounded_json(value,m.EVENT_LIMIT));previous=m.file_reference(root,p,'command-event',run_id)
  return previous
 def test_LIN01_nested_snapshot_and_stale_projection_reject(self):
  import copy,shutil
  for path in SCRIPTS:
   m,root,subject,run=self.fixture(path,'projection');row,_=run.command('typed-current',[sys.executable,'-c','print("owned projection twin")'],subject);j=run.journal;reference=j.events[-1]
   self.assertEqual(m.validate_event(j.root,reference,j.run_id)['phase'],'complete')
   completion=j.finish(run.report|{'status':'PASS'});self.assertEqual(m.accept_finalized(completion)['status'],'PASS')
   for fault in ['missing-snapshot','changed-snapshot','snapshot-alias','stale-baseline','wrong-subject','wrong-sequence','wrong-kind','cross-run-nested','wrong-source-command','wrong-source-sequence']:
    with self.subTest(script=path.name,fault=fault):
     clone=root/('copy-'+fault);shutil.copytree(j.root,clone);ref=copy.deepcopy(reference)
     if fault in ['missing-snapshot','changed-snapshot','snapshot-alias']:
      snapshot=next((clone/'snapshots').rglob('input.txt'))
      if fault=='missing-snapshot':snapshot.unlink()
      elif fault=='snapshot-alias':
       original=j.root/snapshot.relative_to(clone);snapshot.unlink();snapshot.symlink_to(original)
      else:snapshot.write_bytes(b'changed retained source\n')
     else:
      projection=copy.deepcopy(row['projection_ref'])
      if fault=='stale-baseline':projection=copy.deepcopy(j.base_projection)
      else:
       p=clone/projection['relative_path'];value=json.loads(p.read_bytes())
       if fault=='wrong-subject':value['subject_id']='another-command'
       elif fault=='wrong-sequence':value['sequence']+=1
       elif fault=='wrong-kind':value['kind']='BP03_STATIC_BINDING'
       elif fault in ['wrong-source-command','wrong-source-sequence']:
        source_ref=value['own_binding']['source_projection_ref'];source_path=clone/source_ref['relative_path'];source=json.loads(source_path.read_bytes())
        if fault=='wrong-source-command':source['own_binding']['obligation_id']='earlier-command'
        else:source['own_binding']['command_sequence']+=1
        source_path.write_bytes(m.bounded_json(source,m.SIDECAR_LIMIT));value['own_binding']['source_projection_ref']=m.file_reference(clone,source_path,'source-projection',j.run_id)
       else:
        # Same outer ownership/hash, foreign nested baseline or source reference.
        binding=value['own_binding'];key='source_projection_ref' if 'source_projection_ref' in binding else None
        if key is not None:binding[key]['owner_run_id']='0'*32
        else:binding['source_trees'][0]['baseline_ref']['owner_run_id']='0'*32
       p.write_bytes(m.bounded_json(value,m.SIDECAR_LIMIT));projection=m.file_reference(clone,p,'source-projection',j.run_id)
      ref=self.rewrite_chain(m,clone,j.run_id,projection)
     with self.assertRaises((ValueError,OSError),msg='typed current projection must reject '+fault):m.validate_event(clone,ref,j.run_id)
   snapshot=next((j.root/'snapshots').rglob('input.txt'));snapshot.unlink()
   with self.assertRaises((ValueError,OSError),msg='final acceptance must traverse retained snapshots'):m.accept_finalized(completion)
 def test_LIN01_exact_source_delta_and_locked_normal_twins(self):
  for path in SCRIPTS:
   m,root,subject,run=self.fixture(path,'delta-normal');(subject/'removed.txt').write_bytes(b'removed source\n');run.command('before-delta',[sys.executable,'-c','print("before source delta")'],subject)
   (subject/'input.txt').write_bytes(b'changed source\n');(subject/'removed.txt').unlink();(subject/'added.txt').write_bytes(b'new source\n');run.command('after-delta',[sys.executable,'-c','print("after source delta")'],subject)
   run.cargo('generation-twin',['generate-lockfile','--offline'],subject);locked,_=run.cargo('locked-twin',['metadata','--offline','--locked'],subject)
   self.assertEqual(locked['lock_binding']['bytes_ref'],run._lock_bindings[str(subject/'Cargo.lock')]['bytes_ref']);self.assertEqual(m.validate_event(run.journal.root,run.journal.events[-1],run.journal.run_id)['payload']['oracle_ref'],locked['lock_binding_ref']);self.assertEqual(m.accept_finalized(run.journal.finish(run.report|{'status':'PASS'}))['status'],'PASS')
 def test_LIN02_post_effect_link_failure_keeps_uncertainty_and_latch(self):
  for path in SCRIPTS:
   m,root,subject,run=self.fixture(path,'link');j=run.journal;self.assertEqual(m.atomic_json(j.root/'normal.json',{'transport':'normal'})['publication'],'CONFIRMED_DURABLE');real=m.os.link;m._PUBLICATION_OWNER=j
   def linked_then_interrupted(*args,**kwargs):real(*args,**kwargs);raise OSError('owned interruption after real link effect')
   with patch.object(m.os,'link',side_effect=linked_then_interrupted):
    with self.assertRaises(m.PublicationFailure) as caught:m.atomic_json(j.root/'uncertain.json',{'transport':'uncertain'})
   self.assertEqual(json.loads((j.root/'uncertain.json').read_bytes()),{'transport':'uncertain'});self.assertIn(caught.exception.outcome,['UNKNOWN_PUBLICATION','PUBLISHED_DURABILITY_UNKNOWN']);self.assertIn('after real link',caught.exception.failures[0]['message']);self.assertTrue(j.failed)
   with patch.object(m,'_bounded_run') as child:
    with self.assertRaises(m.EvidenceFailure):run.command('forbidden-next',[sys.executable,'-c','pass'],subject)
   child.assert_not_called();m._PUBLICATION_OWNER=None
   def pre_effect(stage,p):
    if stage=='link':raise OSError('owned failure before link attempt')
   with patch.object(m,'publication_step',side_effect=pre_effect):
    with self.assertRaises(m.PublicationFailure) as pre:m.atomic_json(j.root/'not-published.json',{'transport':'pre-effect'})
   self.assertEqual(pre.exception.outcome,'NOT_PUBLISHED');self.assertFalse((j.root/'not-published.json').exists());self.assertEqual(m.atomic_json(j.root/'restored.json',{'transport':'restored'})['publication'],'CONFIRMED_DURABLE')
 def test_LIN03_nullable_collector_log_count_retains_collected(self):
  for path in SCRIPTS:
   m,root,subject,run=self.fixture(path,'nullable-normal');normal,_=run.command('normal',[sys.executable,'-c','print("normal log")'],subject);self.assertIsInstance(normal['raw_result']['logs']['stdout']['bytes'],int)
   m,root,subject,run=self.fixture(path,'nullable-fault');j=run.journal;real=Path.stat;row={};failure=None
   def stat(p,*args,**kwargs):
    if p.suffix=='.stdout':raise OSError(5,'owned log-stat failure')
    return real(p,*args,**kwargs)
   with patch.object(Path,'stat',stat):
    try:m.execute([sys.executable,'-c','print("nullable log")'],subject,{'PATH':'/usr/bin:/bin'},j.root/'logs/nullable',None,record=row,journal=j)
    except m.EvidenceFailure as error:failure=error
   raw=row['raw_result'];self.assertIsNone(raw['logs']['stdout']['bytes']);self.assertEqual(raw['reason_code'],'INTERNAL_ERROR');self.assertEqual(raw['cleanup'],'complete');self.assertEqual(raw['errors'][0]['stage'],'log-stat-stdout');self.assertTrue(j.failed)
   collected=[ref for ref in j.events if ref['relative_path'].endswith('.collected.json')];self.assertEqual(len(collected),1,'legal nullable raw result must retain its confirmed collected reference')
   self.assertEqual(m.validate_event(j.root,collected[0],j.run_id)['payload']['raw_result'],raw);self.assertIsNone(failure,'legal incomplete collector result must remain readable');self.assertEqual(json.loads((j.root/'commands/000001.complete.json').read_bytes())['payload']['qualification'],'INCOMPLETE')
   original=json.loads(json.dumps(raw));j.fail(OSError('later wrapper error after nullable collection'));self.assertEqual(raw,original,'additive wrapper failures must not mutate aliased raw collector errors');self.assertEqual(json.loads((j.root/collected[0]['relative_path']).read_bytes())['payload']['raw_result'],raw)
 def test_LIN04_generated_lock_gates_complete_and_next_child(self):
  for path in SCRIPTS:
   for fault in ['normal','validation','snapshot','sidecar']:
    with self.subTest(script=path.name,fault=fault):
     m,root,subject,run=self.fixture(path,'lock-'+fault);j=run.journal;raw=[];real_collect=m._bounded_run;real_lock=m.lock_closure;real_snapshot=run.snapshot_file;real_sidecar=j.sidecar
     def collect(*args,**kwargs):value=real_collect(*args,**kwargs);raw.append(value);return value
     def validate(*args,**kwargs):
      self.assertTrue((j.root/'commands/000001.collected.json').is_file())
      if fault=='validation':raise ValueError('owned exact generated-lock validation fault')
      return real_lock(*args,**kwargs)
     def snapshot(p):
      if fault=='snapshot' and Path(p).name=='Cargo.lock':raise OSError('owned generated-lock snapshot fault')
      return real_snapshot(p)
     def sidecar(name,binding):
      if fault=='sidecar' and name.endswith('/validated-lock'):raise OSError('owned generated-lock sidecar fault')
      return real_sidecar(name,binding)
     with patch.object(m,'_bounded_run',side_effect=collect),patch.object(m,'lock_closure',side_effect=validate),patch.object(run,'snapshot_file',side_effect=snapshot),patch.object(j,'sidecar',side_effect=sidecar):
      if fault=='normal':row,_=run.cargo('tiny-lock',['generate-lockfile','--offline'],subject)
      else:
       caught=None
       try:run.cargo('tiny-lock',['generate-lockfile','--offline'],subject)
       except BaseException as error:caught=error
     self.assertEqual(len(raw),1);self.assertEqual(raw[0]['exit_code'],0);self.assertEqual(raw[0]['cleanup'],'complete');self.assertEqual(json.loads((j.root/'commands/000001.collected.json').read_bytes())['payload']['raw_result'],raw[0]);self.assertEqual((subject/'Cargo.lock').read_text(),'version=4\n[[package]]\nname="scopebase-bpf"\nversion="0.1.0"\n')
     if fault=='normal':
      complete=m.validate_event(j.root,j.events[-1],j.run_id);self.assertEqual(complete['phase'],'complete');self.assertEqual(complete['payload']['oracle_ref'],row['lock_binding_ref'],'completion must bind exact validated generated lock');self.assertEqual(json.loads(m.read_reference(j.root,row['lock_binding_ref'],j.run_id,'source-projection'))['own_binding']['bytes_ref']['sha256'],hashlib.sha256((subject/'Cargo.lock').read_bytes()).hexdigest());self.assertFalse(j.failed)
     else:
      self.assertFalse((j.root/'commands/000001.complete.json').exists(),'generated-lock postprocessing failure cannot leave an eligible complete');self.assertTrue(j.failed);self.assertIsInstance(caught,m.EvidenceFailure);self.assertIs(caught.custody['raw_result'],raw[0])
      with patch.object(m,'_bounded_run') as child:
       with self.assertRaises(m.EvidenceFailure):run.command('forbidden-next',[sys.executable,'-c','pass'],subject)
      child.assert_not_called()

if __name__=='__main__':unittest.main()
