# SPDX-License-Identifier: Apache-2.0
import importlib.util,pathlib,tempfile,hashlib,json,unittest
from unittest import mock
spec=importlib.util.spec_from_file_location('bind_consumer',pathlib.Path(__file__).parents[1]/'bind_consumer.py')
b=importlib.util.module_from_spec(spec)
class BindingTests(unittest.TestCase):
 def test_review_a5_invalid_digest_is_zero_io(self):
  spec.loader.exec_module(b)
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'binary';p.write_bytes(b'abc');m=b.Meter()
   with mock.patch.object(b.os,'open',wraps=b.os.open) as opened, mock.patch.object(b.os,'pread',wraps=b.os.pread) as reads:
    with self.assertRaisesRegex(b.BindingError,'InvalidDigest'):m.measure(p,3,'bad-digest')
    self.assertEqual(opened.call_count,0,'invalid descriptor must precede all file I/O')
    self.assertEqual(reads.call_count,0)
   self.assertEqual((m.attempts,m.reserved_bytes,m.bytes_hashed,m.read_calls),(0,0,0,0))
   self.assertEqual(m.measure(p,3,hashlib.sha256(b'abc').hexdigest())['length'],'3')
   with self.assertRaisesRegex(b.BindingError,'DigestMismatch'):m.measure(p,3,'0'*64)
   self.assertEqual((m.attempts,m.reserved_bytes,m.bytes_hashed,m.read_calls),(2,8,6,4))
   failed=b.Meter()
   with self.assertRaises(FileNotFoundError):failed.measure(pathlib.Path(d)/'absent',3,hashlib.sha256(b'abc').hexdigest())
   self.assertEqual((failed.attempts,failed.reserved_bytes,failed.bytes_hashed,failed.read_calls),(1,4,0,0))
 def test_known_digest_and_budget(self):
  spec.loader.exec_module(b)
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'binary';p.write_bytes(b'abc')
   m=b.Meter(file_bytes=3,total_bytes=8,read_calls=8,attempts=8)
   self.assertEqual(m.measure(p,3,'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')['length'],'3')
   with self.assertRaisesRegex(b.BindingError,'DigestMismatch'):m.measure(p,3,'0'*64)
   self.assertEqual(m.reserved_bytes,8)
   with self.assertRaisesRegex(b.BindingError,'LimitExceeded'):m.measure(p,3,'0'*64)
 def test_strict_input(self):
  spec.loader.exec_module(b)
  with self.assertRaises(b.BindingError):b.decode(b'{"x":1,"x":2}')
  with self.assertRaises(b.BindingError):b.decode(b'{"x":1.2}')
 def test_bound_actual_records_and_swaps(self):
  spec.loader.exec_module(b)
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);archive=p/'subject.crate';archive.write_bytes(b'archive-A');exe=p/'client';exe.write_bytes(b'abc');other=p/'other';other.write_bytes(b'abd')
   sha=lambda x:hashlib.sha256(x).hexdigest()
   subject={'name':'subject','version':'0.1.0','source_sha256':sha(b'original inventory A'),'archive_sha256':sha(archive.read_bytes())}
   package={'id':'subject-id','name':'subject','version':'0.1.0','source':None,'manifest_path':str(p/'subject/Cargo.toml')}
   client={'id':'client-id','name':'client','version':'0.1.0','source':None,'manifest_path':str(p/'client/Cargo.toml')}
   metadata={'packages':[package,client],'resolve':{'nodes':[{'id':'subject-id','features':[]},{'id':'client-id','features':[]}]}}
   resolved=[{'name':'subject','version':'0.1.0','source':'fixture:subject','source_sha256':subject['source_sha256'],'features':[]}]
   recipe={'schema_version':1,'subject':subject,'generated_lock_sha256':sha(b'lock'),'resolved_packages':resolved,'backend':None,'host':'x86_64-unknown-linux-gnu','target':'x86_64-unknown-linux-gnu','compiler':{n+'_sha256':sha(n.encode())for n in ['rustc','cargo','rustdoc']},'compiler_arguments':[],'linker_arguments':[],'consumer_source_inventory_sha256':sha(b'client source')}
   artifact={'id':'archive','revision':1,'role':'subject_archive','length':'9','sha256':subject['archive_sha256']}
   expected={'schema_version':1,'kind':'tt02-expected-consumer','build_inputs':recipe,'consumer_name':'client','features':[],'artifacts':[artifact]}
   record={'schema_version':1,'kind':'tt02-admitted-build','build_inputs':recipe,'source_mapping':{'original_source_sha256':subject['source_sha256'],'archive_sha256':subject['archive_sha256'],'name':'subject','version':'0.1.0','resolved_manifest_path':package['manifest_path']},'package_sources':{'subject-id':{'source':'fixture:subject','source_sha256':subject['source_sha256']}},'artifact_files':{'archive':str(archive)},'executable_length':'3','consumer_name':'client','build_artifact':{'package_id':'client-id','target_name':'client','executable':str(exe),'sha256':sha(b'abc')}}
   good=b.bind(expected,record,metadata,exe);self.assertEqual(good['executable']['sha256'],'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
   with self.assertRaisesRegex(b.BindingError,'actual build executable'):b.bind(expected,record,metadata,other)
   exe.write_bytes(b'abd')
   with self.assertRaisesRegex(b.BindingError,'DigestMismatch'):b.bind(expected,record,metadata,exe)
   exe.write_bytes(b'abc');metadata['resolve']['nodes'][0]['features']=['json']
   with self.assertRaisesRegex(b.BindingError,'resolved features'):b.bind(expected,record,metadata,exe)
   metadata['resolve']['nodes'][0]['features']=[];self.assertEqual(b.bind(expected,record,metadata,exe)['executable'],good['executable'])
   # All descriptors are checked before even the first valid archive read.
   for descriptor in [artifact,record['build_artifact']]:
    saved=descriptor['sha256'];descriptor['sha256']='bad-digest'
    with mock.patch.object(b.os,'open',wraps=b.os.open) as opened:
     with self.assertRaisesRegex(b.BindingError,'InvalidDigest'):b.bind(expected,record,metadata,exe)
     self.assertEqual(opened.call_count,0)
    descriptor['sha256']=saved
   bad_path={'id':'zz-bad-path','revision':1,'role':'final_object','length':'0','sha256':sha(b'')};expected['artifacts'].append(bad_path);record['artifact_files']['zz-bad-path']='bad\0path'
   with mock.patch.object(b.os,'open',wraps=b.os.open) as opened:
    with self.assertRaises(ValueError):b.bind(expected,record,metadata,exe)
    self.assertEqual(opened.call_count,0,'invalid descriptor path must precede all file I/O')
   expected['artifacts'].pop();del record['artifact_files']['zz-bad-path'];b.bind(expected,record,metadata,exe)
   # Selected inline sources are actual Cargo target members, rather than
   # unused package files that merely have well-formed, correct digests.
   main=p/'client-source/src/main.rs';main.parent.mkdir(parents=True);main.write_bytes(b'fn main() {}\n');other_source=p/'unused.rs';other_source.write_bytes(b'fn main() {println!("unused");}\n');fixture=p/'bundle.json';fixture.write_bytes(b'{"kind":"tt02-vector-bundle"}')
   client['targets']=[{'name':'client','kind':['bin'],'src_path':str(main)}]
   for identity,role,path in [('case-source','case_source',main),('oracle-source','oracle_source',main),('control-source','control_source',main),('fixture-manifest','fixture_manifest',fixture)]:
    expected['artifacts'].append({'id':identity,'revision':1,'role':role,'length':str(path.stat().st_size),'sha256':sha(path.read_bytes())});record['artifact_files'][identity]=str(path)
   expected['artifacts'].sort(key=lambda a:a['id']);b.bind(expected,record,metadata,exe)
   for identity in ['case-source','oracle-source']:
    selected=next(a for a in expected['artifacts'] if a['id']==identity);saved=selected.copy();selected.update(length=str(other_source.stat().st_size),sha256=sha(other_source.read_bytes()));record['artifact_files'][identity]=str(other_source)
    with self.assertRaisesRegex(b.BindingError,'selected source-to-build'):b.bind(expected,record,metadata,exe)
    selected.update(saved);record['artifact_files'][identity]=str(main);b.bind(expected,record,metadata,exe)
