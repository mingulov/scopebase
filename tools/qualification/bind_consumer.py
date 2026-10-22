#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded post-link measurement; no Cargo, fetch, qualification or authority.

Expected and build-record envelopes are independently supplied. build_inputs has
exactly the canonical recipe documented in the TT02 contract; source mappings
are retained SB02 original-source/archive records, not a second directory hash.
"""
from __future__ import annotations
import argparse,hashlib,json,os,pathlib,re,stat
MAX_INPUT=8_388_608
DIGEST=re.compile(r'[0-9a-f]{64}\Z')
class BindingError(ValueError):pass

def pairs(items):
 out={}
 for k,v in items:
  if k in out:raise BindingError('Duplicate: '+k)
  out[k]=v
 return out

def reject_float(_):raise BindingError('InvalidInput: float')
def decode(data):
 if len(data)>MAX_INPUT:raise BindingError('LimitExceeded: input_bytes')
 try:obj=json.loads(data.decode('utf-8'),object_pairs_hook=pairs,parse_float=reject_float,parse_constant=reject_float)
 except (ValueError,UnicodeError,RecursionError) as e:raise BindingError('InvalidInput: '+str(e)) from e
 edges=0
 def visit(x,depth):
  nonlocal edges
  if depth>32:raise BindingError('LimitExceeded: json_depth')
  if isinstance(x,str):
   try:x.encode('utf-8')
   except UnicodeError:raise BindingError('InvalidInput: surrogate') from None
  if isinstance(x,dict):
   edges+=len(x)
   for k,v in x.items():visit(k,depth+1);visit(v,depth+1)
  if isinstance(x,list):
   edges+=len(x)
   for v in x:visit(v,depth+1)
  if edges>262_144:raise BindingError('LimitExceeded: json_edges')
 visit(obj,0)
 return obj

def exact(obj,keys):
 if not isinstance(obj,dict) or set(obj)!=set(keys):raise BindingError('InvalidInput: fields '+','.join(keys))
 return obj

def digest(x):
 if not isinstance(x,str) or not DIGEST.fullmatch(x):raise BindingError('InvalidDigest')
 return x

def decimal(x):
 if not isinstance(x,str) or not re.fullmatch(r'0|[1-9][0-9]*',x) or int(x)>2**64-1:raise BindingError('InvalidInput: decimal')
 return int(x)

def path_descriptor(x):
 if not isinstance(x,str) or not x or '\0' in x or len(x.encode('utf-8'))>4096:raise BindingError('InvalidInput: artifact path')

def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('utf-8')

def read_input(path):
 with open(path,'rb') as f:data=f.read(MAX_INPUT+1)
 return decode(data),hashlib.sha256(data).hexdigest()

class Meter:
 def __init__(self,file_bytes=268_435_456,total_bytes=1_073_741_824,read_calls=65_536,attempts=4096):
  if not 0<file_bytes<=1_073_741_824 or not file_bytes+1<=total_bytes<=4_294_967_296 or not 0<read_calls<=262_144 or not 0<attempts<=4096:raise BindingError('LimitExceeded: configuration')
  self.file_bytes=file_bytes;self.total_bytes=total_bytes;self.max_calls=read_calls;self.max_attempts=attempts
  self.attempts=self.reserved_bytes=self.bytes_returned=self.bytes_hashed=self.read_calls=0;self.last=None
 def measure(self,path,length,expected=None):
  if type(length)is not int or length<0:raise BindingError('InvalidInput: length')
  if expected is not None:digest(expected)
  if length>self.file_bytes:raise BindingError('LimitExceeded: file_bytes')
  self.attempts+=1
  self.last={'expected_length':str(length),'bytes_returned':'0','read_calls':'0'}
  if self.attempts>self.max_attempts or length>self.file_bytes or self.reserved_bytes+length+1>self.total_bytes:raise BindingError('LimitExceeded: measurement')
  self.reserved_bytes+=length+1
  # Open once, positional reads; never reuse an executable-sized byte buffer.
  fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC)
  try:
   md=os.fstat(fd)
   if not stat.S_ISREG(md.st_mode):raise BindingError('NotRegular')
   if md.st_size!=length:raise BindingError('LengthMismatch')
   h=hashlib.sha256();offset=0
   while True:
    if self.read_calls>=self.max_calls:raise BindingError('LimitExceeded: read_calls')
    self.read_calls+=1;self.last['read_calls']=str(int(self.last['read_calls'])+1)
    try:block=os.pread(fd,1 if offset==length else min(65_536,length-offset),offset)
    except InterruptedError:continue
    self.bytes_returned+=len(block);self.last['bytes_returned']=str(int(self.last['bytes_returned'])+len(block))
    if offset==length:
     if block:raise BindingError('LengthMismatch: sentinel')
     break
    if not block:raise BindingError('LengthMismatch: EOF')
    offset+=len(block);self.bytes_hashed+=len(block);h.update(block)
   md=os.fstat(fd)
   if not stat.S_ISREG(md.st_mode) or md.st_size!=length:raise BindingError('LengthMismatch: final metadata')
   actual=h.hexdigest()
   if expected is not None and actual!=expected:raise BindingError('DigestMismatch')
   return {'length':str(length),'sha256':actual}
  finally:os.close(fd)

def validate_recipe(x):
 exact(x,('schema_version','subject','generated_lock_sha256','resolved_packages','backend','host','target','compiler','compiler_arguments','linker_arguments','consumer_source_inventory_sha256'))
 if type(x['schema_version'])is not int or x['schema_version']!=1:raise BindingError('UnsupportedSchema')
 exact(x['subject'],('name','version','source_sha256','archive_sha256'))
 for k in ('source_sha256','archive_sha256'):digest(x['subject'][k])
 digest(x['generated_lock_sha256']);digest(x['consumer_source_inventory_sha256'])
 exact(x['compiler'],('rustc_sha256','cargo_sha256','rustdoc_sha256'))
 for v in x['compiler'].values():digest(v)
 for n in ('name','version'):
  if not isinstance(x['subject'][n],str) or not x['subject'][n] or len(x['subject'][n].encode())>256:raise BindingError('InvalidInput: subject')
 for n in ('host','target'):
  if not isinstance(x[n],str) or not x[n] or len(x[n].encode())>256:raise BindingError('InvalidInput: tuple')
 for n in ('compiler_arguments','linker_arguments'):
  if not isinstance(x[n],list) or len(x[n])>4096 or any(not isinstance(a,str) or '\0' in a for a in x[n]):raise BindingError('InvalidInput: arguments')
 records=x['resolved_packages']
 if not isinstance(records,list) or len(records)>4096:raise BindingError('LimitExceeded: resolved_packages')
 keys=[]
 for r in records:
  exact(r,('name','version','source','source_sha256','features'));digest(r['source_sha256'])
  if any(not isinstance(r[k],str) or not r[k] or len(r[k].encode())>256 for k in ('name','version','source')):raise BindingError('InvalidInput: package')
  if not isinstance(r['features'],list) or len(r['features'])>256 or any(not isinstance(v,str) or not v or len(v.encode())>256 for v in r['features']) or r['features']!=sorted(set(r['features'])):raise BindingError('InvalidInput: features')
  keys.append((r['name'],r['version'],r['source']))
 if keys!=sorted(set(keys)):raise BindingError('Duplicate or Unsorted: packages')
 if x['backend'] is not None:
  exact(x['backend'],('name','version','source_sha256'));digest(x['backend']['source_sha256'])
 return x

def bind(expected,record,metadata,executable,input_hashes=None):
 exact(expected,('schema_version','kind','build_inputs','consumer_name','features','artifacts'))
 exact(record,('schema_version','kind','build_inputs','source_mapping','package_sources','artifact_files','executable_length','consumer_name','build_artifact'))
 if type(expected['schema_version'])is not int or type(record['schema_version'])is not int or expected['schema_version']!=1 or record['schema_version']!=1 or expected['kind']!='tt02-expected-consumer' or record['kind']!='tt02-admitted-build':raise BindingError('UnsupportedSchema')
 for value in (expected['consumer_name'],record['consumer_name']):
  if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,255}',value):raise BindingError('InvalidInput: consumer name')
 recipe=validate_recipe(record['build_inputs']);validate_recipe(expected['build_inputs'])
 if recipe!=expected['build_inputs'] or record['consumer_name']!=expected['consumer_name']:raise BindingError('SubjectMismatch: build inputs')
 mapping=record['source_mapping'];exact(mapping,('original_source_sha256','archive_sha256','name','version','resolved_manifest_path'))
 subject=recipe['subject']
 if any(mapping[k]!=subject[k] for k in ('name','version','archive_sha256')) or mapping['original_source_sha256']!=subject['source_sha256']:raise BindingError('SubjectMismatch: original source/archive')
 if not isinstance(metadata,dict) or not isinstance(metadata.get('packages'),list) or not isinstance(metadata.get('resolve'),dict):raise BindingError('MissingArtifact: cargo metadata')
 packages={p['id']:p for p in metadata['packages']};nodes=metadata['resolve'].get('nodes',[])
 sources=record['package_sources']
 if not isinstance(sources,dict):raise BindingError('InvalidInput: package_sources')
 actual=[];subject_node=None
 for n in nodes:
  p=packages.get(n.get('id'))
  if p is None:raise BindingError('MissingArtifact: resolved package')
  # Only the actual consumer itself is outside the subject dependency recipe.
  if p['name']==record['consumer_name'] and p.get('source')is None:continue
  key=p['id'];s=sources.get(key)
  if s is None:raise BindingError('MissingArtifact: admitted package source')
  exact(s,('source','source_sha256'));digest(s['source_sha256'])
  actual.append({'name':p['name'],'version':p['version'],'source':s['source'],'source_sha256':s['source_sha256'],'features':sorted(n['features'])})
  if p.get('manifest_path')==mapping['resolved_manifest_path']:subject_node=n
 actual.sort(key=lambda r:(r['name'],r['version'],r['source']))
 if actual!=recipe['resolved_packages']:raise BindingError('SubjectMismatch: resolved features/source')
 if subject_node is None or sorted(subject_node['features'])!=expected['features']:raise BindingError('SubjectMismatch: subject features')
 if not isinstance(executable,(str,os.PathLike)):raise BindingError('MissingArtifact: actual executable')
 if not isinstance(expected['features'],list) or any(not isinstance(v,str) or not v or len(v.encode())>256 for v in expected['features']) or expected['features']!=sorted(set(expected['features'])):raise BindingError('InvalidInput: subject features')
 if not isinstance(expected['artifacts'],list) or any(not isinstance(a,dict) for a in expected['artifacts']):raise BindingError('InvalidInput: artifacts')
 ids=[a.get('id') for a in expected['artifacts']]
 if any(not isinstance(i,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}',i) for i in ids):raise BindingError('InvalidInput: artifact ID')
 if len(ids)>4095 or ids!=sorted(set(ids)):raise BindingError('Duplicate or Unsorted: artifacts')
 # Preflight the complete inventory, including the final executable, before
 # opening any member. A later malformed descriptor must not consume early I/O.
 if not isinstance(record['artifact_files'],dict) or record['artifact_files'].keys()!= {a['id'] for a in expected['artifacts']}:raise BindingError('MissingArtifact: file inventory')
 for value in record['artifact_files'].values():path_descriptor(value)
 for a in expected['artifacts']:
  exact(a,('id','revision','role','length','sha256'))
  if type(a['revision'])is not int or not 0<a['revision']<=4294967295 or a['role'] not in ('subject_archive','consumer_executable','case_source','oracle_source','control_source','fixture_manifest','fixture_input','expected_vector','fixture_ledger','worker_executable','final_object','source_terms','elf_license_bytes','loader_license_bytes'):raise BindingError('InvalidInput: artifact revision/role')
  digest(a['sha256']);length=decimal(a['length'])
  if length>268_435_456 or a['role'] in ('fixture_input','expected_vector','fixture_ledger') and length>8_388_608:raise BindingError('LimitExceeded: artifact length')
 artifact=record['build_artifact'];exact(artifact,('package_id','target_name','executable','sha256'))
 path_descriptor(artifact['executable']);path_descriptor(os.fspath(executable))
 digest(artifact['sha256']);executable_length=decimal(record['executable_length'])
 if executable_length>268_435_456:raise BindingError('LimitExceeded: executable length')
 client=packages.get(artifact['package_id'])
 if client is None or client['name']!=record['consumer_name'] or artifact['target_name']!=record['consumer_name'] or pathlib.Path(artifact['executable']).resolve()!=pathlib.Path(executable).resolve():raise BindingError('SubjectMismatch: actual build executable')
 selected=[a for a in expected['artifacts'] if a['role'] in ('case_source','oracle_source','control_source')]
 if selected:
  roles={a['role'] for a in expected['artifacts']}
  if not {'case_source','oracle_source','control_source','fixture_manifest'}<=roles:raise BindingError('MissingArtifact: selected source inventory')
  targets=client.get('targets',[])
  paths={pathlib.Path(t['src_path']).resolve() for t in targets if t.get('name')==artifact['target_name'] and 'bin' in t.get('kind',[]) and isinstance(t.get('src_path'),str)}
  # These TT02 reference consumers implement their selected case, oracle and
  # active control inline in the actual Cargo binary target. Source hashes are
  # frozen before compilation; an unused packaged implementation is not a member.
  if len(paths)!=1 or any(pathlib.Path(record['artifact_files'][a['id']]).resolve() not in paths for a in selected):raise BindingError('SubjectMismatch: selected source-to-build')
 meter=Meter();artifacts=[]
 for a in expected['artifacts']:
  measurement=meter.measure(record['artifact_files'][a['id']],decimal(a['length']),a['sha256']);artifacts.append(dict(a,**measurement))
 measured=meter.measure(executable,executable_length,artifact['sha256'])
 build_hash=hashlib.sha256(canonical(recipe)).hexdigest()
 manifest={'schema_version':1,'kind':'tt02-generated-measurement','build_inputs_sha256':build_hash,'input_sha256':input_hashes or {},'subject':{'package_name':subject['name'],'package_version':subject['version'],'source_sha256':subject['source_sha256'],'build_inputs_sha256':build_hash,'features':expected['features'],'backend':recipe['backend'],'host':recipe['host'],'target':recipe['target'],'consumer':{'name':record['consumer_name'],'build_inputs_sha256':build_hash,'executable_sha256':measured['sha256']},'objects':sorted(artifacts,key=lambda a:a['id'])},'executable':measured,'artifacts':artifacts,'measurement_usage':{'attempts':str(meter.attempts),'reserved_bytes':str(meter.reserved_bytes),'bytes_returned':str(meter.bytes_returned),'bytes_hashed':str(meter.bytes_hashed),'read_calls':str(meter.read_calls)}}
 if len(canonical(manifest))>MAX_INPUT:raise BindingError('LimitExceeded: output')
 return manifest

def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument('--expected',required=True);p.add_argument('--build-record',required=True);p.add_argument('--metadata',required=True);p.add_argument('--executable',required=True);p.add_argument('--output',required=True);a=p.parse_args(argv)
 expected,eh=read_input(a.expected);record,rh=read_input(a.build_record);metadata,mh=read_input(a.metadata)
 result=bind(expected,record,metadata,a.executable,{'expected':eh,'build_record':rh,'metadata':mh})
 payload=canonical(result)
 # Hash generated manifest once; its digest is the external measurement identity.
 manifest_sha=hashlib.sha256(payload).hexdigest()
 with open(a.output,'xb') as f:f.write(payload)
 os.chmod(a.output,0o444)
 print(json.dumps({'output':a.output,'measurement_sha256':manifest_sha}))
if __name__=='__main__':main()
