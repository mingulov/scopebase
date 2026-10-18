#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent bounded ScopeBase catalog checker; metadata never qualifies a subject."""
from __future__ import annotations
import argparse,hashlib,json,os,re,stat,sys
from pathlib import Path

CEILINGS=dict(max_input_bytes=8388608,max_cases=4096,max_profiles=128,max_extensions=128,max_obligations=512,max_cells=256,max_edges=8192,max_string_bytes=65536,max_depth=32,max_selected_cells=16384)
FIELDS={
 'root':'schema_version catalog_revision tasks obligations families cells cases profiles extensions',
 'obligation':'kind id description owners','ref':'kind id','family':'id short_contract obligations',
 'cell':'id tier description binding','case':'id family version implementation_status owners obligations required_cells registration',
 'profile':'id definition_state requires_profiles requires_extensions required_cases open_owners',
 'extension':'id profile requires_profiles requires_tasks required_cases','required':'case_id case_version when_extensions',
 'registration':'executable fixture oracle bad_control oracle_basis control_assertion',
 'artifact':'id revision path sha256 entrypoint'}
KINDS={'research_todo','regression_family','public_contract_gap','user_conformance','overlap_row'}
ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*\Z',re.ASCII)
class CatalogInvalid(ValueError):pass
def fail(kind):raise CatalogInvalid(kind)
def exact(v,kind):
 if type(v) is not dict:fail('InvalidJson')
 keys=set(FIELDS[kind].split())
 if set(v)-keys:fail('UnknownField')
 if keys-set(v):fail('InvalidJson')
def identifier(v,profile=False):
 if type(v) is not str or len(v.encode())>(64 if profile else 96) or not ID.fullmatch(v):fail('InvalidId')
 if profile:
  m=re.fullmatch(r'(.+)-v([1-9][0-9]*)',v,re.ASCII)
  if not m or int(m[2])>4294967295:fail('InvalidVersion')
 return v
def version(v):
 if type(v) is not int or not 0<v<=4294967295:fail('InvalidVersion')
def text(v,nonempty=True):
 if type(v) is not str:fail('InvalidJson')
 if nonempty and not v:fail('InvalidDefinition')
def sequence(v,nonempty=False):
 if type(v) is not list:fail('InvalidJson')
 if nonempty and not v:fail('InvalidDefinition')
def unique(v):
 if len({json.dumps(x,sort_keys=True,separators=(',',':')) for x in v})!=len(v):fail('DuplicateId')
def pairs(items):
 out={}
 for k,v in items:
  if k in out:fail('DuplicateField')
  out[k]=v
 return out
def limits_with(overrides):
 limits=CEILINGS| (overrides or {})
 if set(limits)!=set(CEILINGS) or any(type(v) is not int or v<=0 or v>CEILINGS[k] for k,v in limits.items()):fail('InvalidLimits')
 return limits

def preflight(raw,limits):
 """Only delimiters, strings and container counts; json remains syntax authority.

 Count the next element before json's C decoder can append it. No size hint or
 unbounded container is constructed by this pass. Malformed syntax may meet a
 bound before the final grammar error; that deterministic precedence is public.
 """
 try:s=raw.decode('utf-8',errors='strict')
 except UnicodeError:fail('InvalidJson')
 stack=[];last_string=None;pending='';i=0;edges=0
 # All legal objects fit the widest declared schema object. This also bounds
 # the preflight key set; no full object pairs reach json.loads above it.
 object_cap=max(len(fields.split()) for fields in FIELDS.values())
 edge_keys={'owners','required_cells','requires_profiles','requires_extensions','required_cases','when_extensions','open_owners','requires_tasks'}
 def enter_element():
  nonlocal edges
  if stack and stack[-1]['type']=='[' and stack[-1]['next']:
   f=stack[-1];f['next']=False;f['count']+=1
   if f['count']>f['cap']:fail('LimitExceeded')
   if f['edge']:
    edges+=1
    if edges>limits['max_edges']:fail('LimitExceeded')
 while i<len(s):
  ch=s[i]
  if ch in ' \t\r\n':i+=1;continue
  if ch=='"':
   enter_element();j=i+1;escaped=False
   while j<len(s):
    if escaped:escaped=False
    elif s[j]=='\\':escaped=True
    elif s[j]=='"':break
    j+=1
   if j==len(s):break
   try:value=json.loads(s[i:j+1])
   except (ValueError,UnicodeError):fail('InvalidJson')
   try:n=len(value.encode('utf-8'))
   except UnicodeError:fail('InvalidJson')
   if n>limits['max_string_bytes']:fail('LimitExceeded')
   if stack and stack[-1]['type']=='{' and stack[-1]['next']:
    frame=stack[-1]
    if value in frame['keys']:fail('DuplicateField')
    if frame['count']==frame['cap']:fail('UnknownField')
    frame['keys'].add(value);frame['count']+=1;frame['next']=False
   last_string=value;i=j+1;continue
  if ch==':':
   pending=last_string or ''
   if pending in ('profile','family'):
    edges+=1
    if edges>limits['max_edges']:fail('LimitExceeded')
   i+=1;continue
  if ch in '[{':
   enter_element()
   key=pending;pending=''
   cap=128 if key in ('tasks','families') else limits.get('max_'+key,limits['max_edges'])
   # Only root obligations are a population; nested obligations are edges.
   if key=='obligations' and len(stack)>1:cap=limits['max_edges']
   if ch=='{':cap=object_cap
   stack.append({'type':ch,'count':0,'cap':cap,'next':True,'keys':set(),'edge':key in edge_keys or (key=='obligations' and len(stack)>1)})
   if len(stack)>limits['max_depth']:fail('LimitExceeded')
  elif ch in ']}':
   if stack:stack.pop()
   pending=''
  elif ch==',':
   if stack:stack[-1]['next']=True
   pending=''
  else:enter_element()
  i+=1
 return s

def _validate(raw,limits=None):
 limits=limits_with(limits)
 if len(raw)>limits['max_input_bytes']:fail('InputTooLarge')
 s=preflight(raw,limits)
 try:data=json.loads(s,object_pairs_hook=pairs,parse_constant=lambda _:fail('InvalidJson'))
 except (ValueError,RecursionError) as e:
  if isinstance(e,CatalogInvalid):raise
  fail('InvalidJson')
 exact(data,'root')
 if type(data['schema_version']) is not int:fail('InvalidJson')
 if data['schema_version']!=1:fail('UnsupportedSchema')
 version(data['catalog_revision'])
 for name in ['tasks','obligations','families','cells','cases','profiles','extensions']:sequence(data[name]);unique(data[name]) if name=='tasks' else None
 for t in data['tasks']:identifier(t)
 if not data['tasks']:fail('InvalidDefinition')
 tasks=set(data['tasks'])
 def owners(values,nonempty=False):
  sequence(values,nonempty);unique(values)
  if any(type(v) is not str or v not in tasks for v in values):fail('UnknownReference')
 obligations={}
 for o in data['obligations']:
  exact(o,'obligation');identifier(o['id']);text(o['description'],False);owners(o['owners'],True)
  if type(o['kind']) is not str or o['kind'] not in KINDS:fail('InvalidDefinition')
  key=(o['kind'],o['id'])
  if key in obligations:fail('DuplicateId')
  obligations[key]=o
 def refs(values):
  sequence(values);unique(values)
  for r in values:
   exact(r,'ref')
   if type(r['kind']) is not str or type(r['id']) is not str or (r['kind'],r['id']) not in obligations:fail('UnknownReference')
 families={}
 for f in data['families']:
  exact(f,'family');identifier(f['id']);text(f['short_contract']);refs(f['obligations'])
  if {'kind':'regression_family','id':f['id']} not in f['obligations']:fail('InvalidDefinition')
  if f['id'] in families:fail('DuplicateId')
  families[f['id']]=f
 cells={}
 for cell in data['cells']:
  exact(cell,'cell');identifier(cell['id']);text(cell['description'])
  if cell['binding']!='LOGICAL_ONLY' or cell['tier'] not in ['T0','T1','T2','T3','T4','T5']:fail('InvalidDefinition')
  if cell['id'] in cells:fail('DuplicateId')
  cells[cell['id']]=cell
 def artifact(a):
  exact(a,'artifact');identifier(a['id']);identifier(a['entrypoint']);version(a['revision'])
  if type(a['path']) is not str or not a['path'] or '\\' in a['path'] or '\x00' in a['path'] or any(p in ('','.','..') for p in a['path'].split('/')):fail('InvalidRegistration')
  if type(a['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}',a['sha256']):fail('InvalidRegistration')
 cases={}
 for case in data['cases']:
  exact(case,'case');identifier(case['id']);version(case['version']);owners(case['owners'],True);refs(case['obligations']);sequence(case['required_cells'],True);unique(case['required_cells'])
  if type(case['family']) is not str or case['family'] not in families:fail('UnknownReference')
  if not case['id'].startswith(case['family']+'.'):fail('InvalidId')
  if any(type(v) is not str or v not in cells for v in case['required_cells']):fail('UnknownReference')
  key=(case['id'],case['version'])
  if key in cases:fail('DuplicateId')
  cases[key]=case
  reg=case['registration']
  if case['implementation_status']=='UNIMPLEMENTED':
   if reg is not None:fail('InvalidRegistration')
  elif case['implementation_status']=='REGISTERED_EXECUTABLE':
   if reg is None:fail('InvalidRegistration')
   try:
    exact(reg,'registration')
    for field in ['executable','fixture','oracle','bad_control']:artifact(reg[field])
   except CatalogInvalid as error:
    if str(error) in ('InvalidJson','InvalidId','InvalidDefinition'):fail('InvalidRegistration')
    raise
   text(reg['oracle_basis']);text(reg['control_assertion'])
   identity=lambda a:(a['path'],a['sha256'],a['entrypoint'])
   if any(identity(reg[k])==identity(reg['executable']) for k in ['oracle','bad_control']):fail('InvalidRegistration')
  else:fail('InvalidRegistration')
 profiles={};extensions={}
 def required(values):
  sequence(values);unique(values)
  seen=set()
  for r in values:
   exact(r,'required');identifier(r['case_id']);version(r['case_version']);sequence(r['when_extensions']);unique(r['when_extensions'])
   for e in r['when_extensions']:identifier(e,True)
   # Predicate ordering is immaterial; a duplicate declaration cannot hide by reordering.
   key=(r['case_id'],r['case_version'],tuple(sorted(r['when_extensions'])))
   if key in seen:fail('DuplicateId')
   seen.add(key)
   if (r['case_id'],r['case_version']) not in cases:fail('UnknownReference')
 for p in data['profiles']:
  exact(p,'profile');identifier(p['id'],True)
  if p['id'] in profiles:fail('DuplicateId')
  profiles[p['id']]=p
  if p['definition_state'] not in ['DRAFT','FROZEN']:fail('InvalidDefinition')
  owners(p['open_owners'],p['definition_state']=='DRAFT')
  if p['definition_state']=='FROZEN' and p['open_owners']:fail('InvalidDefinition')
  for field in ['requires_profiles','requires_extensions']:
   sequence(p[field]);unique(p[field])
   for v in p[field]:identifier(v,True)
  required(p['required_cases'])
 for e in data['extensions']:
  exact(e,'extension');identifier(e['id'],True);identifier(e['profile'],True);owners(e['requires_tasks']);sequence(e['requires_profiles']);unique(e['requires_profiles'])
  for p in e['requires_profiles']:identifier(p,True)
  required(e['required_cases'])
  if e['id'] in extensions or e['id'] in profiles:fail('DuplicateId')
  extensions[e['id']]=e
 graph={p['id']:p['requires_profiles']+p['requires_extensions'] for p in profiles.values()}|{e['id']:[e['profile']]+e['requires_profiles'] for e in extensions.values()}
 for p in profiles.values():
  if any(v not in profiles for v in p['requires_profiles']) or any(v not in extensions for v in p['requires_extensions']):fail('UnknownReference')
 for e in extensions.values():
  if e['profile'] not in profiles or any(p not in profiles for p in e['requires_profiles']):fail('UnknownReference')
 for obj in [*profiles.values(),*extensions.values()]:
  if any(v not in extensions for r in obj['required_cases'] for v in r['when_extensions']):fail('UnknownReference')
 colors={}
 for root in graph:
  todo=[(root,False)]
  while todo:
   node,exit=todo.pop()
   if exit:colors[node]=2;continue
   if colors.get(node)==1:fail('Cycle')
   if colors.get(node)==2:continue
   colors[node]=1;todo.append((node,True));todo.extend((v,False) for v in reversed(graph[node]))
 for root in profiles:select(data,root,limits)
 return data

def validate(raw,limits=None):
 try:return _validate(raw,limits)
 except CatalogInvalid:raise
 except (TypeError,KeyError,ValueError,UnicodeError,OverflowError,RecursionError):fail('InvalidJson')

def select(data,root,limits=None):
 limits=limits_with(limits);profiles={p['id']:p for p in data['profiles']};extensions={e['id']:e for e in data['extensions']}
 if root not in profiles:fail('ExtensionNotProfile' if root in extensions else 'UnknownProfile')
 graph={p['id']:p['requires_profiles']+p['requires_extensions'] for p in profiles.values()}|{e['id']:[e['profile']]+e['requires_profiles'] for e in extensions.values()}
 selected=set();todo=[root]
 while todo:
  node=todo.pop()
  if node not in selected:selected.add(node);todo.extend(graph[node])
 versions={};case_versions={};required={};open_owners=set();complete=True
 for node in sorted(selected):
  namespace='profile' if node in profiles else 'extension';stem,version=node.rsplit('-v',1);key=(namespace,stem)
  if key in versions and versions[key]!=version:fail('VersionConflict')
  versions[key]=version
  p=(profiles|extensions)[node]
  if node in profiles:complete &= p['definition_state']=='FROZEN';open_owners.update(p['open_owners'])
  for r in p['required_cases']:
   if not set(r['when_extensions'])<=selected:continue
   if r['case_id'] in case_versions and case_versions[r['case_id']]!=r['case_version']:fail('VersionConflict')
   case_versions[r['case_id']]=r['case_version']
   case=next(c for c in data['cases'] if (c['id'],c['version'])==(r['case_id'],r['case_version']))
   for cell_id in case['required_cells']:
    key=(r['case_id'],r['case_version'],cell_id)
    if key not in required and len(required)==limits['max_selected_cells']:fail('LimitExceeded')
    required.setdefault(key,set()).add(node)
 if profiles[root]['definition_state']=='FROZEN' and (not complete or not required):fail('InvalidDefinition')
 tiers={c['id']:c['tier'] for c in data['cells']}
 return {'profiles':sorted(selected&profiles.keys()),'extensions':sorted(selected&extensions.keys()),'required':[(a,b,c,tiers[c],tuple(sorted(by))) for (a,b,c),by in sorted(required.items())],'open_owners':sorted(open_owners),'definition_complete':complete}

def normalized(value):
 if isinstance(value,dict):return {k:normalized(v) for k,v in sorted(value.items())}
 if isinstance(value,list):return sorted((normalized(v) for v in value),key=lambda v:json.dumps(v,sort_keys=True))
 return value

def baseline(new,old):
 if new['catalog_revision']<old['catalog_revision'] or (new!=old and new['catalog_revision']==old['catalog_revision']):fail('BaselineRevision')
 for field,key in [('tasks',lambda r:r),('obligations',lambda r:(r['kind'],r['id'])),('families',lambda r:r['id']),('cells',lambda r:r['id']),('cases',lambda r:(r['id'],r['version'])),('profiles',lambda r:r['id']),('extensions',lambda r:r['id'])]:
  index={key(r):r for r in new[field]}
  for before in old[field]:
   k=key(before)
   if k not in index:fail('BaselineRemoved')
   after=index[k]
   if field=='tasks':continue
   a=copy_dict(after);b=copy_dict(before)
   if field=='cases':
    for v in [a,b]:v.pop('registration');v.pop('implementation_status')
   if field=='profiles':
    if before['definition_state']=='FROZEN' and after['definition_state']!='FROZEN':fail('BaselineState')
    if before['definition_state']=='DRAFT' and after['definition_state']=='FROZEN':
     if not select(new,after['id'])['definition_complete']:fail('BaselineState')
     for v in [a,b]:v.pop('definition_state');v.pop('open_owners')
   if normalized(a)!=normalized(b):fail('BaselineSemantics')
def copy_dict(value):return {k:v for k,v in value.items()}

def inventory(data,trace,research):
 expected={t['id'] for t in trace['tasks']}
 if set(data['tasks'])!=expected or len(data['tasks'])!=86:fail('InventoryTasks')
 actual={(o['kind'],o['id']):o for o in data['obligations']}
 if set(actual)!={(o['kind'],o['id']) for o in trace['source_obligations']} or len(actual)!=179:fail('InventoryObligations')
 family_contract={r['id']:r['short_contract'] for r in research['cases']}
 for old in trace['source_obligations']:
  got=actual[(old['kind'],old['id'])]
  if set(got['owners'])!=set(old['tasks']):fail('InventoryOwners')
  description=old.get('description',family_contract.get(old['id'],''))
  if got['description']!=description:fail('InventoryDescription')
 kinds={'UC':'user_conformance','G':'public_contract_gap','TODO':'research_todo'}
 expected_families={}
 for r in research['cases']:
  expected_families[r['id']]={'id':r['id'],'short_contract':r['short_contract'],'obligations':[{'kind':'regression_family','id':r['id']}]+[{'kind':kinds[k],'id':v} for k,values in r['related_obligations'].items() for v in values]}
 if normalized(data['families'])!=normalized(list(expected_families.values())) or len(data['families'])!=33:fail('InventoryFamilies')
 initial={p['id']:p for p in trace['profiles']};got={p['id']:p for p in data['profiles']}
 if not set(initial)<=set(got):fail('InventoryProfiles')
 for ident,p in initial.items():
  if set(got[ident]['requires_profiles'])!=set(p['requires_profiles']) or set(got[ident]['requires_extensions'])!=set(p['requires_extensions']):fail('InventoryProfileGraph')
 expected_ext={e['id']:e for e in trace['profile_extensions']};actual_ext={e['id']:e for e in data['extensions']}
 if not set(expected_ext)<=set(actual_ext):fail('InventoryExtensions')
 for ident,e in expected_ext.items():
  if any(normalized(actual_ext[ident][k])!=normalized(e[k]) for k in ['profile','requires_profiles','requires_tasks']):fail('InventoryExtensionGraph')

def verify_artifacts(data,root,limit):
 regs=[case['registration'] for case in data['cases'] if case['registration'] is not None]
 if not regs:return True
 if root is None:return False
 # Open every root/component through directory descriptors with O_NOFOLLOW.
 # This binds each read to its opened file and avoids lstat/open substitution.
 root=Path(root).absolute();fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY);cache={}
 try:
  for part in root.parts[1:]:
   next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=next_fd
  for reg in regs:
   for name in ['executable','fixture','oracle','bad_control']:
    artifact=reg[name];path=artifact['path']
    if path not in cache:
     parent=os.dup(fd)
     try:
      parts=path.split('/')
      for part in parts[:-1]:
       next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);os.close(parent);parent=next_fd
      source=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
      try:
       if not stat.S_ISREG(os.fstat(source).st_mode):fail('ArtifactNonregular')
       content=bytearray()
       while len(content)<=limit:
        block=os.read(source,min(65536,limit+1-len(content)))
        if not block:break
        content.extend(block)
       if len(content)>limit:fail('ArtifactLimitExceeded')
       cache[path]=hashlib.sha256(content).hexdigest()
      finally:os.close(source)
     finally:os.close(parent)
    if cache[path]!=artifact['sha256']:fail('ArtifactDigestMismatch')
 except OSError as e:raise CatalogInvalid('ArtifactPathRefused') from e
 finally:os.close(fd)
 return True

def read_bounded(path):
 try:
  with Path(path).open('rb') as stream:raw=stream.read(CEILINGS['max_input_bytes']+1)
 except OSError as e:raise CatalogInvalid('InputUnavailable') from e
 if len(raw)>CEILINGS['max_input_bytes']:fail('InputTooLarge')
 return raw
class UsageParser(argparse.ArgumentParser):
 def error(self,message):self.print_usage(sys.stderr);self.exit(64,'invalid usage\n')
def main(argv=None):
 p=UsageParser(description=__doc__);p.add_argument('catalog');p.add_argument('--baseline');p.add_argument('--artifact-root');p.add_argument('--traceability');p.add_argument('--research-catalog');args=p.parse_args(argv)
 if bool(args.traceability)!=bool(args.research_catalog):p.error('paired inventory inputs required')
 summary=dict(schema_version=1,structurally_valid=False,definition_complete=False,qualification='not_evaluated',registrations_verified=False,errors=[])
 try:
  raw=read_bounded(args.catalog);data=validate(raw)
  if args.baseline:baseline(data,validate(read_bounded(args.baseline)))
  if args.traceability:
   inventory(data,json.loads(read_bounded(args.traceability)),json.loads(read_bounded(args.research_catalog)))
   package=Path(__file__).resolve().parents[2]/'crates/scopebase-testkit/tests/fixtures/catalog/cases-v1.json'
   if raw!=package.read_bytes():fail('InventoryPackageCopy')
   schema=Path(__file__).resolve().parents[2]/'profiles/profile-schema-v1.json'
   if schema.read_bytes()!=(package.parent/'profile-schema-v1.json').read_bytes():fail('InventorySchemaCopy')
  summary['registrations_verified']=verify_artifacts(data,args.artifact_root,CEILINGS['max_input_bytes'])
  summary['definition_complete']=bool(data['profiles']) and all(select(data,p['id'])['definition_complete'] for p in data['profiles'])
  summary['structurally_valid']=True
 except (CatalogInvalid,ValueError,TypeError,KeyError,OSError,RecursionError) as e:
  summary['errors']=[str(e)[:128] if isinstance(e,CatalogInvalid) else 'InvalidJson']
 print(json.dumps(summary,separators=(',',':')))
 return 0 if summary['structurally_valid'] else 2
if __name__=='__main__':sys.exit(main())
