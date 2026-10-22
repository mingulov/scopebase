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

# BP03 embeds the preceding accepted collector verbatim; no private runtime import.
COLLECTOR_SHA256='81e371cec788e07df9139695f8f52b07fa653b1b93d36bbf8fd41ce2d8ef5bdd'
_bounded_run=run
import argparse,copy,re,shutil,sys,tomllib,uuid
sys.dont_write_bytecode=True

# Reviewed BP03 schema2 transport; the accepted collector above is unchanged.
EVENT_LIMIT=1048576
SIDECAR_LIMIT=8388608
STATIC_LIMIT=33554432
FINAL_LIMIT=67108864
RAW_FIELDS={'exit_code','reason_code','cleanup','duration_ms','command','cwd','process_group','logs','errors'}
_PUBLICATION_OWNER=None
_FINALIZED_RETURNS={}

def error_fact(stage,error):
    return dict(stage=stage,exception=type(error).__name__,message=str(error)[:512],errno=getattr(error,'errno',None))

class EvidenceFailure(RuntimeError):
    def __init__(self,message,custody=None,failures=None,outcome='NOT_PUBLISHED'):
        super().__init__(message);self.custody={} if custody is None else custody;self.failures=[] if failures is None else failures;self.outcome=outcome

class PublicationFailure(EvidenceFailure):pass

class FinalizedReceipt:
    def __init__(self,root,reference,run_id):self.root=Path(root);self.reference=reference;self.run_id=run_id;self.publication='CONFIRMED_DURABLE'

def publication_step(stage,path):
    """Named writer seam for causal tests; never interposes on child launch."""
    return None

def lexical_path(path):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:raise ValueError('explicit canonical absolute path required')
    for candidate in [path,*path.parents]:
        if candidate.is_symlink():raise ValueError('symlink output ancestor')
    return path

def durable_directory(path):
    path=lexical_path(path);fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            try:child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            except FileNotFoundError:
                publication_step('mkdir',path);os.mkdir(component,mode=0o700,dir_fd=fd);child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            try:
                publication_step('mkdir-fsync-child',path);os.fsync(child)
                publication_step('mkdir-fsync-parent',path);os.fsync(fd)
            except BaseException:os.close(child);raise
            os.close(fd);fd=child
        if (os.fstat(fd).st_dev,os.fstat(fd).st_ino)!=(path.stat().st_dev,path.stat().st_ino):raise ValueError('owned directory identity changed')
        return fd
    except BaseException:os.close(fd);raise

def bounded_json(value,limit):
    data=bytearray()
    for piece in json.JSONEncoder(sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).iterencode(value):
        encoded=piece.encode('utf-8')
        if len(data)+len(encoded)+1>limit:raise ValueError('evidence serialization byte bound')
        data.extend(encoded)
    data.extend(b'\n');return bytes(data)

def atomic_json(path,value,limit=SIDECAR_LIMIT):
    path=Path(path);directory=None;temporary='.'+path.name+'.'+uuid.uuid4().hex+'.tmp';created=False;attempted=False;linked=False;confirmed=False;failures=[]
    try:
        publication_step('serialize',path);data=bounded_json(value,limit);directory=durable_directory(path.parent)
        publication_step('temp-open',path);fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory);created=True
        with os.fdopen(fd,'wb') as stream:
            publication_step('file-write',path)
            if stream.write(data)!=len(data):raise OSError('short evidence write')
            publication_step('file-flush',path);stream.flush();publication_step('file-fsync',path);os.fsync(stream.fileno())
        publication_step('link',path);attempted=True;os.link(temporary,path.name,src_dir_fd=directory,dst_dir_fd=directory,follow_symlinks=False);linked=True
        publication_step('directory-fsync',path);os.fsync(directory);confirmed=True
    except BaseException as error:failures.append(error_fact('publication',error))
    finally:
        if created:
            try:publication_step('temp-unlink',path);os.unlink(temporary,dir_fd=directory);publication_step('cleanup-directory-fsync',path);os.fsync(directory)
            except BaseException as error:failures.append(error_fact('own-temp-cleanup',error))
        if directory is not None:
            try:os.close(directory)
            except BaseException as error:failures.append(error_fact('directory-close',error))
    if failures:
        outcome='CONFIRMED_DURABLE' if confirmed else 'PUBLISHED_DURABILITY_UNKNOWN' if linked else 'UNKNOWN_PUBLICATION' if attempted else 'NOT_PUBLISHED'
        failure=PublicationFailure('evidence publication failed '+str(path),failures=failures,outcome=outcome)
        if _PUBLICATION_OWNER is not None:_PUBLICATION_OWNER.fail(failure)
        raise failure
    return dict(path=str(path),bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),publication='CONFIRMED_DURABLE')

def finite_projection(value):
    # Nonfinal evidence can contain one command/result/binding, never histories.
    pending=[value];count=0
    while pending:
        item=pending.pop();count+=1
        if count>200000:raise ValueError('projection node bound')
        if isinstance(item,dict):
            if set(item)&{'commands','clients','controls','command_event_refs','result_event_refs','dynamic_sidecar_refs'}:raise ValueError('history array in nonfinal own-row evidence')
            pending.extend(item.values())
        elif isinstance(item,(list,tuple)):pending.extend(item)
    return value

def strict_json(data):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('duplicate evidence key')
            result[key]=value
        return result
    return json.loads(data,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite evidence scalar')))

def file_reference(root,path,kind,run_id):
    path=Path(path);relative=path.relative_to(root)
    if '..' in relative.parts or any(p in {'','.','..'} for p in relative.parts):raise ValueError('unsafe evidence reference')
    return dict(kind=kind,owner_run_id=run_id,relative_path=relative.as_posix(),length=path.stat().st_size,sha256=sha(path))

def read_reference(root,reference,run_id=None,kind=None):
    if not isinstance(reference,dict):raise ValueError('typed evidence reference')
    if set(reference)!={'kind','owner_run_id','relative_path','length','sha256'} or any(not isinstance(reference[k],str) for k in ['kind','owner_run_id','relative_path','sha256']) or not re.fullmatch('[0-9a-f]{32}',reference['owner_run_id']) or not re.fullmatch('[0-9a-f]{64}',reference['sha256']):raise ValueError('typed evidence reference')
    if run_id is not None and reference['owner_run_id']!=run_id:raise ValueError('cross-run evidence reference')
    if kind is not None and reference['kind']!=kind:raise ValueError('wrong evidence reference kind')
    fixed={'static-binding':'bindings-v2.json','required-inventory':'required-v2.json','final-receipt':'receipt.json'}
    if reference['kind'] in fixed and reference['relative_path']!=fixed[reference['kind']]:raise ValueError('fixed evidence kind/path identity')
    relative=Path(reference['relative_path'])
    if relative.is_absolute() or relative.as_posix()!=reference['relative_path'] or any(p in {'.','..',''} for p in relative.parts):raise ValueError('unsafe evidence reference path')
    path=lexical_path(Path(root)/relative);length=reference['length']
    if type(length) is not int or not 0<=length<={'command-event':EVENT_LIMIT,'result-event':EVENT_LIMIT,'source-projection':SIDECAR_LIMIT,'source-snapshot':SIDECAR_LIMIT,'static-binding':STATIC_LIMIT,'required-inventory':STATIC_LIMIT,'final-receipt':FINAL_LIMIT}.get(reference['kind'],0):raise ValueError('evidence reference length bound')
    with path.open('rb') as stream:data=stream.read(length+1)
    if len(data)!=length or hashlib.sha256(data).hexdigest()!=reference['sha256']:raise ValueError('evidence reference bytes changed')
    return data

class ProjectionReader:
    """Bounded typed retained closure; never infers producer completion from bytes."""
    def __init__(self,root,run_id):self.root=Path(root);self.run_id=run_id;self.cache={};self.active=set();self.nodes=0;self.references=0
    def reference(self,reference,kind):
        # Validate even cached aliases, so kind/owner mutations cannot bypass checks.
        data=read_reference(self.root,reference,self.run_id,kind);key=(kind,reference['relative_path'],reference['sha256'],reference['length'])
        self.references+=1
        if self.references>200000:raise ValueError('retained reference work bound')
        if key in self.active or len(self.active)>=32:raise ValueError('cyclic/deep retained reference')
        if key in self.cache:return self.cache[key]
        if kind=='source-snapshot':return data
        value=strict_json(data);self.active.add(key)
        try:
            if kind=='source-projection':self.projection(value,reference)
            elif kind in ['static-binding','required-inventory']:
                expected='BP03_STATIC_BINDING' if kind=='static-binding' else 'BP03_REQUIRED_INVENTORY'
                if not isinstance(value,dict) or value.get('schema_version')!=2 or value.get('kind')!=expected or value.get('run_id')!=self.run_id:raise ValueError('binding kind/run identity')
                if kind=='static-binding':
                    if set(value)!={'schema_version','kind','run_id','required_inventory_ref','bindings'}:raise ValueError('static binding schema')
                    self.reference(value['required_inventory_ref'],'required-inventory')
                elif set(value)!={'schema_version','kind','run_id','global_obligations','local_required'} or value['global_obligations']!=fixed_obligations():raise ValueError('fixed required inventory mismatch')
            elif kind=='command-event':validate_event(self.root,reference,self.run_id,_reader=self)
            elif kind=='result-event':self.result(value,reference)
            else:raise ValueError('unsupported retained document kind')
        finally:self.active.remove(key)
        self.cache[key]=value;return value
    def walk(self,value,depth=0):
        self.nodes+=1
        if depth>32 or self.nodes>200000:raise ValueError('retained projection node/depth bound')
        if isinstance(value,dict):
            if set(value)=={'kind','owner_run_id','relative_path','length','sha256'}:
                if value['kind'] not in ['source-projection','source-snapshot','command-event','result-event','static-binding','required-inventory']:raise ValueError('nested retained reference kind')
                return self.reference(value,value['kind'])
            # A parent owns this finite cross-run association; its child root is explicit.
            if set(value)=={'child_id','root','receipt_ref','producer_return'}:
                if value['producer_return']!='OBSERVED_SUCCESS':raise ValueError('child completion association')
                child=value['receipt_ref'];read_reference(lexical_path(value['root']),child,child['owner_run_id'],'final-receipt');return
            expected={'static_binding_ref':'static-binding','required_inventory_ref':'required-inventory','baseline_ref':'source-projection','source_projection_ref':'source-projection','projection_ref':'source-projection','bytes_ref':'source-snapshot','lock_binding_ref':'source-projection','last_event_ref':'command-event','raw_result_ref':'command-event','lease_ref':'source-projection','oracle_ref':'source-projection','proof_ref':'source-projection'}
            for name,item in value.items():
                if name in expected and item is not None:self.reference(item,expected[name])
                else:self.walk(item,depth+1)
        elif isinstance(value,list):
            for item in value:self.walk(item,depth+1)
    def result(self,value,reference):
        fields={'schema_version','kind','run_id','sequence','obligation_id','phase','static_binding_ref','required_inventory_ref','previous_event_ref','payload'}
        if not isinstance(value,dict) or set(value)!=fields or value['schema_version']!=2 or value['kind']!='BP03_RESULT_PHASE' or value['run_id']!=self.run_id or type(value['sequence']) is not int or not 1<=value['sequence']<=999999 or reference['relative_path']!='results/%06d.%s.json'%(value['sequence'],value['phase']) or not isinstance(value['payload'],dict):raise ValueError('result kind/sequence/phase schema')
        static=self.reference(value['static_binding_ref'],'static-binding');required=self.reference(value['required_inventory_ref'],'required-inventory')
        if static['required_inventory_ref']!=value['required_inventory_ref']:raise ValueError('result static/inventory identity')
        expected=next((row for row in required['local_required'] if row['id']==value['obligation_id']),None)
        if expected is None:raise ValueError('result obligation outside required inventory')
        phases=expected.get('required_phases',['reserved','complete'])
        if value['phase'] not in phases:raise ValueError('result phase outside required inventory')
        index=phases.index(value['phase'])
        if index==0:
            if value['previous_event_ref'] is not None:raise ValueError('result reservation predecessor')
        else:
            before=self.reference(value['previous_event_ref'],'result-event')
            if before['phase']!=phases[index-1] or before['sequence']>=value['sequence'] or any(before[key]!=value[key] for key in ['obligation_id','static_binding_ref','required_inventory_ref']):raise ValueError('result predecessor identity/order')
        finite_projection(value['payload']);self.walk(value['payload'])
    def record(self,value):
        if not isinstance(value,dict) or set(value)!={'bytes','sha256'} or type(value['bytes']) is not int or not 0<=value['bytes']<=SIDECAR_LIMIT or not isinstance(value['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',value['sha256']):raise ValueError('source inventory record')
    def relative(self,name):
        if not isinstance(name,str) or not name or len(name)>4096 or Path(name).is_absolute() or Path(name).as_posix()!=name or any(p in {'.','..',''} for p in Path(name).parts):raise ValueError('source relative path')
    def snapshot(self,reference,record,name):
        self.relative(name);self.record(record)
        if reference.get('length')!=record['bytes'] or reference.get('sha256')!=record['sha256'] or Path(reference.get('relative_path','')).name!=Path(name).name or not re.fullmatch(r'snapshots/[0-9]{6}/[^/]+',reference.get('relative_path','')):raise ValueError('snapshot/inventory identity')
        self.reference(reference,'source-snapshot')
    def projection(self,value,reference):
        if not isinstance(value,dict) or set(value)!={'schema_version','kind','run_id','sequence','subject_id','own_binding'} or value['schema_version']!=2 or value['kind']!='BP03_DYNAMIC_PROJECTION' or value['run_id']!=self.run_id or type(value['sequence']) is not int or not 1<=value['sequence']<=999999 or reference['relative_path']!='sidecars/%06d.source-projection.json'%value['sequence'] or not isinstance(value['subject_id'],str) or not value['subject_id'] or not isinstance(value['own_binding'],dict):raise ValueError('projection kind/sequence/subject schema')
        finite_projection(value['own_binding']);binding=value['own_binding'];subject=value['subject_id'];keys=set(binding)
        if keys=={'root','inventory','files'}:
            root=binding['root']
            if not isinstance(root,str) or not Path(root).is_absolute() or '..' in Path(root).parts or subject!=root+'/baseline' or not isinstance(binding['inventory'],dict) or not isinstance(binding['files'],dict) or set(binding['inventory'])!=set(binding['files']):raise ValueError('source baseline role/root/files')
            for name,record in binding['inventory'].items():self.snapshot(binding['files'][name],record,name)
        elif keys=={'source_trees','extra','cwd','product_command','command_sequence','obligation_id'}:
            if subject!='command-projection' or not isinstance(binding['source_trees'],list) or len(binding['source_trees'])>8 or not isinstance(binding['extra'],dict) or set(binding['extra'])-{'program','workspace'} or not isinstance(binding['cwd'],str) or not isinstance(binding['product_command'],list) or not binding['product_command'] or type(binding['command_sequence']) is not int or not 1<=binding['command_sequence']<=999999 or not isinstance(binding['obligation_id'],str) or not binding['obligation_id']:raise ValueError('source command projection role')
            roots=set()
            for tree in binding['source_trees']:
                if not isinstance(tree,dict) or set(tree)!={'root','baseline_ref','changed','removed'} or tree['root'] in roots or not isinstance(tree['changed'],dict) or not isinstance(tree['removed'],list) or len(set(tree['removed']))!=len(tree['removed']):raise ValueError('source delta schema/unique roots')
                roots.add(tree['root']);baseline=self.reference(tree['baseline_ref'],'source-projection')
                if set(baseline['own_binding'])!={'root','inventory','files'} or baseline['own_binding']['root']!=tree['root'] or baseline['sequence']>=value['sequence']:raise ValueError('source baseline/delta root/sequence')
                inventory=baseline['own_binding']['inventory']
                for name in tree['removed']:
                    self.relative(name)
                    if name not in inventory or name in tree['changed']:raise ValueError('source removed/delta relation')
                for name,changed in tree['changed'].items():
                    if not isinstance(changed,dict) or set(changed)!={'record','bytes_ref'} or changed['record']==inventory.get(name):raise ValueError('source changed/delta relation')
                    self.snapshot(changed['bytes_ref'],changed['record'],name)
            for name,extra in binding['extra'].items():
                expected={'path','bytes','sha256'} if name=='program' else {'path','sha256','bytes_ref'}
                if not isinstance(extra,dict) or set(extra)!=expected or not isinstance(extra['path'],str) or not Path(extra['path']).is_absolute() or not isinstance(extra['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',extra['sha256']):raise ValueError('source extra role')
                if name=='program':
                    if extra['path']!=binding['product_command'][0] or type(extra['bytes']) is not int or extra['bytes']<0:raise ValueError('source executable/request identity')
                else:self.snapshot(extra['bytes_ref'],dict(bytes=extra['bytes_ref']['length'],sha256=extra['sha256']),Path(extra['path']).name)
        elif subject.endswith('/validated-lock'):
            if keys!={'path','sha256','packages','bytes_ref'} or not isinstance(binding['path'],str) or not Path(binding['path']).is_absolute() or Path(binding['path']).name!='Cargo.lock' or not isinstance(binding['packages'],list):raise ValueError('validated lock role fields')
            snapshot=binding['bytes_ref'];self.snapshot(snapshot,dict(bytes=snapshot['length'],sha256=binding['sha256']),'Cargo.lock')
            retained=self.reference(snapshot,'source-snapshot')
            if tomllib.loads(retained.decode())['package']!=binding['packages']:raise ValueError('validated lock retained package projection')
        elif subject=='command-projection' or subject.endswith('/baseline'):raise ValueError('source projection role fields')
        else:self.walk(binding)
    def command(self,reference,event,request):
        value=self.reference(reference,'source-projection');binding=value['own_binding']
        if value['subject_id']!=event['obligation_id']+'/command' or set(binding)!={'command_sequence','obligation_id','request','static_binding_ref','baseline_ref','source_projection_ref'} or type(binding['command_sequence']) is not int or binding['command_sequence']!=event['sequence'] or binding['obligation_id']!=event['obligation_id'] or binding['request']!=request or binding['static_binding_ref']!=event['static_binding_ref']:raise ValueError('command projection request/sequence/subject identity')
        baseline=self.reference(binding['baseline_ref'],'source-projection')
        if baseline['subject_id']!='baseline' or baseline['own_binding']!=dict(static_binding_ref=event['static_binding_ref']):raise ValueError('command baseline/static role identity')
        if binding['source_projection_ref'] is None:raise ValueError('missing command source projection')
        source=self.reference(binding['source_projection_ref'],'source-projection')
        if source['subject_id']!='command-projection' or set(source['own_binding'])!={'source_trees','extra','cwd','product_command','command_sequence','obligation_id'} or source['own_binding']['cwd']!=request['cwd'] or source['own_binding']['product_command']!=request['product_command'] or source['own_binding']['command_sequence']!=event['sequence'] or source['own_binding']['obligation_id']!=event['obligation_id'] or not baseline['sequence']<source['sequence']<value['sequence']:raise ValueError('command source projection/request identity')
        return value

def validate_event(root,reference,run_id,_depth=0,_reader=None):
    if _depth>2:raise ValueError('command predecessor depth bound')
    reader=_reader or ProjectionReader(root,run_id)
    event=strict_json(read_reference(root,reference,run_id,'command-event'))
    required={'schema_version','kind','run_id','sequence','obligation_id','phase','static_binding_ref','required_inventory_ref','current_projection_ref','previous_event_ref','payload'}
    if set(event)!=required or event['schema_version']!=2 or event['kind']!='BP03_COMMAND_LIFECYCLE' or event['run_id']!=run_id or type(event['sequence']) is not int or not 1<=event['sequence']<=999999:raise ValueError('command event schema')
    static=reader.reference(event['static_binding_ref'],'static-binding');reader.reference(event['required_inventory_ref'],'required-inventory')
    if static['required_inventory_ref']!=event['required_inventory_ref']:raise ValueError('static binding/inventory identity')
    if not isinstance(event['obligation_id'],str) or not event['obligation_id'] or not isinstance(event['payload'],dict):raise ValueError('event identity/payload type')
    phase=event['phase'];payload=event['payload'];previous=event['previous_event_ref']
    expected_path='commands/%06d.%s.json'%(event['sequence'],event['phase'])
    if reference['relative_path']!=expected_path:raise ValueError('sequence/phase filename identity')
    if phase=='reserved':
        if previous is not None or set(payload)!={'request','at_reservation'} or payload['at_reservation']!=dict(process_group=None,exit_code=None,cleanup='not_started',temporal_scope='reservation instant only'):raise ValueError('reservation temporal schema')
        request=payload['request']
        if not isinstance(request,dict) or any(not isinstance(request.get(k),str) for k in ['cwd','target','stdout_path','stderr_path']) or any(not isinstance(request.get(k),list) or not request[k] or any(not isinstance(v,str) for v in request[k]) for k in ['command','product_command']) or not isinstance(request.get('environment'),dict) or any(not isinstance(k,str) or not isinstance(v,str) for k,v in request['environment'].items()) or type(request.get('start_unix')) not in [int,float]:raise ValueError('reservation scalar types')
        if set(payload['request'])!={'command','product_command','cwd','environment','target','stdout_path','stderr_path','start_unix'}:raise ValueError('reservation request schema')
        reader.command(event['current_projection_ref'],event,request)
    elif phase in ['collected','complete']:
        before=validate_event(root,previous,run_id,_depth+1,reader)
        if any(before[name]!=event[name] for name in ['run_id','sequence','obligation_id','static_binding_ref','required_inventory_ref','current_projection_ref']):raise ValueError('command predecessor identity')
        if phase=='collected':
            if before['phase']!='reserved' or set(payload)!={'raw_result'}:raise ValueError('collected transition')
            raw=payload['raw_result']
            if not isinstance(raw,dict) or not isinstance(raw.get('logs'),dict) or not isinstance(raw.get('errors'),list):raise ValueError('raw collector type')
            if set(raw)!=RAW_FIELDS or set(raw['logs'])!={'stdout','stderr'} or any(set(v)!={'path','sha256','bytes'} for v in raw['logs'].values()) or any(set(e)!={'stage','exception','message','errno'} for e in raw['errors']):raise ValueError('raw collector fields omitted or added')
            if raw['exit_code'] is not None and type(raw['exit_code']) is not int or raw['reason_code'] is not None and not isinstance(raw['reason_code'],str) or raw['cleanup'] not in ['complete','unresolved'] or type(raw['duration_ms']) is not int or raw['duration_ms']<0 or type(raw['process_group']) is not int or raw['process_group']<=0 or raw['command']!=before['payload']['request']['command'] or raw['cwd']!=before['payload']['request']['cwd']:raise ValueError('raw collector scalar/command identity')
            for log in raw['logs'].values():
                if not isinstance(log['path'],str) or log['bytes'] is not None and (type(log['bytes']) is not int or not 0<=log['bytes']<=MAX_LOG) or log['sha256'] is not None and not re.fullmatch('[0-9a-f]{64}',log['sha256']):raise ValueError('raw collector log types')
        else:
            if set(payload)!={'raw_result_ref','setup_proof','wrapper_errors','lease_ref','oracle_ref','qualification','end_unix'}:raise ValueError('complete payload schema')
            if not isinstance(payload['wrapper_errors'],list) or payload['qualification'] not in ['INCOMPLETE','ELIGIBLE_AFTER_PRODUCER_COMPLETION','REFUSED_EXPECTED_ORACLE'] or type(payload['end_unix']) not in [int,float]:raise ValueError('complete scalar types')
            for key in ['lease_ref','oracle_ref']:
                if payload[key] is not None:
                    sidecar=reader.reference(payload[key],'source-projection')
                    if sidecar['subject_id']!=event['obligation_id']+('/lease' if key=='lease_ref' else '/validated-lock'):raise ValueError('complete sidecar subject/role identity')
            if before['phase']=='collected':
                reserved=validate_event(root,before['previous_event_ref'],run_id,_depth+1,reader);request=reserved['payload']['request'];product=request['product_command']
                if len(product)>1 and product[1]=='generate-lockfile' and payload['qualification']!='INCOMPLETE' and payload['oracle_ref'] is None:raise ValueError('generated lock completion requires validation sidecar')
                raw=before['payload']['raw_result']
                if (raw['reason_code'] is not None or raw['cleanup']!='complete' or payload['wrapper_errors']) and payload['qualification']!='INCOMPLETE':raise ValueError('nonqualifying raw custody cannot complete eligible')
                if payload['raw_result_ref']!=previous or payload['setup_proof'] is not None:raise ValueError('complete collected reference')
            elif before['phase']=='reserved':
                if payload['raw_result_ref'] is not None or not payload['setup_proof'] or payload['setup_proof'].get('classification')!='VERIFIED_PRELAUNCH_SETUP':raise ValueError('unproved no-child shortcut')
                proof=payload['setup_proof']
                if proof.get('origin_site') not in ['collector-prelaunch-28','collector-prelaunch-42'] or proof.get('origin_source_sha256')!=COLLECTOR_SHA256:raise ValueError('unverified setup origin')
                proof_projection=reader.reference(proof['proof_ref'],'source-projection')
                if proof_projection['subject_id']!=event['obligation_id']+'/prelaunch-proof' or proof_projection['own_binding']!=dict(site=int(proof['origin_site'].rsplit('-',1)[1]),collector_sha256=COLLECTOR_SHA256):raise ValueError('setup proof projection identity')
            else:raise ValueError('duplicate or wrong predecessor phase')
    else:raise ValueError('unknown command phase')
    return event

def audit_commands(root):
    rows=[];root=Path(root)
    for path in sorted((root/'commands').glob('*.reserved.json')):
        base=path.name.split('.')[0];collected=path.with_name(base+'.collected.json');complete=path.with_name(base+'.complete.json');state='UNKNOWN_EXECUTION_CUSTODY'
        if collected.exists():state='COMPLETE_REQUIRES_PRODUCER_OBSERVATION' if complete.exists() else 'INCOMPLETE_COLLECTED'
        elif complete.exists():
            event=strict_json(complete.read_bytes());validate_event(root,file_reference(root,complete,'command-event',event['run_id']),event['run_id'])
            if event['payload']['setup_proof'] is not None:state='VERIFIED_PRELAUNCH_SETUP'
        rows.append(dict(sequence=int(base),state=state,automatic_retry=False,ownership_release=False))
    return rows

class EventJournal:
    def __init__(self,root):
        self.root=lexical_path(root);self.run_id=uuid.uuid4().hex;self.sequence=0;self.side_sequence=0;self.result_sequence=0;self.sealed=False;self.failed=False;self.final_attempted=False;self.active=None;self.events=[];self.sidecars=[];self.results=[];self.last_failure=None;self.emergency_attempted=False
        fd=durable_directory(self.root);os.close(fd)
    def fail(self,error,custody=None):
        self.failed=True
        if custody is None:custody=self.active or getattr(error,'custody',{})
        if self.last_failure is None:
            self.last_failure=error if isinstance(error,EvidenceFailure) else EvidenceFailure(str(error),custody,[error_fact('outer',error)])
            if custody:self.last_failure.custody=custody
        else:
            if not self.last_failure.custody and custody:self.last_failure.custody=custody
            if error is not self.last_failure:
                additional=getattr(error,'failures',None) or [error_fact('later',error)]
                self.last_failure.failures.extend(v for v in additional if v not in self.last_failure.failures)
        return self.last_failure
    def publish(self,path,value,limit=EVENT_LIMIT):
        try:atomic_json(self.root/path,value,limit)
        except BaseException as error:raise self.fail(error)
        return file_reference(self.root,self.root/path,value.get('reference_kind','source-projection'),self.run_id)
    def seal(self,bindings,required):
        if self.sealed or self.sequence or self.failed:raise self.fail(ValueError('static binding seal order'))
        self.required_ref=self.publish('required-v2.json',dict(schema_version=2,kind='BP03_REQUIRED_INVENTORY',run_id=self.run_id,global_obligations=fixed_obligations(),local_required=required),STATIC_LIMIT);self.required_ref['kind']='required-inventory'
        self.static_ref=self.publish('bindings-v2.json',dict(schema_version=2,kind='BP03_STATIC_BINDING',run_id=self.run_id,required_inventory_ref=self.required_ref,bindings=bindings),STATIC_LIMIT);self.static_ref['kind']='static-binding'
        self.required=copy.deepcopy(required);self.result_phases={};self.base_projection=self.sidecar('baseline',dict(static_binding_ref=self.static_ref));self.sealed=True
    def sidecar(self,subject,binding):
        try:finite_projection(binding)
        except BaseException as error:raise self.fail(error)
        self.side_sequence+=1;name='sidecars/%06d.source-projection.json'%self.side_sequence
        reference=self.publish(name,dict(schema_version=2,kind='BP03_DYNAMIC_PROJECTION',run_id=self.run_id,sequence=self.side_sequence,subject_id=subject,own_binding=binding),SIDECAR_LIMIT);self.sidecars.append(reference);return reference
    def event(self,row,phase,payload):
        value=dict(schema_version=2,kind='BP03_COMMAND_LIFECYCLE',run_id=self.run_id,sequence=row['sequence'],obligation_id=row['id'],phase=phase,static_binding_ref=self.static_ref,required_inventory_ref=self.required_ref,current_projection_ref=row['projection_ref'],previous_event_ref=row.get('last_event_ref'),payload=payload)
        reference=self.publish('commands/%06d.%s.json'%(row['sequence'],phase),value);reference['kind']='command-event'
        try:validate_event(self.root,reference,self.run_id)
        except BaseException as error:raise self.fail(error,row)
        row['last_event_ref']=reference;self.events.append(reference);return reference
    def reserve(self,row,request,projection=None):
        if not self.sealed or self.failed or self.active is not None:raise self.fail(ValueError('unsealed, failed or concurrent dispatch'),row)
        self.sequence+=1;self.active=row
        if projection is None:projection=self.sidecar('command-projection',dict(source_trees=[],extra={},cwd=request['cwd'],product_command=request['product_command'],command_sequence=self.sequence,obligation_id=row['id']))
        binding=dict(command_sequence=self.sequence,obligation_id=row['id'],request=request,static_binding_ref=self.static_ref,baseline_ref=self.base_projection,source_projection_ref=projection)
        row.update(sequence=self.sequence,projection_ref=self.sidecar(row['id']+'/command',binding))
        self.event(row,'reserved',dict(request=request,at_reservation=dict(process_group=None,exit_code=None,cleanup='not_started',temporal_scope='reservation instant only')))
    def result(self,obligation,phase,payload,previous=None):
        if not self.sealed or self.failed:raise self.fail(ValueError('result requires sealed healthy journal'))
        expected=next((r for r in self.required if r['id']==obligation),None)
        if expected is None:raise self.fail(ValueError('result outside presealed obligations '+obligation))
        if 'required_phases' in expected and phase not in expected['required_phases']:raise self.fail(ValueError('phase outside presealed obligation'))
        phases=self.result_phases.setdefault(obligation,[])
        required_phases=expected.get('required_phases')
        if required_phases and (len(phases)>=len(required_phases) or phase!=required_phases[len(phases)]):raise self.fail(ValueError('required result phase order'))
        if phase in phases:raise self.fail(ValueError('duplicate result phase'))
        if phases and previous!=self.results_by_obligation[obligation]:raise self.fail(ValueError('result predecessor mismatch'))
        if not phases and (previous is not None or phase!='reserved'):raise self.fail(ValueError('result reservation first'))
        try:finite_projection(payload)
        except BaseException as error:raise self.fail(error)
        self.result_sequence+=1;value=dict(schema_version=2,kind='BP03_RESULT_PHASE',run_id=self.run_id,sequence=self.result_sequence,obligation_id=obligation,phase=phase,static_binding_ref=self.static_ref,required_inventory_ref=self.required_ref,previous_event_ref=previous,payload=payload)
        reference=self.publish('results/%06d.%s.json'%(self.result_sequence,phase),value);reference['kind']='result-event';self.results.append(reference);phases.append(phase)
        if not hasattr(self,'results_by_obligation'):self.results_by_obligation={}
        self.results_by_obligation[obligation]=reference;return reference
    def finish(self,report):
        if self.final_attempted:raise self.fail(ValueError('final receipt attempt already used'))
        self.final_attempted=True
        if self.failed and report['status']=='PASS':raise self.last_failure or self.fail(ValueError('latched failure cannot pass'))
        if report['status']=='PASS':
            if not self.sealed or self.active is not None:raise self.fail(ValueError('unsealed or active command cannot pass'))
            for row in self.required:
                if not set(row.get('required_phases',[]))<=set(self.result_phases.get(row['id'],[])):raise self.fail(ValueError('required obligation incomplete '+row['id']))
            for reference in self.events:
                event=validate_event(self.root,reference,self.run_id)
                if event['phase']=='complete' and event['payload']['qualification']=='INCOMPLETE':raise self.fail(ValueError('incomplete command cannot pass'))
        value=dict(report,schema_version=2,run_id=self.run_id,static_binding_ref=getattr(self,'static_ref',None),required_inventory_ref=getattr(self,'required_ref',None),command_event_refs=self.events,dynamic_sidecar_refs=self.sidecars,result_event_refs=self.results,producer_completion_required=True)
        try:atomic_json(self.root/'receipt.json',value,FINAL_LIMIT)
        except BaseException as error:raise self.fail(error)
        reference=file_reference(self.root,self.root/'receipt.json','final-receipt',self.run_id)
        completion=FinalizedReceipt(self.root,reference,self.run_id);_FINALIZED_RETURNS[id(completion)]=(completion,self.root,copy.deepcopy(reference),self.run_id);return completion
    def emergency(self,error):
        failure=self.fail(error)
        if not self.emergency_attempted:
            self.emergency_attempted=True
            try:atomic_json(self.root/'emergency.failure.json',dict(schema_version=2,run_id=self.run_id,status='INCOMPLETE',custody=failure.custody,failures=failure.failures),EVENT_LIMIT)
            except BaseException as later:failure.failures.extend(getattr(later,'failures',[error_fact('emergency',later)]))
        return failure

def accept_finalized(completion):
    if not isinstance(completion,FinalizedReceipt) or _FINALIZED_RETURNS.get(id(completion))!=(completion,completion.root,completion.reference,completion.run_id) or completion.publication!='CONFIRMED_DURABLE':raise ValueError('successful producer completion required')
    report=strict_json(read_reference(completion.root,completion.reference,completion.run_id,'final-receipt'))
    if report['status']!='PASS' or report['run_id']!=completion.run_id:raise ValueError('nonpassing child receipt')
    events=[validate_event(completion.root,reference,completion.run_id) for reference in report['command_event_refs']]
    identities=[(v['sequence'],v['phase']) for v in events]
    if len(set(identities))!=len(identities) or {v['sequence'] for v in events}!=set(range(1,1+max([v['sequence'] for v in events],default=0))):raise ValueError('duplicate/missing command sequence')
    for seq in {v['sequence'] for v in events}:
        phases={v['phase'] for v in events if v['sequence']==seq}
        if phases!={'reserved','collected','complete'}:raise ValueError('incomplete child command lifecycle')
    for key in ['static_binding_ref','required_inventory_ref']:read_reference(completion.root,report[key],completion.run_id)
    reader=ProjectionReader(completion.root,completion.run_id)
    for key,kind in [('dynamic_sidecar_refs','source-projection'),('result_event_refs','result-event')]:
        for reference in report[key]:reader.reference(reference,kind)
    return report

class ParentEvents:
    """Parent-owned finite rows and validated child references, never child histories."""
    def __init__(self,root,bindings,required):
        self.journal=EventJournal(root);self.cache={};self.previous={};self.required=required
        self.journal.seal(bindings,[dict(id=r['id'],status='NOT_RUN',required_phases=['reserved','complete'],oracle='successful producer return and durable validated child receipt') for r in required])
    def reserve_row(self,row):
        if self.journal.failed:raise self.journal.last_failure
        ident=row['id']
        if ident in self.previous:raise self.journal.fail(ValueError('duplicate parent row dispatch'))
        self.previous[ident]=self.journal.result(ident,'reserved',dict(row=copy.deepcopy(row)))
    def child(self,module,completion,ident):
        report=module.accept_finalized(completion)
        reference=dict(child_id=ident,root=str(completion.root),receipt_ref=copy.deepcopy(completion.reference),producer_return='OBSERVED_SUCCESS')
        return report,reference
    def checkpoint(self,report):
        for row in report['required']+report.get('combined_helpers',[]):
            ident=row['id'];digest=hashed(row)
            if self.cache.get(ident)==digest:continue
            if row['status']=='PASS':
                if ident not in self.previous:raise self.journal.fail(ValueError('unreserved parent completion'))
                if not row.get('child_reference'):raise self.journal.fail(ValueError('parent completion requires child reference'))
                phases=self.journal.result_phases.get(ident,[])
                if 'complete' not in phases:self.previous[ident]=self.journal.result(ident,'complete',dict(row=copy.deepcopy(row)),self.previous[ident])
            self.journal.sidecar('parent-row/'+ident,dict(row=copy.deepcopy(row)));self.cache[ident]=digest
        for row in report.get('clients',[]):
            if set(row)!={'id','input','compiler','mode','client','child_reference'}:raise self.journal.fail(ValueError('parent clients must contain only identity and child reference'))
            key='client/'+row['id'];digest=hashed(row)
            if self.cache.get(key)!=digest:self.journal.sidecar(key,dict(row=row));self.cache[key]=digest
    def finish(self,report):
        self.checkpoint(report)
        if report['status']=='PASS' and any(r['status']!='PASS' for r in report['required']+report.get('combined_helpers',[])):raise self.journal.fail(ValueError('parent required denominator incomplete'))
        return self.journal.finish(report)
    def abort(self,error,report):
        failure=self.journal.fail(error,getattr(error,'custody',None));report['status']='INCOMPLETE';report['exception']=dict(type=type(error).__name__,message=str(error)[:1024],custody=failure.custody,failures=failure.failures)
        if not self.journal.final_attempted:
            try:self.journal.finish(report)
            except BaseException as later:self.journal.fail(later)
        return self.journal.emergency(failure)

def fixed_obligations():
    items=[]
    def add(ident,kind,phases,oracle,**extra):items.append(dict(id=ident,kind=kind,status='NOT_RUN',required_phases=phases,oracle=oracle,**extra))
    modes=['default','minimal','core-default','core-minimal','json-union'];bpfmodes=['default','no-default','json'];retained=['tt01-inventory','tt01-selection','tt02-run','tt02-receipt'];clients=['bp03-cache','bp03-populations']
    bpfcore=['all_zero_supported','ignores_excluded_hits','missing_own_thread_accepted','extra_own_or_expected_zero_accepted','exclusion_prerequisite_omitted','incomplete_overwrites_known_failure']+['context_field_omitted-'+x for x in ['kernel','btf-value','btf-presence','architecture','namespace','security','topology','object','profile']]+['ID_normalized','truncates_payload_or_diagnostics','stages_collapsed']
    bpfjson=['import_recreates_local_origin','duplicate_last_wins','unknown_ignored','encoder_counts_before_work','decoder_scans_before_work']
    adaptercore=['invocation_limits_ignored','implicit_work_from_time','ID_to_normalized','ID_from_normalized'];adapterjson=['per_record_budget_reset','prefix_peak_omitted']
    for origin in ['source','archive']:
     for version in ['1.88.0','1.98.1']:
      context=origin+'/'+version
      for mode in modes:
       stem=context+'/testkit/'+mode;add(stem,'library-cell',['reserved','complete'],'manifest+metadata-target+lib+integration+doc',input=origin,compiler=version,mode=mode,subsystem='testkit')
       for name in retained:add(stem+'/retained/'+name,'retained-client',['reserved','complete'],'actual unchanged TT01/TT02 consumer completion',mode=mode)
       if mode in ['core-default','core-minimal','json-union']:
        for client in clients:
         add(context+'/bp03/'+mode+'/'+client,'bp03-positive-client',['reserved','complete'],'actual direct+adapter same package ID; externally required completion groups',client=client,mode=mode)
         if mode=='json-union':add(context+'/client-json/omitted/'+client,'omitted-client-json',['reserved','negative-executed','coverage-refused','restored-positive','complete'],'BP03_CLIENT_JSON_COVERAGE_MISSING; exact missing groups and accepted_groups=[]; restored actual group PASS',client=client)
         else:add(context+'/client-json/core/'+mode+'/'+client,'core-client-json',['reserved','refused-before-cargo','restored-admission','complete'],'BP03_CLIENT_JSON_MODE_MISMATCH; no Cargo/payload; restored [] admission',client=client)
      for mode in bpfmodes:
       add(context+'/bpf/'+mode,'library-cell',['reserved','complete'],'manifest+metadata-target+lib+inherited host+capability+doc+two examples',input=origin,compiler=version,mode=mode,subsystem='bpf')
       add(context+'/bpf/'+mode+'/bpf-contracts','bpf-contract-client',['reserved','complete'],'actual inherited BPF contract consumer')
      for helper in ['bpf-public','adapter']:
       add(context+'/controls/'+helper,'control-helper',['reserved','complete'],'successful producer return + durable validated receipt; all fixed nested controls')
      for mode in ['default','minimal','json']:
       for ident in bpfcore+(bpfjson if mode=='json' else []):add(context+'/controls/bpf-public/'+mode+'/'+ident,'bpf-semantic-control',['reserved','wrong-executed','source-restored','restored-positive','complete'],'intended named assertion from frozen selector table; exact restored positive')
       for ident,codes in [('bp03_private',['E0308','E0616','E0423']),('bp03_default',['E0599']),('bp03_deserialize',['E0277']),('bp03_native_owner',['E0308'])]:add(context+'/controls/bpf-public/'+mode+'/'+ident,'bpf-compile-control',['reserved','refused-compile','positive-reference','complete'],'exact intended owned public boundary diagnostics; same-mode positive binding',codes=codes)
      for mode in ['core-default','core-minimal','json-union']:
       for ident in adaptercore+(adapterjson if mode=='json-union' else []):add(context+'/controls/adapter/'+mode+'/'+ident,'adapter-semantic-control',['reserved','wrong-executed','source-restored','restored-positive','complete'],'intended named adapter assertion and exact restored positive')
      add(context+'/controls/adapter/json-union/allocation_remapped_to_malformed','adapter-semantic-control',['reserved','fault-setup-positive','wrong-executed','source-restored','restored-positive','complete'],'codec.error-stage; valid actual imported record, real allocation seam')
      add(context+'/controls/adapter/wrong_library_copy','adapter-binding-control',['reserved','refused-before-cargo','source-restored','restored-metadata','complete'],'actual same-version foreign optional path rejected before Cargo, restored single-ID metadata')
    return items

def local_obligations(kind,version='1.88.0',input_kind='source'):
    rows=fixed_obligations();prefix=input_kind+'/'+version+'/'
    if kind=='BP03_BPF_PUBLIC_CONTROLS':selected=[r for r in rows if r['id'].startswith(prefix+'controls/bpf-public/')]
    elif kind=='BP03_ADAPTER_SOURCE_CONTROLS':selected=[r for r in rows if r['id'].startswith(prefix+'controls/adapter/')]
    elif kind=='BP03_PACKAGE_CONSUMERS':selected=[r for r in rows if r['id'].startswith(prefix) and r['kind'] in ['bp03-positive-client','omitted-client-json','core-client-json']]
    else:raise ValueError('explicit required inventory needed for focused or parent run')
    return selected

LEASE_CHILD='''import json,os,sys
rows=[]
for name in os.listdir('/proc/self/fd'):
 try:
  target=os.readlink('/proc/self/fd/'+name)
  if target.endswith('.lock'):
   s=os.fstat(int(name));rows.append(dict(fd=int(name),path=target,device=s.st_dev,inode=s.st_ino,pid=os.getpid()))
 except OSError:pass
with open(sys.argv[1],'x') as f:json.dump(rows,f)
os.execvpe(sys.argv[2],sys.argv[2:],os.environ)
'''
_ACCEPTED_COLLECTOR_CODE=_bounded_run.__code__

def execute(argv,cwd,env,stem,wrapper,*,record=None,checkpoint=None,timeout=2400,journal=None,projection=None,postprocess=None):
    """Reserve, attach exact returned custody, durably collect, then postprocess."""
    raw=list(map(str,argv));stem=Path(stem);lease_file=stem.with_suffix('.lease.json');row={} if record is None else record
    if journal is None:
        journal=EventJournal(stem.parent/('evidence-'+uuid.uuid4().hex));journal.seal(dict(kind='OWNED_TINY_COMMAND',argv=raw,cwd=str(cwd),environment=dict(env),collector_sha256=COLLECTOR_SHA256,wrapper=None if wrapper is None else dict(path=str(wrapper),sha256=sha(wrapper))),[dict(id='tiny-command',oracle='actual collector custody',status='NOT_RUN')])
    command=([str(wrapper),'--timeout','1800','--',sys.executable,'-c',LEASE_CHILD,str(lease_file),*raw] if wrapper else raw)
    row.update(id=row.get('id','tiny-command'),command=command,product_command=raw,cwd=str(cwd),environment=dict(env),process_group=None,start_unix=time.time(),exit_code=None,reason_code=None,cleanup='not_started',logs={},errors=[],wrapper_errors=[],raw_result=None,execution_status='RESERVED',command_mode='wrapped' if wrapper else 'direct',stdout=str(stem.with_suffix('.stdout')),stderr=str(stem.with_suffix('.stderr')))
    request=dict(command=command,product_command=raw,cwd=str(cwd),environment=dict(env),target=env.get('CARGO_TARGET_DIR',''),stdout_path=row['stdout'],stderr_path=row['stderr'],start_unix=row['start_unix'])
    try:
        journal.reserve(row,request,projection)
        if checkpoint is not None:checkpoint()
    except BaseException as error:
        row['wrapper_errors'].append(error_fact('reserve',error));raise journal.fail(error,row)
    try:result=_bounded_run(command,cwd,env,stem,timeout=timeout)
    except BaseException as error:
        # No callback observes successful launch. Unknown Popen-origin exceptions
        # remain reserved-only; null recorded PID is never a retirement proof.
        row['wrapper_errors'].append(error_fact('collector-exception',error));row['execution_status']='UNKNOWN_EXECUTION_CUSTODY'
        trace=error.__traceback__;known_site=None
        while trace is not None:
            if trace.tb_frame.f_code is _ACCEPTED_COLLECTOR_CODE and trace.tb_lineno in {28,42}:known_site=trace.tb_lineno
            trace=trace.tb_next
        if known_site is not None:
            proof_ref=journal.sidecar(row['id']+'/prelaunch-proof',dict(site=known_site,collector_sha256=COLLECTOR_SHA256))
            proof=dict(classification='VERIFIED_PRELAUNCH_SETUP',origin_site='collector-prelaunch-'+str(known_site),origin_source_sha256=COLLECTOR_SHA256,exception=error_fact('collector-setup',error),proof_ref=proof_ref)
            journal.event(row,'complete',dict(raw_result_ref=None,setup_proof=proof,wrapper_errors=row['wrapper_errors'],lease_ref=None,oracle_ref=None,qualification='INCOMPLETE',end_unix=time.time()))
            row['execution_status']='VERIFIED_PRELAUNCH_SETUP'
        raise journal.fail(error,row)
    row['raw_result']=result
    row.update(result);row['execution_status']='COLLECTED'
    try:
        collected=journal.event(row,'collected',dict(raw_result=result))
        if checkpoint is not None:checkpoint()
    except BaseException as error:
        row['wrapper_errors'].append(error_fact('collected-publication',error));raise journal.fail(error,row)
    lease_ref=None
    try:
        if lease_file.exists():
            with lease_file.open('rb') as stream:data=stream.read(16385)
            if len(data)>16384:raise ValueError('lease record exceeds 16384 bytes')
            leases=json.loads(data)
            if not isinstance(leases,list):raise ValueError('lease record must be an array')
            row['live_lease_identity']=leases;lease_ref=journal.sidecar(row['id']+'/lease',dict(lease=leases,raw_length=len(data),raw_sha256=hashlib.sha256(data).hexdigest()))
        if wrapper and result['exit_code']==75 and 'command not launched' in Path(row['stderr']).read_text(errors='replace'):row['execution_status']='NOT_RUN_LOCK_REFUSAL'
    except BaseException as error:
        row['wrapper_errors'].append(error_fact('lease-record',error));journal.fail(error,row)
    row.update(end_unix=time.time(),retired=result['cleanup']=='complete',timeout=result['reason_code']=='TIMEOUT',interrupted=result['reason_code']=='INTERRUPTED')
    for name in ['stdout','stderr']:row[name+'_sha256']=result['logs'].get(name,{}).get('sha256')
    qualification='INCOMPLETE' if row['wrapper_errors'] or result['reason_code'] is not None or result['cleanup']!='complete' else 'ELIGIBLE_AFTER_PRODUCER_COMPLETION'
    oracle_ref=None
    if qualification!='INCOMPLETE' and postprocess is not None:
        try:oracle_ref=postprocess(row)
        except BaseException as error:
            row['wrapper_errors'].append(error_fact('command-postprocessing',error));raise journal.fail(error,row)
    try:
        journal.event(row,'complete',dict(raw_result_ref=collected,setup_proof=None,wrapper_errors=row['wrapper_errors'],lease_ref=lease_ref,oracle_ref=oracle_ref,qualification=qualification,end_unix=row['end_unix']))
        if checkpoint is not None:checkpoint()
    except BaseException as error:
        row['wrapper_errors'].append(error_fact('complete-publication',error));raise journal.fail(error,row)
    journal.active=None
    if row['wrapper_errors']:raise journal.fail(EvidenceFailure('command postprocessing failed',row,row['wrapper_errors']),row)
    if qualification=='INCOMPLETE':journal.fail(EvidenceFailure('collector returned nonqualifying custody',row,copy.deepcopy(result['errors'])),row)
    return row

def render_manifest(template,bpf,testkit,bpf_default,testkit_default,bpf_features,testkit_features):
    values={'BPF_PACKAGE_PATH':str(bpf),'TESTKIT_PACKAGE_PATH':str(testkit),'BPF_DEFAULT_FEATURES':bpf_default,'TESTKIT_DEFAULT_FEATURES':testkit_default,'BPF_FEATURES':bpf_features,'TESTKIT_FEATURES':testkit_features}
    if any(not isinstance(v,bool) for v in [bpf_default,testkit_default]):raise ValueError('typed feature booleans')
    if not all(isinstance(v,list) and all(isinstance(s,str) for s in v) for v in [bpf_features,testkit_features]):raise ValueError('typed feature lists')
    if set(re.findall(r'__([A-Z_]+)__',template))!=set(values):raise ValueError('finite template markers')
    for key,value in values.items():template=template.replace('__'+key+'__',json.dumps(value))
    if re.search(r'__[A-Z_]+__|@[A-Z_]+@',template):raise ValueError('unknown template marker')
    parsed=tomllib.loads(template);edges=parsed['dependencies'];assert set(edges)=={'scopebase-bpf','scopebase-testkit'}
    for name,path,default,features in [('scopebase-bpf',bpf,bpf_default,bpf_features),('scopebase-testkit',testkit,testkit_default,testkit_features)]:
        if edges[name]!={'version':'=0.1.0','path':str(path),'default-features':default,'features':features}:raise ValueError('typed direct edge')
    if parsed['patch']['crates-io']!={'scopebase-bpf':{'path':str(bpf)}}:raise ValueError('same direct BPF patch')
    return template

def inspect_graph(meta,bpf,testkit,bpf_features,testkit_features):
    nodes={n['id']:n for n in meta['resolve']['nodes']};packages={p['id']:p for p in meta['packages']};active=[p for p in meta['packages'] if p['name']=='scopebase-bpf' and p['id'] in nodes]
    if len(active)!=1:raise ValueError('exactly one active BPF package ID required')
    selected=active[0];bid=selected['id']
    if selected['version']!='0.1.0' or Path(selected['manifest_path']).resolve()!=bpf.resolve()/'Cargo.toml':raise ValueError('actual direct BPF package ID/source')
    if sorted(nodes[bid]['features'])!=sorted(bpf_features):raise ValueError('raw BPF features')
    tk=next((p for p in packages.values() if p['name']=='scopebase-testkit' and p['id'] in nodes),None)
    if testkit is not None:
        if tk is None or tk['version']!='0.1.0' or Path(tk['manifest_path']).resolve()!=testkit.resolve()/'Cargo.toml':raise ValueError('actual adapter package source')
        if sorted(nodes[tk['id']]['features'])!=sorted(testkit_features):raise ValueError('raw testkit features')
        edge=[d['pkg'] for d in nodes[tk['id']]['deps'] if d['name']=='scopebase_bpf']
        if edge!=[bid]:raise ValueError('adapter BPF package ID differs')
        root=nodes[meta['resolve']['root']];direct=[d['pkg'] for d in root['deps'] if d['name']=='scopebase_bpf']
        if direct!=[bid]:raise ValueError('direct BPF package ID differs')
    return dict(package_id=bid,source=str(bpf),version=selected['version'],features=nodes[bid]['features'],adapter_id=None if tk is None else tk['id'])

MODES={'core-default':(True,True,[],['bpf-host'],['default'],['bpf-host','default']),'core-minimal':(False,False,[],['bpf-host'],[],['bpf-host']),'json-union':(False,False,['json'],['bpf-host','bpf-host-json'],['json'],['bpf-host','bpf-host-json'])}

def inventory(root):
    root=Path(root)
    return {str(p.relative_to(root)):dict(bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(root.rglob('*')) if p.is_file() and not p.is_symlink() and not any(part in {'target','.git','__pycache__'} for part in p.relative_to(root).parts)}
def absolute(path,kind='file'):
    if path is None or not path.is_absolute() or '..' in path.parts or not (path.is_dir() if kind=='dir' else path.is_file()):raise ValueError('explicit absolute '+kind+' required: '+str(path))
    return path.resolve()
def effective_configs(cwd,home,config):
    configs={config}
    for directory in [cwd,*cwd.parents]:
        for name in ['.cargo/config','.cargo/config.toml']:
            if (directory/name).is_file():configs.add(directory/name)
    for name in ['config','config.toml']:
        if (home/name).is_file():configs.add(home/name)
    if any(sha(path)!=sha(config) for path in configs):raise ValueError('undeclared effective Cargo config')
    return [dict(path=str(path),sha256=sha(path)) for path in sorted(configs)]
def offline_packages(config):
    parsed=tomllib.loads(config.read_text());source=parsed.get('source',{})
    if set(parsed)!={'source','net'} or parsed['net']!={'offline':True} or source.get('crates-io')!={'replace-with':'vendored-sources'} or set(source)!={'crates-io','vendored-sources'} or set(source['vendored-sources'])!={'directory'}:raise ValueError('finite offline vendor config required')
    vendor=absolute(Path(source['vendored-sources']['directory']),'dir');packages={}
    for directory in sorted(vendor.iterdir()):
        if not directory.is_dir() or directory.is_symlink():raise ValueError('vendor entries must be real package directories')
        checksum_path=directory/'.cargo-checksum.json';checksums=json.loads(checksum_path.read_text());manifest=tomllib.loads((directory/'Cargo.toml').read_text())['package'];key=manifest['name']+' '+manifest['version']
        if key in packages or not isinstance(checksums.get('package'),str) or not re.fullmatch('[0-9a-f]{64}',checksums['package']):raise ValueError('unique checksummed vendor package required')
        files={}
        for relative,want in checksums['files'].items():
            path=Path(relative)
            if path.is_absolute() or '..' in path.parts:raise ValueError('unsafe vendor checksum path')
            actual=directory/path
            if actual.is_symlink() or not actual.is_file() or sha(actual)!=want:raise ValueError('vendor source checksum differs '+relative)
            files[relative]=dict(bytes=actual.stat().st_size,sha256=want)
        if any(path.is_symlink() for path in directory.rglob('*')):raise ValueError('vendor symlink not admitted')
        actual={str(path.relative_to(directory)) for path in directory.rglob('*') if path.is_file()}-{'.cargo-checksum.json'}
        if actual!=set(files):raise ValueError('vendor source listing differs')
        packages[key]=dict(path=str(directory),checksum=checksums['package'],checksum_file_sha256=sha(checksum_path),source_files=len(files),inventory_sha256=hashed(files))
    return packages

def cargo_lock_path(manifest):
    for directory in [manifest.parent,*manifest.parent.parents]:
        candidate=directory/'Cargo.toml'
        if candidate.is_file() and 'workspace' in tomllib.loads(candidate.read_text()):return directory/'Cargo.lock'
    return manifest.parent/'Cargo.lock'

def lock_closure(path,packages):
    lock=tomllib.loads(path.read_text());rows=[]
    for package in lock['package']:
        source=package.get('source')
        if source is None:
            if package['name'] not in {'scopebase-bpf','scopebase-testkit','bp03-cache','bp03-populations','bp03-ui','scopebase-client','bpf-contracts'}:raise ValueError('unadmitted local lock package '+package['name'])
        elif source!='registry+https://github.com/rust-lang/crates.io-index':raise ValueError('unadmitted lock source')
        else:
            key=package['name']+' '+package['version']
            if key not in packages or package.get('checksum')!=packages[key]['checksum']:raise ValueError('lock dependency absent from checksummed offline closure '+key)
        rows.append(package)
    return dict(path=str(path),sha256=sha(path),packages=rows)

class Run:
    def __init__(self,args,kind):
        global _PUBLICATION_OWNER
        self.args=args;self.out=lexical_path(args.out)
        if self.out.exists():raise ValueError('fresh output required')
        for name in ['package','testkit_package']:
            source=getattr(args,name,None)
            if source is not None and self.out.resolve().is_relative_to(Path(source).resolve()):raise ValueError('output inside selected input')
        self.report=dict(schema_version=2,kind=kind,status='INCOMPLETE',collector_sha256=COLLECTOR_SHA256,commands=[],clients=[],controls=[])
        self.journal=EventJournal(self.out);_PUBLICATION_OWNER=self.journal;self.sequence=0;self._checkpoint_cache={};self._result_refs={};self._result_phases={};self._source_baselines={};self._lock_bindings={};self._snapshot_sequence=0
        self.config=absolute(args.cargo_config);self.home=absolute(args.cargo_home,'dir');self.tools=absolute(args.toolchain_root,'dir')/'bin';self.wrapper=None if args.build_wrapper is None else absolute(args.build_wrapper)
        for path in [self.tools/n for n in ['cargo','rustc','rustdoc']]:absolute(path)
        self.report['tools']={n:dict(path=str(self.tools/n),sha256=sha(self.tools/n)) for n in ['cargo','rustc','rustdoc']};self.report['config']=dict(path=str(self.config),sha256=sha(self.config));self.report['cargo_home']=str(self.home)
        for name,value in os.environ.items():
            if name.startswith(('CARGO_','RUST_')):
                expected={'CARGO_HOME':str(self.home),'CARGO_NET_OFFLINE':'true','CARGO_INCREMENTAL':'0','RUSTC':str(self.tools/'rustc'),'RUSTDOC':str(self.tools/'rustdoc')}
                if name not in expected or value!=expected[name]:raise ValueError('unbound inherited override '+name)
        for name in ['tmp','home','cwd']:
            fd=durable_directory(self.out/name);os.close(fd)
        self.env=dict(PATH=str(self.tools)+':/usr/bin:/bin',HOME=str(self.out/'home'),TMPDIR=str(self.out/'tmp'),CARGO_HOME=str(self.home),CARGO_NET_OFFLINE='true',CARGO_INCREMENTAL='0',RUSTC=str(self.tools/'rustc'),RUSTDOC=str(self.tools/'rustdoc'),LANG='C.UTF-8',LC_ALL='C.UTF-8')
        self.report['effective_configs']=effective_configs(self.out/'cwd',self.home,self.config);self.report['offline_config']=tomllib.loads(self.config.read_text());self.packages=offline_packages(self.config);self.report['offline_packages']=self.packages
    def seal(self,required=None):
        if not self.report.get('source_mapping') or not self.report.get('stage_workspace'):raise self.journal.fail(ValueError('stage and final workspace required before seal'))
        workspace=self.report['stage_workspace']
        if sha(workspace['path'])!=workspace['sha256']:raise self.journal.fail(ValueError('stale final stage workspace binding'))
        for source in self.report['source_mapping'].values():
            if inventory(source['copied'])!=source['inventory']:raise self.journal.fail(ValueError('staged source changed before seal'))
            for name in source['inventory']:
                with (Path(source['copied'])/name).open('rb') as stream:os.fsync(stream.fileno())
        header={k:v for k,v in self.report.items() if k not in ['commands','clients','controls','test_executables']}
        self.local_required=required or local_obligations(self.report['kind'],self.args.toolchain,'archive' if any((Path(v['copied'])/'Cargo.toml.orig').exists() for v in self.report['source_mapping'].values()) else 'source')
        self.journal.seal(dict(report_header=header,environment=self.env,wrapper=None if self.wrapper is None else dict(path=str(self.wrapper),sha256=sha(self.wrapper)),collector_sha256=COLLECTOR_SHA256),self.local_required)
        self._checkpoint_cache={k:hashed(v) for k,v in header.items()};self.checkpoint()
    def result_phase(self,row,phase,collection='controls'):
        if not self.journal.sealed:return
        if 'obligation_id' in row:ident=row['obligation_id']
        else:
            candidates=self.local_required
            if collection=='clients':candidates=[r for r in candidates if r['kind'] in ['bp03-positive-client','retained-client'] and r.get('mode')==row.get('mode') and (r.get('client')=='bp03-'+row.get('client','') or r['id'].endswith('/retained/'+row.get('client','')))]
            elif row.get('id') in ['core_with_client_json','omitted_client_json']:
                kind='core-client-json' if row['id']=='core_with_client_json' else 'omitted-client-json';candidates=[r for r in candidates if r['kind']==kind and r.get('client')==row.get('client') and (kind=='omitted-client-json' or r.get('mode')==row.get('mode'))]
            else:candidates=[r for r in candidates if r['id'].endswith('/'+str(row.get('id'))) and (not row.get('mode') or '/'+row['mode']+'/' in r['id'])]
            if len(candidates)!=1:raise self.journal.fail(ValueError('result must bind one presealed obligation '+str(row.get('id'))))
            ident=candidates[0]['id'];row['obligation_id']=ident
        previous=self._result_refs.get(ident)
        if previous is None and phase!='reserved':self.result_phase(row,'reserved',collection);previous=self._result_refs[ident]
        if phase in self._result_phases.get(ident,set()):return
        reference=self.journal.result(ident,phase,dict(result=copy.deepcopy(row)),previous);self._result_refs[ident]=reference;self._result_phases.setdefault(ident,set()).add(phase)
    def checkpoint(self):
        if not self.journal.sealed:return
        for collection in ['clients','controls']:
            if not self.report[collection]:continue
            row=self.report[collection][-1];self.result_phase(row,'reserved',collection)
            if row.get('status')=='KILLED_SEMANTIC' and row.get('id')!='omitted_client_json':self.result_phase(row,'wrong-executed',collection)
            if 'restored_source_sha256' in row:self.result_phase(row,'source-restored',collection)
            if row.get('restored')=='PASS' and row.get('id')!='wrong_library_copy':self.result_phase(row,'restored-positive',collection)
            if row.get('status')=='PASS' or row.get('restored')=='PASS':self.result_phase(row,'complete',collection)
            key=collection+'/'+str(len(self.report[collection])-1);digest=hashed(row)
            if self._checkpoint_cache.get(key)!=digest:self.journal.sidecar(key,dict(result=row));self._checkpoint_cache[key]=digest
        for key,value in self.report.items():
            if key in ['commands','clients','controls','status']:continue
            current=value[-1:] if key=='test_executables' else value
            digest=hashed(current)
            if self._checkpoint_cache.get(key)!=digest:self.journal.sidecar('report-field/'+key,dict(field=key,value=current));self._checkpoint_cache[key]=digest
        if self.report['commands']:
            row=self.report['commands'][-1];key='command/'+row['id'];digest=hashed(row)
            if self._checkpoint_cache.get(key)!=digest:self.journal.sidecar(key,dict(command=row));self._checkpoint_cache[key]=digest
    def snapshot_file(self,path):
        path=Path(path);self._snapshot_sequence+=1;destination=self.out/'snapshots'/('%06d'%self._snapshot_sequence)/path.name;fd=durable_directory(destination.parent);os.close(fd)
        with path.open('rb') as source,destination.open('xb') as target:
            shutil.copyfileobj(source,target);target.flush();os.fsync(target.fileno())
        fd=durable_directory(destination.parent);os.close(fd)
        return file_reference(self.out,destination,'source-snapshot',self.journal.run_id)
    def source_projection(self,cwd,argv,command_id):
        manifests=[];argv=list(map(str,argv));manifest=Path(argv[argv.index('--manifest-path')+1]) if '--manifest-path' in argv else cwd/'Cargo.toml'
        if manifest.is_file():manifests.append(manifest)
        trees=[];seen=set()
        while manifests:
            current=manifests.pop();root=current.parent.resolve()
            if root in seen:continue
            if len(seen)>=8:raise ValueError('local source projection bound')
            seen.add(root);data=tomllib.loads(current.read_text())
            for edge in list(data.get('dependencies',{}).values())+list(data.get('patch',{}).get('crates-io',{}).values()):
                if isinstance(edge,dict) and 'path' in edge:manifests.append((root/edge['path']).resolve()/'Cargo.toml')
            current_inventory=inventory(root);baseline=self._source_baselines.get(str(root));changed={}
            if baseline is None:
                files={name:self.snapshot_file(root/name) for name in current_inventory};reference=self.journal.sidecar(str(root)+'/baseline',dict(root=str(root),inventory=current_inventory,files=files));baseline=(current_inventory,reference);self._source_baselines[str(root)]=baseline
            else:
                for name,value in current_inventory.items():
                    if baseline[0].get(name)!=value:changed[name]=dict(record=value,bytes_ref=self.snapshot_file(root/name))
            trees.append(dict(root=str(root),baseline_ref=baseline[1],changed=changed,removed=sorted(set(baseline[0])-set(current_inventory))))
        extra={}
        if manifest.is_file():
            workspace=cargo_lock_path(manifest).parent/'Cargo.toml'
            if workspace.is_file():extra['workspace']=dict(path=str(workspace),sha256=sha(workspace),bytes_ref=self.snapshot_file(workspace))
        program=Path(argv[0])
        if program.is_file():extra['program']=dict(path=str(program),bytes=program.stat().st_size,sha256=sha(program))
        return self.journal.sidecar('command-projection',dict(source_trees=trees,extra=extra,cwd=str(cwd),product_command=argv,command_sequence=self.journal.sequence+1,obligation_id=command_id))
    def command(self,name,argv,cwd=None,target=None,expected=0,*,postprocess=None):
        if not self.journal.sealed or self.journal.failed:raise self.journal.fail(ValueError('dispatch requires sealed healthy journal'))
        if any(row['id']==name for row in self.report['commands']):raise self.journal.fail(ValueError('duplicate command ID'))
        cwd=Path(cwd or self.out/'cwd').resolve();configs=effective_configs(cwd,self.home,self.config);row=dict(id=name,effective_configs=configs);self.report['commands'].append(row)
        try:
            projection=self.source_projection(cwd,argv,name);env=dict(self.env,CARGO_TARGET_DIR=str(target or self.out/'targets'/name));stem=self.out/'logs'/name
            execute(argv,cwd,env,stem,self.wrapper,record=row,journal=self.journal,projection=projection,postprocess=postprocess)
            if row['reason_code'] is not None or row['cleanup']!='complete' or row['wrapper_errors']:raise self.journal.fail(ValueError('command custody/incomplete '+name),row)
            if (row['exit_code']==0)!=(expected==0):raise self.journal.fail(ValueError('unexpected command result '+name),row)
            self.checkpoint();return row,stdout(row)
        except BaseException as error:raise self.journal.fail(error,row)
    def cargo(self,name,args,cwd,target=None,expected=0):
        manifest=Path(args[args.index('--manifest-path')+1]) if '--manifest-path' in args else Path(cwd)/'Cargo.toml';lock=cargo_lock_path(manifest);binding=None
        if '--locked' in args:
            binding=lock_closure(lock,self.packages);known=self._lock_bindings.get(str(lock))
            if known is None or known['sha256']!=binding['sha256']:raise self.journal.fail(ValueError('changed or unvalidated generated lock'))
            binding['bytes_ref']=known['bytes_ref'];read_reference(self.out,binding['bytes_ref'],self.journal.run_id,'source-snapshot')
        def postprocess(row):
            nonlocal binding
            if args[0]=='generate-lockfile':
                binding=lock_closure(lock,self.packages);binding['bytes_ref']=self.snapshot_file(lock)
                if binding['bytes_ref']['sha256']!=binding['sha256'] or tomllib.loads(read_reference(self.out,binding['bytes_ref'],self.journal.run_id,'source-snapshot').decode())['package']!=binding['packages']:raise ValueError('generated lock changed during validation/snapshot')
            if binding is not None:
                row['lock_binding']=binding;row['lock_binding_ref']=self.journal.sidecar(name+'/validated-lock',binding)
                if args[0]=='generate-lockfile':self._lock_bindings[str(lock)]=binding
                return row['lock_binding_ref']
        return self.command(name,[self.tools/'cargo',*args,'--config',self.config],cwd,target,expected,postprocess=postprocess)
    def test(self,name,args,cwd,target,expected=0):
        if args[0]!='test' or args[-1].startswith('-'):raise ValueError('one explicit test filter required')
        selected=args[-1];_,output=self.cargo(name+'-compile',args[:-1]+['--no-run','--message-format=json'],cwd,target);artifacts=[json.loads(line) for line in output.splitlines() if line.strip()];binaries=[Path(v['executable']) for v in artifacts if v.get('reason')=='compiler-artifact' and v.get('executable') and v.get('profile',{}).get('test')]
        if len(binaries)!=1:raise self.journal.fail(ValueError('one actual selected test executable required'))
        actual=binaries[0];retained=self.out/'test-executables'/name;fd=durable_directory(retained.parent);os.close(fd)
        if retained.exists():raise FileExistsError(retained)
        shutil.copy2(actual,retained)
        with retained.open('rb') as stream:os.fsync(stream.fileno())
        if sha(actual)!=sha(retained):raise self.journal.fail(ValueError('retained test executable differs'))
        binding=dict(build_command=name+'-compile',test_filter=selected,actual_path=str(actual),retained_path=str(retained),sha256=sha(retained),bytes=retained.stat().st_size);self.report.setdefault('test_executables',[]).append(binding);self.checkpoint();row,output=self.command(name,[retained,selected,'--nocapture'],cwd,target,expected)
        if sha(retained)!=binding['sha256']:raise self.journal.fail(ValueError('test executable changed during execution'),row)
        row['test_executable']=binding;self.checkpoint();return row,output+Path(row['stderr']).read_text(errors='replace')
    def versions(self):
        for tool in ['cargo','rustc','rustdoc']:
            _,text=self.command(tool+'-version',[self.tools/tool,'--version'])
            if not text.startswith(tool+' '+self.args.toolchain+' '):raise self.journal.fail(ValueError('tool version/root mismatch'))
    def finish(self,status):
        global _PUBLICATION_OWNER
        self.report['status']=status
        try:
            if not (status=='INCOMPLETE' and self.journal.failed):self.checkpoint()
            return self.journal.finish(self.report)
        finally:_PUBLICATION_OWNER=None
    def abort(self,error):
        failure=self.journal.fail(error,self.journal.active or (self.report['commands'][-1] if self.report['commands'] else {}));self.report['exception']=dict(type=type(error).__name__,message=str(error)[:1024],custody=failure.custody,failures=failure.failures);self.report['status']='INCOMPLETE'
        if not self.journal.final_attempted:
            try:self.finish('INCOMPLETE')
            except BaseException as later:failure.failures.extend(getattr(later,'failures',[error_fact('final-failure',later)]))
        return self.journal.emergency(failure)

def arguments(testkit=False):
    p=argparse.ArgumentParser(description='BP03 bounded descriptive model delivery')
    p.add_argument('--package',required=True,type=Path)
    if testkit:p.add_argument('--testkit-package',required=True,type=Path)
    p.add_argument('--out',required=True,type=Path);p.add_argument('--toolchain',required=True,choices=['1.88.0','1.98.1']);p.add_argument('--toolchain-root',required=True,type=Path);p.add_argument('--cargo-home',required=True,type=Path);p.add_argument('--cargo-config',required=True,type=Path);p.add_argument('--build-wrapper',type=Path)
    return p

def canonical(value):return json.dumps(value,separators=(',',':'),ensure_ascii=True).encode()
def hashed(value):return hashlib.sha256(canonical(value)).hexdigest()
def measured_file(path,ident,role):return dict(id=ident,revision=1,role=role,length=str(path.stat().st_size),sha256=sha(path))

def stage_pair(run,bpf,testkit=None):
    originals={'scopebase-bpf':absolute(bpf,'dir')}
    if testkit is not None:originals['scopebase-testkit']=absolute(testkit,'dir')
    stage=run.out/'stage';stage.mkdir();bound={}
    for name,source in originals.items():
        before=inventory(source);destination=stage/name
        shutil.copytree(source,destination,ignore=shutil.ignore_patterns('target','.git','__pycache__'))
        after=inventory(destination)
        if before!=after:raise ValueError('source/package copy differs')
        bound[name]=destination;run.report.setdefault('source_mapping',{})[name]=dict(original=str(source),copied=str(destination),inventory=before,inventory_sha256=hashed(before))
    (stage/'Cargo.toml').write_text('[workspace]\nresolver="2"\nmembers='+json.dumps(list(bound))+'\n'+('[patch.crates-io]\nscopebase-bpf={path="scopebase-bpf"}\n' if testkit is not None else ''))
    run.report['stage_workspace']=dict(path=str(stage/'Cargo.toml'),sha256=sha(stage/'Cargo.toml'));run.checkpoint()
    return bound

def inspect_packages(bpf,testkit=None):
    d=tomllib.loads((bpf/'Cargo.toml').read_text());p=d['package']
    if (p['name'],p['version'],p['edition'],p['rust-version'],p['license'],p['build'],p['autotests'],p['autoexamples'])!=('scopebase-bpf','0.1.0','2021','1.88.0','Apache-2.0',False,False,False):raise ValueError('BPF package identity/target discovery')
    if d['features']!={'default':[],'json':['dep:serde','dep:serde_json']}:raise ValueError('BPF exact feature declarations')
    if d.get('dependencies')!={'serde':{'version':'=1.0.229','default-features':False,'features':['std'],'optional':True},'serde_json':{'version':'=1.0.151','default-features':False,'features':['std'],'optional':True}}:raise ValueError('BPF exact JSON edges')
    expected_tests={name:dict(name=name,path='tests/'+name+'.rs') for name in ['api_contract','maps_pure','maps_contract','maps_live','maps_mounts','who_preservation','capability']};expected_tests['capability_json']=dict(name='capability_json',path='tests/capability_json.rs',**{'required-features':['json']})
    expected_examples={name:dict(name=name,path='examples/'+name+'.rs') for name in ['possible_topology','who_map_reader','bp02_live_fixture','capability_cache','filter_assessment']}
    for kind,expected in [('test',expected_tests),('example',expected_examples)]:
        rows=[]
        for original in d.get(kind,[]):
            row=dict(original)
            if 'doc-scrape-examples' in row:
                if row.pop('doc-scrape-examples') is not False:raise ValueError('normalized target flags')
            rows.append(row)
        if len(rows)!=len(expected) or {row['name']:row for row in rows}!=expected:raise ValueError('exact BPF target declarations')
        for row in rows:
            if '..' in Path(row['path']).parts or not (bpf/row['path']).is_file():raise ValueError('missing BPF target source')
    if 'fixtures/capability-v1/**' not in p['include']:raise ValueError('missing primary BPF fixtures include')
    expected={'rustix':('=1.1.5',{'std','fs','process','thread','linux_4_11'}),'libc':('=0.2.191',{'std'}),'sha2':('=0.11.0',set())}
    target=d.get('target',{});key='cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu", target_pointer_width = "64", target_endian = "little"))'
    if list(target)!=[key] or set(target[key]['dependencies'])!=set(expected):raise ValueError('inherited cfg declarations')
    for name,(version,features) in expected.items():
        edge=target[key]['dependencies'][name]
        if edge['version']!=version or edge['default-features'] is not False or set(edge.get('features',[]))!=features or set(edge)-{'version','features','default-features'}:raise ValueError('inherited cfg edge '+name)
    if testkit is not None:
        t=tomllib.loads((testkit/'Cargo.toml').read_text());edge=t['dependencies']['scopebase-bpf']
        if t['package']['name']!='scopebase-testkit' or t['package']['version']!='0.1.0' or t['features']!={'default':[],'bpf-host':['dep:scopebase-bpf'],'bpf-host-json':['bpf-host','scopebase-bpf/json']}:raise ValueError('testkit identity/features')
        expected_inherited={'serde':{'version':'=1.0.229','default-features':False,'features':['std','derive']},'serde_json':{'version':'=1.0.151','default-features':False,'features':['std']},'sha2':{'version':'=0.11.0','default-features':False}}
        if {name:value for name,value in t['dependencies'].items() if name!='scopebase-bpf'}!=expected_inherited:raise ValueError('inherited testkit direct edges')
        if edge['version']!='=0.1.0' or edge['default-features'] is not False or edge['optional'] is not True or set(edge)-{'version','default-features','optional','path'}:raise ValueError('exact optional adapter edge')
        if 'path' in edge and (testkit/edge['path']).resolve()!=bpf.resolve():raise ValueError('source adapter edge must resolve to same BPF package')
        if [x for x in t['test'] if x['name']=='bpf_host']!=[{'name':'bpf_host','path':'tests/bpf_host.rs','required-features':['bpf-host']}]:raise ValueError('explicit gated testkit target')
    return dict(bpf_manifest_sha256=sha(bpf/'Cargo.toml'),bpf_original_manifest_sha256=sha(bpf/'Cargo.toml.orig') if (bpf/'Cargo.toml.orig').exists() else None,testkit_manifest_sha256=None if testkit is None else sha(testkit/'Cargo.toml'))

CASE_DEFINITIONS=[('H22.model-filter','assess-filter',['filter.state','filter.not-native-support']),('H22.model-profile-bridge','to-testkit-profile',['profile.result','profile.bytes-unchanged']),('H22.model-context','context-applies',['context.applies','context.not-authority']),('H22.model-origin','import-observation',['origin.imported','origin.claim-preserved']),('H33.model-description','import-observation',['description.fields','cause.not-authenticated']),('H22.model-json','import-observation',['json.result','json.no-authority'])]

def make_catalog(testkit,full):
    paths={'case-source':('src/bpf/adapter.rs','BpfHostAdapter.execute'),'fixture-source':('tests/fixtures/bp03/bundle-template.json','VectorFixtureSession.prepare'),'oracle-source':('tests/fixtures/bp03/clients/populations/src/oracle.rs','LiteralOracle.evaluate'),'control-source':('tests/fixtures/bp03/run_consumers.py','adapter_controls')}
    registration={}
    for key,(path,entry) in paths.items():registration[key]=dict(id=key,revision=1,path=path,sha256=sha(testkit/path),entrypoint=entry)
    profile='bp03-host-json-models-v1' if full else 'bp03-host-models-v1';cases=[]
    for ident,_,assertions in CASE_DEFINITIONS[:6 if full else 2]:
        family=ident.split('.')[0];cases.append(dict(id=ident,family=family,version=1,implementation_status='REGISTERED_EXECUTABLE',owners=['BP03'],obligations=[],required_cells=['model'],registration=dict(executable=registration['case-source'],fixture=registration['fixture-source'],oracle=registration['oracle-source'],bad_control=registration['control-source'],oracle_basis='independent-literal-vector',control_assertion=assertions[0])))
    cases.sort(key=lambda c:c['id']);families=['H22','H33'] if full else ['H22'];return dict(schema_version=1,catalog_revision=1,tasks=['BP03'],obligations=[dict(kind='regression_family',id=f,description='T0 supplied descriptive model only',owners=['BP03']) for f in families],families=[dict(id=f,short_contract='T0 descriptive model; no native support',obligations=[dict(kind='regression_family',id=f)]) for f in families],cells=[dict(id='model',tier='T0',description='descriptive supplied model',binding='LOGICAL_ONLY')],cases=cases,profiles=[dict(id=profile,definition_state='FROZEN',requires_profiles=[],requires_extensions=[],required_cases=[dict(case_id=c['id'],case_version=1,when_extensions=[]) for c in cases],open_owners=[])],extensions=[])

RUN_LIMITS={k:str(v) for k,v in dict(input_bytes=8388608,observation_bytes=8388608,vector_bytes=8388608,receipt_bytes=8388608,retained_bytes=67108864,diagnostic_bytes=65536,name_bytes=256,label_bytes=96,measure_file_bytes=268435456,measure_total_bytes=1073741824,read_calls=65536,measurement_attempts=4096,case_attempts=4096,steps_per_invocation=64,steps_total=65536,attempts_per_case=16,assertions_per_case=64,coverage_per_case=64,effects_per_case=64,assertion_records=65536,coverage_records=65536,effects_total=4096,features=256,artifacts=4096,input_slots=16,script_parameters=16,resource_views=64,scalar_bytes=4096,json_depth=32,json_edges=262144,execution_ms=30000,retirement_ms=5000).items()}

def bind_models(run,bpf,testkit,project,binary,metadata,mode):
    full=mode=='json-union';root=project/'models';root.mkdir();corpus=bpf/'fixtures/capability-v1'
    catalog=make_catalog(testkit,full);catalog_bytes=canonical(catalog);(root/'catalog.json').write_bytes(catalog_bytes)
    profile=catalog['profiles'][0]['id'];selected=catalog['cases'];selection=dict(requested=profile,profiles=[profile],extensions=[],required=[dict(case_id=c['id'],case_version=1,cell_id='model',tier='T0',implementation_status='REGISTERED_EXECUTABLE',required_by=[profile]) for c in selected],open_owners=[],definition_complete=True)
    filters=json.loads((corpus/'filter-inputs.json').read_text());filter_expected=json.loads((corpus/'filter-expected.json').read_text());profiles=json.loads((corpus/'profile-inputs.json').read_text());profile_expected=json.loads((corpus/'profile-expected.json').read_text());contexts=json.loads((corpus/'context-inputs.json').read_text());context_expected=json.loads((corpus/'context-expected.json').read_text());observations=json.loads((corpus/'observation-inputs.json').read_text());codec=json.loads((corpus/'observation-expected.json').read_text())['codec_cases']
    if len(filters)!=38 or len(profiles)!=23 or len(codec)!=22:raise ValueError('fixed primary corpus denominator')
    primary_index=json.loads((corpus/'index.json').read_text())
    for row in primary_index['files']:
        path=corpus/row['path']
        if path.stat().st_size!=row['bytes'] or sha(path)!=row['sha256']:raise ValueError('primary corpus identity '+row['path'])
    source=inventory(bpf);build=dict(metadata_sha256=hashed(metadata),manifest_sha256=sha(project/'Cargo.toml'),lock_sha256=sha(project/'Cargo.lock'),tools=run.report['tools'],config=run.report['config'],client_sources=inventory(project/'src'))
    subject=dict(package_name='scopebase-bpf',package_version='0.1.0',source_sha256=hashed(source),build_inputs_sha256=hashed(build),features=MODES[mode][4],backend=None,host='x86_64-unknown-linux-gnu',target='x86_64-unknown-linux-gnu',consumer=dict(name='bp03-populations',build_inputs_sha256=hashed(build),executable_sha256=sha(binary)),objects=[measured_file(corpus/'codec/valid-base.bytes','fixture-object','fixture_input')],provenance=dict(kind='generated_build',manifest_sha256=sha(project/'Cargo.toml'),measurement_sha256=hashed(build)))
    oracle=dict(id='literal-model-oracle',revision=1,schema_id='bp03-model-result',source_sha256=sha(project/'src/oracle.rs'),artifact_id='oracle-source',provenance=subject['provenance'])
    registrations=[]
    for ident,path,role in [('case-source',testkit/'src/bpf/adapter.rs','case_source'),('fixture-source',testkit/'tests/fixtures/bp03/bundle-template.json','fixture_manifest'),('oracle-source',project/'src/oracle.rs','oracle_source'),('control-source',testkit/'tests/fixtures/bp03/run_consumers.py','control_source')]:registrations.append(measured_file(path,ident,role))
    for index in range(38):
        directory=root/('set-%03d'%index);(directory/'files').mkdir(parents=True);run_id=hashed(dict(build=build,index=index))[:32];rules=[];files=[];artifacts=list(registrations)+subject['objects'];invocations=[]
        for schedule_index,case in enumerate(selected):
            ident=case['id'];number=next(n for n,r in enumerate(CASE_DEFINITIONS) if r[0]==ident);_,operation,assertions=CASE_DEFINITIONS[number];schema='bp03-host-v1';inputs={};expected=None
            if number==0:
                row=filters[index];want=filter_expected[index]
                if row['id']!=want['id']:raise ValueError('filter input/expected pairing')
                inputs={'counts':row['input_ascii'].encode()};expected=b'observed\n'+want['adapter_bytes_ascii'].encode()
            elif number==1:
                row=profiles[index%23];want=profile_expected[index%23]
                if row['id']!=want['id']:raise ValueError('profile input/expected pairing')
                operation=row['operation'];inputs={'profile':row['input_ascii'].encode()};expected=b'observed\n'+want['expected_bytes_ascii'].encode()
            elif number==2:
                row=contexts['cases'][index%len(contexts['cases'])];want=context_expected[index%len(context_expected)]
                if row['id']!=want['id']:raise ValueError('context input/expected pairing')
                inputs={'base':canonical(contexts['base']),'candidate':canonical(row['candidate'])};expected=b'observed\n'+(b'true' if want['expected_applies'] else b'false');schema='bp03-host-json-v1'
            elif number==3:
                value=copy.deepcopy(observations['base_wire_object']);value['claimed_origin']='caller_described' if index%2==0 else 'imported';wire=canonical(value);inputs={'record':wire};expected=b'observed\nimported\n'+wire;schema='bp03-host-json-v1'
            elif number==4:
                row=observations['same_errno_descriptive_cause_cases'][index%len(observations['same_errno_descriptive_cause_cases'])];wire=canonical(row['input']);inputs={'record':wire};expected=b'observed\nimported\n'+wire;schema='bp03-host-json-v1'
            else:
                row=codec[index%22];raw=corpus/'codec'/Path(row['path']).name;inputs={'record':raw.read_bytes()};want=row['expected'];schema='bp03-host-json-v1'
                if want['result']=='ok':expected=b'observed\nimported\n'+observations['base_wire_ascii'].encode()
                else:
                    kind=re.sub(r'(?<!^)(?=[A-Z])','_',want['kind']).lower();stage=want['stage'].lower();diagnostic='bpf:'+kind+'/'+stage
                    if want['required_size'] is not None:diagnostic+=';required='+str(want['required_size'])
                    expected=('error\nrefused\n'+stage+'\n'+diagnostic).encode()
            key=dict(run_id=run_id,case_key=dict(case_id=ident,case_version=1,cell_id='model'),attempt=1,operation_id=str(number+1))
            script=dict(schema_version=1,kind='steps-v1',schema_id=schema,steps=[dict(step_id='only-step',operation=operation,inputs=sorted(inputs),parameters=[])])
            rules.append(dict(case_key=key['case_key'],tier='T0',observation_schema=dict(id='bp03-model-result',revision=1),fixture_schema=dict(id='bp03-fixed-input',revision=1),script=script,assertions=[dict(id=a,requires_coverage=[],requires_positive_twin=False) for a in assertions],coverage=[],intent=dict(kind='assertion_only'),attempts=1,operation_ids=[str(number+1)],max_effects=0))
            expected_id='expected-%d'%number;ledger_id='ledger-%d'%number;slot_rows=[];payloads=[(expected_id,'expected',expected),(ledger_id,'ledger',canonical(dict(schema_version=1,kind='tt02-vector-ledger',key=key,truth_kind='fixed-before-execute',evidence_tier='T0',coverage=[])))]
            for slot,data in sorted(inputs.items()):
                fid='input-%d-%s'%(number,slot);slot_rows.append(dict(slot=slot,file_id=fid));payloads.append((fid,'input',data))
            for fid,role,data in payloads:
                path=directory/'files'/(fid+'.bytes');path.write_bytes(data);record=dict(file_id=fid,role=role,length=str(len(data)),sha256=sha(path));files.append(record);artifacts.append(dict(id=fid,revision=1,role={'input':'fixture_input','expected':'expected_vector','ledger':'fixture_ledger'}[role],length=str(len(data)),sha256=sha(path)))
            invocations.append(dict(key=key,inputs=slot_rows,expected_file=expected_id,ledger_file=ledger_id))
        contract=dict(schema_version=1,kind='tt02-run-contract',run_id=run_id,catalog_sha256=hashlib.sha256(catalog_bytes).hexdigest(),catalog_revision=1,selection=selection,expected_subject=subject,expected_oracle=oracle,artifacts=sorted(artifacts,key=lambda r:r['id']),case_rules=rules,limits=RUN_LIMITS)
        contract_bytes=canonical(contract);(directory/'contract.json').write_bytes(contract_bytes);(directory/'bundle.json').write_bytes(canonical(dict(schema_version=1,kind='tt02-vector-bundle',run_contract_sha256=hashlib.sha256(contract_bytes).hexdigest(),run_id=run_id,files=sorted(files,key=lambda r:r['file_id']),invocations=invocations)))
    (root/'runs.txt').write_text(''.join('set-%03d\n'%i for i in range(38)))
    atomic_json(root/'measurement.json',dict(subject=subject,actual_direct_adapter_package_id=inspect_graph(metadata,bpf,testkit,MODES[mode][4],MODES[mode][5])['package_id'],catalog_sha256=sha(root/'catalog.json'),corpus_index_sha256=sha(corpus/'index.json'),oracle_sha256=sha(project/'src/oracle.rs'),fixed_before_execute_observes_entry_or_return=False,bpf_limits=json.loads((testkit/'tests/fixtures/bp03/bundle-template.json').read_text())['bpf_limits']))
    return root,profile


REQUIRED_JSON_GROUPS={'bp03-cache':['cache.json-import-fields-origin','cache.json-reencode-literal'],'bp03-populations':['populations.json-adapter-cases','populations.json-direct-api','populations.json-report-roundtrip']}
def mode_admission(client,mode,requested):
    expected=['json'] if mode=='json-union' else []
    if requested!=expected:return dict(status='REFUSED',code='BP03_CLIENT_JSON_MODE_MISMATCH',client=client,mode=mode,requested_client_features=requested,expected_client_features=expected)
    return dict(status='ADMITTED',client=client,mode=mode,requested_client_features=requested,expected_client_features=expected)
def completion(output,client,mode):
    rows=[line[len('BP03_COMPLETION '):] for line in output.splitlines() if line.startswith('BP03_COMPLETION ')]
    if len(rows)!=1 or len(rows[0])>1024:raise ValueError('one bounded semantic completion record required')
    row=json.loads(rows[0]);groups=row.get('groups')
    if set(row)!={'client','groups'} or row['client']!=client or not isinstance(groups,list) or any(not isinstance(v,str) for v in groups) or groups!=sorted(set(groups)):raise ValueError('typed completion record')
    required=REQUIRED_JSON_GROUPS[client] if mode=='json-union' else []
    if set(groups)-set(required):raise ValueError('unexpected semantic completion group')
    missing=sorted(set(required)-set(groups))
    if missing:return dict(status='REFUSED',code='BP03_CLIENT_JSON_COVERAGE_MISSING',client=client,missing_required_groups=missing,accepted_groups=[])
    return dict(status='PASS',client=client,required_groups=required,accepted_groups=groups)
def client_flags(mode):return ['--features','json'] if mode=='json-union' else []
def build_client(run,testkit,bpf,mode,name,project,*,omit_json=False,prefix=None):
    bd,td,bf,tf,braw,traw=MODES[mode];template=testkit/'tests/fixtures/bp03/clients'/name;shutil.copytree(template,project);manifest=project/'Cargo.toml';manifest.write_text(render_manifest((project/'Cargo.toml.in').read_text(),bpf,testkit,bd,td,bf,tf));target=project/'target';prefix=prefix or mode+'-'+name;flags=[] if omit_json else client_flags(mode);client='bp03-'+name
    requested=[] if omit_json or mode!='json-union' else ['json'];admission=mode_admission(client,mode,requested)
    if admission['status']!='ADMITTED' and not omit_json:raise ValueError(admission)
    if tomllib.loads(manifest.read_text()).get('features')!={'json':[]}:raise ValueError('exact client-own feature declaration')
    run.cargo(prefix+'-lock',['generate-lockfile','--offline','--manifest-path',manifest],project,target)
    _,text=run.cargo(prefix+'-metadata',['metadata','--offline','--locked','--format-version','1','--filter-platform','x86_64-unknown-linux-gnu','--manifest-path',manifest,*flags],project,target);metadata=json.loads(text);graph=inspect_graph(metadata,bpf,testkit,braw,traw);root_node=next(n for n in metadata['resolve']['nodes'] if n['id']==metadata['resolve']['root'])
    if root_node['features']!=requested:raise ValueError('actual client-own feature graph differs')
    atomic_json(project/'metadata.json',metadata);source_before=inventory(project/'src');_,build=run.cargo(prefix+'-build',['build','--offline','--locked','--message-format=json','--manifest-path',manifest,*flags],project,target)
    if inventory(project/'src')!=source_before:raise ValueError('client source changed during build')
    artifacts=[json.loads(line) for line in build.splitlines() if line.strip()];executables=[v for v in artifacts if v.get('reason')=='compiler-artifact' and v.get('executable') and v['target']['name']==client]
    if len(executables)!=1:raise ValueError('unique actual client executable required')
    binary=Path(executables[0]['executable']);row=dict(mode=mode,client=name,status='NOT_RUN',graph=graph,client_package_id=metadata['resolve']['root'],requested_client_features=requested,client_features=root_node['features'],cargo_feature_arguments=flags,template_sha256=sha(project/'Cargo.toml.in'),manifest_sha256=sha(manifest),lock_sha256=sha(project/'Cargo.lock'),sources=source_before,binary=dict(path=str(binary),sha256=sha(binary)),metadata_sha256=sha(project/'metadata.json'),normal_admission=admission)
    if name=='cache':command=[binary,bpf,mode]
    else:models,profile=bind_models(run,bpf,testkit,project,binary,metadata,mode);command=[binary,models,profile,bpf];row['binding_sha256']=sha(models/'measurement.json')
    return row,command,project,target,prefix

def consumers_main(argv=None):
    args=arguments(True).parse_args(argv);run=None
    try:
        run=Run(args,'BP03_PACKAGE_CONSUMERS');staged=stage_pair(run,args.package,args.testkit_package);bpf=staged['scopebase-bpf'];testkit=staged['scopebase-testkit'];run.report['manifests']=inspect_packages(bpf,testkit);run.seal();run.versions()
        for mode in MODES:
            for name in ['cache','populations']:
                client='bp03-'+name
                if mode!='json-union':
                    count=len(run.report['commands']);negative=mode_admission(client,mode,['json']);restored=mode_admission(client,mode,[])
                    if negative!=dict(status='REFUSED',code='BP03_CLIENT_JSON_MODE_MISMATCH',client=client,mode=mode,requested_client_features=['json'],expected_client_features=[]) or restored['status']!='ADMITTED' or len(run.report['commands'])!=count:raise ValueError('pre-Cargo mode control')
                    control=dict(id='core_with_client_json',mode=mode,client=client,kind='BINDING_NEGATIVE',refusal=negative,restored_admission=restored,cargo_children=0,payload_entries=0);run.report['controls'].append(control);run.result_phase(control,'reserved');run.result_phase(control,'refused-before-cargo');run.result_phase(control,'restored-admission');run.result_phase(control,'complete');run.checkpoint()
                project=run.out/'clients'/mode/name;row,command,cwd,target,prefix=build_client(run,testkit,bpf,mode,name,project);run.report['clients'].append(row);run.checkpoint();_,output=run.command(prefix+'-run',command,cwd,target);result=completion(output,client,mode)
                if result['status']!='PASS':raise ValueError(result)
                if sha(command[0])!=row['binary']['sha256']:raise ValueError('retained executable changed')
                row.update(status='PASS',completion=result,output_sha256=hashlib.sha256(output.encode()).hexdigest());run.checkpoint()
                if mode=='json-union':
                    control=dict(id='omitted_client_json',mode=mode,client=client,kind='SEMANTIC_COVERAGE_NEGATIVE',status='NOT_RUN');run.report['controls'].append(control);run.result_phase(control,'reserved');negative_project=run.out/'controls'/('omitted-client-json-'+name);negative,ncommand,ncwd,ntarget,nprefix=build_client(run,testkit,bpf,mode,name,negative_project,omit_json=True,prefix='omitted-client-json-'+name)
                    if negative['sources']!=row['sources'] or negative['manifest_sha256']!=row['manifest_sha256'] or negative['lock_sha256']!=row['lock_sha256'] or negative['graph']!=row['graph']:raise ValueError('omission must preserve source/dependency/lock projection')
                    _,wrong=run.command(nprefix+'-run',ncommand,ncwd,ntarget);refusal=completion(wrong,client,mode);expected=dict(status='REFUSED',code='BP03_CLIENT_JSON_COVERAGE_MISSING',client=client,missing_required_groups=REQUIRED_JSON_GROUPS[client],accepted_groups=[])
                    if refusal!=expected:raise ValueError('omitted client feature not semantically sensitive')
                    control.update(status='KILLED_SEMANTIC',normal_binding_bypassed_only='client-own-feature',negative=negative,semantic_refusal=refusal);run.result_phase(control,'negative-executed');run.result_phase(control,'coverage-refused');_,restored=run.command(nprefix+'-restored',command,cwd,target)
                    if completion(restored,client,mode)!=result:raise ValueError('restored semantic completion differs')
                    run.result_phase(control,'restored-positive');run.result_phase(control,'complete');run.checkpoint()
        if len(run.report['clients'])!=6 or any(r['status']!='PASS' for r in run.report['clients']):raise ValueError('required six positive client executions incomplete')
        completion=run.finish('PASS');print(json.dumps(dict(status='PASS',clients=6,receipt=str(run.out/'receipt.json'))));return completion
    except BaseException as e:
        if run is not None:
            raise run.abort(e)
        raise


def adapter_mutations():
    return [
      dict(id='invocation_limits_ignored',test='zero_work_and_binding_have_no_payload_entry',assertion='adapter.limit-binding-error',json_only=False,changes=[(r'if i\.limits\(\)\s*!=\s*&self\.run\s*\{\s*return Err\(self\.error\([\s\S]*?b"run-limits-mismatch"[\s\S]*?\)\);\s*\}','',True)]),
      dict(id='implicit_work_from_time',test='zero_work_and_binding_have_no_payload_entry',assertion='adapter.work-before-scan',json_only=False,changes=[(r'if self\.work\s*>\s*self\.work_cap','if false',True)]),
      dict(id='ID_to_normalized',test='profile_literal_receiving_domains',assertion='profile.result',json_only=False,changes=[('ProfileId::parse(v.as_str())','ProfileId::parse(&v.as_str().replace(\'/\',"-"))',False)]),
      dict(id='ID_from_normalized',test='profile_literal_receiving_domains',assertion='profile.result',json_only=False,changes=[('b::ProfileId::new(v.as_str())','b::ProfileId::new(&v.as_str().to_ascii_lowercase())',False)]),
      dict(id='per_record_budget_reset',test='joint_and_prefix_peaks_with_restored_twins',assertion='adapter.joint-retained / adapter.prefix-retained',json_only=True,changes=[(r'ledger\.remaining\(base_live\)\?','ledger.remaining(result_charge)?',True),(r'(let peak\s*=\s*checked_add\(base_live,\s*candidate\.retained_bytes\(\)\)\?\s*;)\s*ledger\.check\(peak\)\?',r'\1 ledger.check(base_live)?',True)]),
      dict(id='prefix_peak_omitted',test='joint_and_prefix_peaks_with_restored_twins',assertion='adapter.joint-retained / adapter.prefix-retained',json_only=True,changes=[(r'(let peak\s*=\s*checked_add\([^;]*?future\s*,?\s*\)\?\s*;)\s*ledger\.check\(peak\)\?',r'\1 /* wrong omitted prefix peak */',True),(r'ledger\.remaining\(future\)\?','ledger.remaining(0)?',True),(r'ledger\.check\(checked_add\(live,\s*future\)\?\)\?\s*;','',True),(r'ledger\.buffer\(prefixed,\s*live\)\?','ledger.buffer(prefixed,0)?',True)])
    ]

def apply_changes(text,changes):
    for old,new,regex in changes:
        if regex:result,count=re.subn(old,new,text)
        else:result,count=text.replace(old,new),text.count(old)
        if count!=1:raise ValueError('source control selector must match exactly once '+repr(old)+' count='+str(count))
        text=result
    return text

ALLOCATION_CONTROL_TEST=r'''
 #[test] fn injected_codec_allocation_stage(){
  let l=RunLimits::default();let mut a=BpfHostAdapter::new(subject(&l,16),limits(),l.clone()).unwrap();let i=invocation(&l,"bp03-host-json-v1","import-observation",&["record"]);let raw=literal_input::OBSERVATION_INPUT;let inputs=[FixtureInput::new(label("record"),raw)];let fixture=FixtureAccess::new(&inputs,&[],EffectBatch::empty(&l),&l).unwrap();let e=a.execute(&i,&fixture).unwrap_err();assert_eq!(e.stage().as_str(),"allocate","codec.error-stage");assert_eq!(e.diagnostic_bytes(),b"bpf:backend/allocate","codec.error-stage");full_error(&e,&i,CaseErrorCategory::Refused,"allocate",true);
 }
'''

def wrong_library_copy(run,bpf,testkit):
    # Verification requires pre-Cargo edge inspection. Distinct same-version
    # path packages need not form a successful colliding two-ID Cargo lock.
    root=run.out/'wrong-library-copy';root.mkdir();direct=root/'scopebase-bpf';foreign=root/'foreign-bpf';adapter=root/'scopebase-testkit'
    for source,target in [(bpf,direct),(bpf,foreign),(testkit,adapter)]:shutil.copytree(source,target)
    original=(adapter/'Cargo.toml').read_text();manifest=adapter/'Cargo.toml';edge=tomllib.loads(original)['dependencies']['scopebase-bpf']
    if 'path' in edge:
        pattern=r'path\s*=\s*"'+re.escape(edge['path'])+r'"';changed,count=re.subn(pattern,'path = '+json.dumps(str(foreign)),original)
        if count!=1:raise ValueError('unique actual optional-path control selector')
    else:
        token='[dependencies.scopebase-bpf]'
        if original.count(token)!=1:raise ValueError('normalized optional adapter table required')
        changed=original.replace(token,token+'\npath = '+json.dumps(str(foreign)))
    manifest.write_text(changed);before=len(run.report['commands']);reason=None
    try:inspect_packages(direct,adapter)
    except ValueError as error:reason=str(error)
    if reason!='source adapter edge must resolve to same BPF package' or len(run.report['commands'])!=before:raise ValueError('wrong-library-copy must refuse actual foreign path before Cargo')
    row=dict(id='wrong_library_copy',kind='BINDING_NEGATIVE',status='KILLED_BINDING',refusal_stage='pre-Cargo-source-edge-inspection',diagnostic=reason,cargo_children_before_refusal=0,direct=dict(path=str(direct),version=tomllib.loads((direct/'Cargo.toml').read_text())['package']['version'],inventory=inventory(direct)),foreign=dict(path=str(foreign),version=tomllib.loads((foreign/'Cargo.toml').read_text())['package']['version'],inventory=inventory(foreign)),mutated_manifest_sha256=sha(manifest),interpretation='Actual same-name/version foreign optional path refuses before qualification; successful colliding two-ID graph is not required.')
    run.report['controls'].append(row);run.result_phase(row,'reserved');run.result_phase(row,'refused-before-cargo');atomic_json(root/'negative-binding.json',row);manifest.write_text(original);row['restored_source_sha256']=sha(manifest);run.result_phase(row,'source-restored');inspect_packages(direct,adapter);(root/'Cargo.toml').write_text('[workspace]\nresolver="2"\nmembers=["scopebase-testkit"]\nexclude=["scopebase-bpf","foreign-bpf"]\n[patch.crates-io]\nscopebase-bpf={path="scopebase-bpf"}\n');target=root/'target';run.cargo('wrong-copy-restored-lock',['generate-lockfile','--offline','--manifest-path',adapter/'Cargo.toml'],adapter,target);_,text=run.cargo('wrong-copy-restored-metadata',['metadata','--offline','--locked','--format-version','1','--filter-platform','x86_64-unknown-linux-gnu','--manifest-path',adapter/'Cargo.toml','--no-default-features','--features','bpf-host'],adapter,target);metadata=json.loads(text);row['restored_graph']=inspect_graph(metadata,direct,adapter,[],['bpf-host']);row['restored_manifest_sha256']=sha(manifest);row['restored']='PASS';atomic_json(root/'restored-metadata.json',metadata);run.result_phase(row,'restored-metadata');run.result_phase(row,'complete');run.checkpoint()

def run_adapter_controls(args):
    run=None
    try:
        run=Run(args,'BP03_ADAPTER_SOURCE_CONTROLS');pair=stage_pair(run,args.package,args.testkit_package);bpf=pair['scopebase-bpf'];testkit=pair['scopebase-testkit'];run.report['manifests']=inspect_packages(bpf,testkit);run.seal();run.versions();wrong_library_copy(run,bpf,testkit)
        for mode in MODES:
            flags=(['--features','bpf-host'] if mode=='core-default' else ['--no-default-features','--features','bpf-host'] if mode=='core-minimal' else ['--no-default-features','--features','bpf-host,bpf-host-json']);base=['test','--offline','--locked','--manifest-path',testkit/'Cargo.toml',*flags];target=run.out/'targets'/mode
            run.cargo(mode+'-lock',['generate-lockfile','--offline','--manifest-path',testkit/'Cargo.toml'],testkit,target);run.cargo(mode+'-baseline',base+['--lib','--test','bpf_host'],testkit,target)
            for control in adapter_mutations():
                if control['json_only'] and mode!='json-union':continue
                ident=mode+'-'+control['id'];parent=run.out/'mutation-subjects'/mode;changed_bpf=parent/'scopebase-bpf';changed_tk=parent/'scopebase-testkit';mtarget=run.out/'mutation-targets'/mode
                if not parent.exists():
                    parent.mkdir(parents=True);shutil.copytree(bpf,changed_bpf);shutil.copytree(testkit,changed_tk);(parent/'Cargo.toml').write_text('[workspace]\nresolver="2"\nmembers=["scopebase-testkit"]\nexclude=["scopebase-bpf"]\n[patch.crates-io]\nscopebase-bpf={path="scopebase-bpf"}\n');run.cargo(mode+'-mutation-lock',['generate-lockfile','--offline','--manifest-path',changed_tk/'Cargo.toml'],changed_tk,mtarget)
                source=changed_tk/'src/bpf/adapter.rs';original=source.read_text();source.write_text(apply_changes(original,control['changes']));snapshot=run.out/'control-sources'/(ident+'.rs');snapshot.parent.mkdir(exist_ok=True);snapshot.write_bytes(source.read_bytes());row=dict(id=control['id'],mode=mode,status='NOT_RUN',before_sha256=hashlib.sha256(original.encode()).hexdigest(),after_sha256=sha(source),source_snapshot=str(snapshot),assertion=control['assertion'],bpf_source_sha256=hashed(inventory(changed_bpf)),testkit_source_sha256=hashed(inventory(changed_tk)));run.report['controls'].append(row);run.checkpoint()
                selected=['--test','bpf_host'] if control['test']=='profile_literal_receiving_domains' else ['--lib'];command=['test','--offline','--locked','--manifest-path',changed_tk/'Cargo.toml',*flags,*selected,control['test']]
                try:
                    _,wrong=run.test(ident+'-wrong',command,changed_tk,mtarget,expected=1)
                    if control['assertion'] not in wrong or 'FAILED' not in wrong or 'running 0 tests' in wrong:raise ValueError('NOT_SENSITIVE '+ident)
                    row.update(status='KILLED_SEMANTIC');run.result_phase(row,'wrong-executed')
                finally:source.write_text(original);row['restored_source_sha256']=sha(source);run.checkpoint()
                run.test(ident+'-restored',command,changed_tk,mtarget);row['restored']='PASS';run.checkpoint()
        # A valid imported record first reaches the codec's actual allocation
        # helper, faulted only in this owned source. Then a cause-preservation
        # mutant is tested against that same valid allocation-failure setup.
        parent=run.out/'allocation-control';parent.mkdir();ab=parent/'scopebase-bpf';at=parent/'scopebase-testkit';shutil.copytree(bpf,ab);shutil.copytree(testkit,at)
        (parent/'Cargo.toml').write_text('[workspace]\nresolver="2"\nmembers=["scopebase-testkit"]\nexclude=["scopebase-bpf"]\n[patch.crates-io]\nscopebase-bpf={path="scopebase-bpf"}\n')
        allocation=ab/'src/capability.rs';allocation.write_text(apply_changes(allocation.read_text(),[(r'(fn allocation_entry\(\)\s*->\s*Result<\(\),\s*OperationError>\s*\{)',r'\1 return Err(error(ErrorKind::Backend,Stage::Allocate,None));',True)]))
        adapter=at/'src/bpf/adapter.rs';adapter.write_text(adapter.read_text().replace('// BP03_CONTROL_TEST_INSERT',ALLOCATION_CONTROL_TEST+'\n// BP03_CONTROL_TEST_INSERT'))
        row=dict(id='allocation_remapped_to_malformed',mode='json-union',status='NOT_RUN',assertion='codec.error-stage',faulted_allocation_sha256=sha(allocation));run.report['controls'].append(row);run.result_phase(row,'reserved')
        target=run.out/'mutation-targets/json-union';cmd=['test','--offline','--locked','--manifest-path',at/'Cargo.toml','--no-default-features','--features','bpf-host,bpf-host-json','--lib','injected_codec_allocation_stage']
        run.cargo('allocation-stage-lock',['generate-lockfile','--offline','--manifest-path',at/'Cargo.toml'],at,target);run.test('allocation-stage-positive',cmd,at,target);run.result_phase(row,'fault-setup-positive')
        codec=ab/'src/capability/json.rs';original=codec.read_text();row['before_sha256']=sha(codec)
        try:
            codec.write_text(apply_changes(original,[(r'\}\s*else\s*\{\s*e\s*\}\s*\)\?','}else{error(ErrorKind::Malformed,Stage::Inspect,None)})?',True)]));row['after_sha256']=sha(codec)
            _,wrong=run.test('allocation-remapped-wrong',cmd,at,target,expected=1)
            if 'codec.error-stage' not in wrong or 'FAILED' not in wrong or 'running 0 tests' in wrong:raise ValueError('NOT_SENSITIVE allocation remap')
            row['status']='KILLED_SEMANTIC';run.result_phase(row,'wrong-executed')
        finally:
            codec.write_text(original);row['restored_source_sha256']=sha(codec);run.result_phase(row,'source-restored')
        run.test('allocation-stage-restored',cmd,at,target);row['restored']='PASS';run.checkpoint();completion=run.finish('PASS');print(json.dumps(dict(status='PASS',controls=len(run.report['controls']),receipt=str(run.out/'receipt.json'))));return completion

    except BaseException as e:
        if run is not None:raise run.abort(e)
        raise

def adapter_controls(*args,**kwargs):return run_adapter_controls(*args,**kwargs)
if __name__=='__main__':consumers_main()
