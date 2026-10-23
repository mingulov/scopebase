#!/usr/bin/env python3
"""Check the current ScopeBase planning documents, not future software behavior.

Run from any directory: python3 tools/check_planning_docs.py
Task progress is administrative; acceptance records never certify runtime support.
Counts and unqualified capability guards describe the current foundation schema.
Amend those guards explicitly when a later qualification schema is implemented.
"""
import collections, json, os, re, subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit

root=Path(__file__).resolve().parents[1]
base=root/'docs/research/2026-10-17-shared-libraries'

def discover_files(repo_root, suffix):
    """Return Git-deliverable files, including untracked nonignored files."""
    listed=subprocess.run(
        ['git','-C',str(repo_root),'ls-files','-z','--cached','--others','--exclude-standard'],
        check=True,stdout=subprocess.PIPE,
    ).stdout
    paths={Path(os.fsdecode(raw)) for raw in listed.split(b'\0') if raw}
    return sorted(repo_root/path for path in paths if path.suffix==suffix and (repo_root/path).is_file())

md=discover_files(root,'.md')
js=discover_files(root,'.json')
catalog_dir=Path('crates/scopebase-testkit/tests/fixtures/catalog')
catalog_metadata={'admission-expectations.json','profile-schema-v1.json'}
errors=[]
counts=collections.Counter()
docs={p:p.read_text() for p in md}
def fail(x):
    errors.append(x)
def headings(p):
    counts_slug=collections.Counter()
    result=set()
    fenced=False
    for line in docs[p].splitlines():
        if line.startswith(chr(96)*3) or line.startswith('~~~'):
            fenced=not fenced
            continue
        if fenced: continue
        m=re.match(r'^#{1,6}\s+(.+?)(?:\s+#+)?$',line)
        if m:
            s=re.sub(r'[^\w\- ]','',m[1].lower()).replace(' ','-')
            n=counts_slug[s]
            result.add(s if not n else s+'-'+str(n))
            counts_slug[s]+=1
    return result
anchors={p:headings(p) for p in md}
def acceptance_record(value):
    """Require public Markdown beneath docs/reviews, without symlink custody."""
    if not isinstance(value,str) or not value or '\0' in value:
        return False
    path=Path(value)
    if path.is_absolute() or '..' in path.parts or path.parts[:2]!=('docs','reviews'):
        return False
    if len(path.parts)<3 or path.suffix!='.md':
        return False
    if any(root.joinpath(*path.parts[:i]).is_symlink() for i in range(1,len(path.parts)+1)):
        return False
    return root/path in docs

def link(p,target):
    if target.startswith(('<','>')):
        target=target.strip('<>')
    if urlsplit(target).scheme or target.startswith('//'):
        return
    target=unquote(target)
    path,sep,frag=target.partition('#')
    path=re.sub(r':\d+$','',path)
    q=(p.parent/path).resolve() if path else p
    counts['local_link_occurrences']+=1
    if not q.exists(): fail(f'{p.relative_to(root)}: missing {target}')
    elif sep and frag and q.suffix=='.md' and frag not in anchors.get(q,set()):
        fail(f'{p.relative_to(root)}: missing anchor {target}')
for p,body in docs.items():
    fenced=False
    table_width=None
    for no,line in enumerate(body.splitlines(),1):
        if line.rstrip()!=line: fail(f'{p.relative_to(root)}:{no}: trailing whitespace')
        if line.startswith(chr(96)*3) or line.startswith('~~~'):
            fenced=not fenced
            continue
        if fenced: continue
        for m in re.finditer(r'(?<!!)\[[^\]]+\]\(([^)\n]+)\)',line):
            link(p,m[1])
        if line.startswith('|') and line.rstrip().endswith('|'):
            cells=re.split(r'(?<!\\)\|',line.strip())[1:-1]
            if table_width is None:
                table_width=len(cells)
                counts['markdown_tables']+=1
            elif len(cells)!=table_width:
                fail(f'{p.relative_to(root)}:{no}: table width {len(cells)} expected {table_width}')
        else: table_width=None
    if fenced: fail(f'{p.relative_to(root)}: unclosed fence')
json_values={}
json_parse_errors=False
for p in js:
    relative=p.relative_to(root)
    # Catalog suites judge raw payloads, including intentionally invalid JSON.
    # Their metadata and all JSON outside this exact corpus remain checked here.
    if relative.parent==catalog_dir and p.name not in catalog_metadata:
        continue
    try:
        body=p.read_text()
        json_values[p]=json.loads(body)
    except Exception as e:
        fail(f'{relative}: JSON {e}')
        json_parse_errors=True
        continue
    for no,line in enumerate(body.splitlines(),1):
        if line.rstrip()!=line: fail(f'{p.relative_to(root)}:{no}: trailing whitespace')
if json_parse_errors:
    print(json.dumps({'counts':dict(counts),'errors':errors,'result':'FAIL'},indent=2))
    raise SystemExit(1)
h=re.findall(r'^\| (H\d{2}) \|',docs[base/'testing-strategy.md'],re.M)
g=re.findall(r'^## (G\d{2})\.',docs[base/'gap-analysis.md'],re.M)
uc=re.findall(r'^\| \*\*(UC\d{2}) ',docs[base/'user-conformance.md'],re.M)
todo=re.findall(r'^\| ([A-Z]\d{2}) \|',docs[base/'TODO.md'],re.M)
ov=re.findall(r'^\| (\d{1,2}) [^|]*\|',docs[base/'overlap-matrix.md'],re.M)
for label,actual,n in [('H',h,33),('G',g,23),('UC',uc,14)]:
    expected=[f'{label}{i:02d}' for i in range(1,n+1)]
    if actual!=expected: fail(f'{label} identifiers mismatch: {actual}')
if len(todo)!=len(set(todo)): fail('duplicate TODO identifiers')
if [int(x) for x in ov]!=list(range(1,29)): fail(f'overlap rows mismatch: {ov}')
cat=json_values[base/'regression-catalog.json']
if cat['schema_version']!='0.2.0': fail('catalog schema version')
if cat['runnable'] or cat['execution_status']!='NOT_RUN' or cat['implementation_status']!='NOT_IMPLEMENTED': fail('catalog qualification status')
if [c['id'] for c in cat['cases']]!=h: fail('catalog H identifiers mismatch')
alias=cat['source_aliases']
for v in alias.values():
    link(base/'regression-catalog.json',v['pin_document'])
for c in cat['cases']:
    if c['runnable'] or c['execution_status']!='NOT_RUN' or c['implementation_status']!='NOT_IMPLEMENTED' or c['status']!='PLANNED':
        fail(c['id']+': qualification status')
    if 'required_evidence_tiers' in c or 'conditional_evidence_tiers' in c:
        fail(c['id']+': ambiguous family tier fields')
    plan=c['subcase_tier_plan']
    if plan['status']!='UNRESOLVED_BEFORE_PORTING' or plan['required_subcase_tiers_and_cells'] is not None:
        fail(c['id']+': unresolved plan state')
    if not c['independent_oracle'] or not c['known_bad_control']['required_failure_layer']:
        fail(c['id']+': missing oracle/control')
    row=next(x for x in docs[base/'testing-strategy.md'].splitlines() if x.startswith('| '+c['id']+' |'))
    tier_inventory=sorted(set(re.findall(r'\bT[0-5]\b',row)))
    if sorted(c['family_evidence_tier_inventory'])!=tier_inventory:
        fail(c['id']+': family tier inventory differs from matrix')
    for anchor in c['inspected_donor_anchors']:
        if anchor['alias'] is not None and anchor['alias'] not in alias:
            fail(c['id']+': unknown donor alias')
        link(base/'regression-catalog.json',anchor['pin_document'])
    for typ,valid in [('UC',uc),('G',g),('TODO',todo)]:
        for ref in c['related_obligations'][typ]:
            if ref not in valid: fail(c['id']+': unknown '+typ+' '+ref)
src=json_values[base/'external-sources.json']
for entry in src['sources']:
    if not re.fullmatch(r'[0-9a-f]{40}',entry['sha']): fail('invalid upstream SHA '+str(entry))
counts.update(markdown_files=len(md), json_files=len(js), H_families=len(h), UC_scenarios=len(uc), G_obligations=len(g), backlog_items=len(todo), overlap_rows=len(ov), upstream_research_pins=len(src['sources']))

registry_path=root/'docs/superpowers/plans/2026-10-17-scopebase-traceability.json'
reg=json_values[registry_path]
tasks=reg['tasks']
task_ids=[t['id'] for t in tasks]
task_map={t['id']:t for t in tasks}
if len(task_ids)!=86 or len(set(task_ids))!=86: fail('planning task IDs/count')
progressed=any(t.get('status')!='PLANNED' for t in tasks)
expected_state=('DEVELOPMENT','IN_PROGRESS') if progressed else ('DESIGN_ONLY','NOT_IMPLEMENTED')
if (reg.get('status'),reg.get('implementation_status'))!=expected_state:
    fail('planning execution state differs from task progress')
if reg.get('qualification_status')!='NOT_RUN' or reg.get('runnable') is not False:
    fail('planning qualification status')
plan_ids=[]
for p,body in docs.items():
    if p.parent != root/'docs/superpowers/plans': continue
    plan_ids.extend(re.findall(r'^#{2,3} (?:Task )?((?:SB|LX|BP|TC|CP|TT|SDK|NX|RL|MG)\d{2}):',body,re.M))
if collections.Counter(plan_ids)!=collections.Counter(task_ids): fail('task registry differs from detailed plans')
todo_rows=[]
for line in docs[root/'TODO.md'].splitlines():
    match=re.match(r'^- \[([ x])\] \[((?:SB|LX|BP|TC|CP|TT|SDK|NX|RL|MG)\d{2}):',line)
    if match: todo_rows.append((match[2],match[1],line))
todo_ids=[ident for ident,_,_ in todo_rows]
if collections.Counter(todo_ids)!=collections.Counter(task_ids): fail('root TODO differs from registry')
all_edges={}
# Alpha-mode partial-prereq exceptions (2026-10-23, owner-directed): tasks
# accepted on TT03 worker increments (0c7f297/4a7f4a4/796a1d3/c238010, all
# reviewer-approved progress) while TT03 itself stays PLANNED pending F
# rows/final-index/DAG delivery. Each entry justifies why the accepted slice
# suffices; unknown tasks/deps/edges here are themselves failures (below).
PREREQ_EXCEPTIONS={
    'SDK04': {'TT03': 'observer uses SDK02/SDK03 context only, zero testkit refs'},
    'TT09': {'TT03': 'harness complete; tt03_pair_launch baseline honestly UNBUILT'},
    'TT07': {'TT03': 'operator runs on worker increments (14/14 P, collect/retire); domain profiles honestly NoBoundAdapter'},
}
for task in tasks:
    state=task.get('status')
    if state not in ('PLANNED','IN_PROGRESS','ACCEPTED'):
        fail(task['id']+': unknown task status')
    if state in ('IN_PROGRESS','ACCEPTED'):
        unmet=[dep for dep in task['depends_on'] if task_map.get(dep,{}).get('status')!='ACCEPTED' and dep not in PREREQ_EXCEPTIONS.get(task['id'],{})]
        if unmet: fail(task['id']+': mandatory prerequisites not ACCEPTED: '+','.join(unmet))
    if state=='ACCEPTED':
        acceptance=task.get('acceptance')
        if not isinstance(acceptance,dict) or not {'subject_commit','evidence_record'}<=acceptance.keys():
            fail(task['id']+': invalid acceptance object')
        else:
            subject=acceptance['subject_commit']
            if not isinstance(subject,str) or not re.fullmatch(r'[0-9a-f]{40}',subject):
                fail(task['id']+': invalid acceptance subject_commit')
            if not acceptance_record(acceptance['evidence_record']):
                fail(task['id']+': invalid acceptance evidence_record')
    elif 'acceptance' in task:
        fail(task['id']+': acceptance requires ACCEPTED')
    link(root/'README.md',task['plan']+'#'+task['anchor'])
    all_edges[task['id']]=set(task['depends_on'])
    for gate in task['profile_gates']:
        all_edges[task['id']].update(gate['requires_tasks'])
    if len(task['depends_on'])!=len(set(task['depends_on'])): fail(task['id']+': duplicate dependency')
    checkbox,line=next(((checked,line) for ident,checked,line in todo_rows if ident==task['id']), ('',''))
    if checkbox!=('x' if state=='ACCEPTED' else ' '):
        fail(task['id']+': root TODO checkbox differs from task status')
    match=re.search(r'prerequisites: ([^;.]+)',line)
    listed=[] if match and match[1]=='none' else (match[1].split(', ') if match else None)
    if listed!=task['depends_on']: fail(task['id']+': root TODO prerequisites drift')
    if any(x not in task_map for x in all_edges[task['id']]): fail(task['id']+': dangling dependency')
    if not task['id'].startswith('MG') and any(x.startswith('MG') for x in all_edges[task['id']]):
        fail(task['id']+': package work depends on later product migration')
for task_id,deps in PREREQ_EXCEPTIONS.items():
    if task_id not in task_map: fail('PREREQ_EXCEPTIONS unknown task '+task_id)
    for dep in deps:
        if dep not in task_map.get(task_id,{}).get('depends_on',[]): fail('PREREQ_EXCEPTIONS '+task_id+': not a declared edge: '+dep)
pending={k:set(v) for k,v in all_edges.items()}
order=[]
while pending:
    ready=sorted(k for k,v in pending.items() if not (v & pending.keys()))
    if not ready:
        fail('task dependency cycle: '+','.join(sorted(pending)))
        break
    order.extend(ready)
    for k in ready: del pending[k]
stored=reg['validated_all_edges_topological_order']
if stored!=order: fail('stored topological order differs from graph')
spec_ids={}
for p,body in docs.items():
    if p.parent != root/'docs/superpowers/specs': continue
    for ident in re.findall(r'^\| ((?:SB|LX|BP|TC|CP|TT|SDK|NX)-R\d{2}) \|',body,re.M):
        if ident in spec_ids: fail('duplicate requirement '+ident)
        spec_ids[ident]=p
requirements=reg['requirements']
if len(requirements)!=120 or {r['id'] for r in requirements}!=set(spec_ids): fail('requirement registry differs from specifications')
for r in requirements:
    if r.get('status')!='PLANNED': fail(r['id']+': requirement status must remain PLANNED')
    if root/r['spec']!=spec_ids.get(r['id']): fail(r['id']+': wrong spec path')
    if not r['tasks'] or any(t not in task_map for t in r['tasks']): fail(r['id']+': missing/dangling owner')
    for t in r['tasks']:
        if r['id'] not in task_map.get(t,{}).get('requirements',[]): fail(r['id']+': asymmetric task mapping')
for t in tasks:
    for ident in t['requirements']:
        r=next((r for r in requirements if r['id']==ident),None)
        if not r or t['id'] not in r['tasks']: fail(t['id']+': asymmetric requirement mapping')
expected={'research_todo':set(todo),'regression_family':set(h),'public_contract_gap':set(g),'user_conformance':set(uc),'overlap_row':{'OV'+x for x in ov}}
observed=collections.defaultdict(list)
for o in reg['source_obligations']:
    observed[o['kind']].append(o['id'])
    if o['status']!='OPEN' or not o['tasks'] or any(t not in task_map for t in o['tasks']): fail('source mapping/status '+o['id'])
    if not (root/o['source']).is_file(): fail('missing source '+o['source'])
for kind,ids in expected.items():
    if set(observed[kind])!=ids or len(observed[kind])!=len(ids): fail('source set mismatch '+kind)
if set(observed)!=set(expected): fail('unknown source-obligation category')
profiles={p['id']:p for p in reg['profiles']}
extensions={e['id']:e for e in reg['profile_extensions']}
if len(profiles)!=19 or list(profiles)!=reg['profile_ids']: fail('canonical profile set/order mismatch')
profile_edges={p:set(v['requires_profiles']) for p,v in profiles.items()}
for ident in [*profiles,*extensions]:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}',ident): fail('invalid profile/extension ID '+ident)
for e in extensions.values():
    if 'status' in e and e['status']!='PLANNED': fail(e['id']+': extension status must remain PLANNED')
    if e['profile'] not in profiles: fail('unknown extension owner '+e['id'])
    else: profile_edges[e['profile']].update(e['requires_profiles'])
    if any(t not in task_map for t in e['requires_tasks']): fail('dangling extension task '+e['id'])
for p in profiles.values():
    if p.get('status')!='PLANNED': fail(p['id']+': profile status must remain PLANNED')
    if any(e not in extensions for e in p['requires_extensions']): fail('dangling extension '+p['id'])
    if any(t not in task_map for t in p['readiness_tasks']): fail('dangling readiness task '+p['id'])
for t in tasks:
    for gate in t['profile_gates']:
        if any(p not in profiles for p in gate['profiles']): fail('dangling gate profile '+t['id'])
        if any(e not in extensions for e in gate['when_extensions']): fail('dangling gate extension '+t['id'])
pp={k:set(v) for k,v in profile_edges.items()}
if any(x not in profiles for v in pp.values() for x in v): fail('dangling required profile')
while pp:
    ready=[p for p,d in pp.items() if not d.intersection(pp)]
    if not ready:
        fail('profile dependency cycle')
        break
    for p in ready: del pp[p]
def closure(selected):
    selected=set(selected); ext=set()
    while True:
        before=(len(selected),len(ext))
        for p in list(selected):
            selected.update(profiles[p]['requires_profiles'])
            ext.update(profiles[p]['requires_extensions'])
        for e in list(ext):
            selected.add(extensions[e]['profile'])
            selected.update(extensions[e]['requires_profiles'])
        if before==(len(selected),len(ext)): return selected,ext
if not errors:
    sdk,_=closure(['sdk-live-aya-v1'])
    native,nx_ext=closure(['native-v1'])
    if not {'sdk-host-v1','held-file-v1','capture-core-v1','bpf-aya-uprobe-v1','owned-child-v1','process-observation-v1','compiler-object-v1'} <= sdk:
        fail('SDK component-profile closure incomplete')
    if not {'capture-core-v1','mojo-elf-v1','compiler-object-v1','bpf-host-v1','btf-shape-le-v1'} <= native or 'btf-runtime-linkage-v1' not in nx_ext:
        fail('native component-profile closure incomplete')
for p,body in docs.items():
    if root/'docs/superpowers' not in p.parents: continue
    for stale in ['scopebase-check capture','tools/object-contracts/','--profile filesystem-matrix']:
        if stale in body: fail(str(p.relative_to(root))+': stale contract '+stale)
counts.update(planned_tasks=len(tasks),normative_requirements=len(requirements),source_obligation_mappings=len(reg['source_obligations']),canonical_profiles=len(profiles),profile_extensions=len(extensions))

print(json.dumps({'counts':dict(counts),'errors':errors,'result':'PASS' if not errors else 'FAIL'},indent=2))
raise SystemExit(bool(errors))
