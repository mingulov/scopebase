#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Root BP03 public-boundary and semantic controls using delivered helpers.

Use the same explicit source/archive/tool/cache/wrapper bindings as execute.py.
Source review and a resource reservation precede this finite, fresh campaign.
The returned control records distinguish compile boundaries, binding negatives
and actual intended semantic failures; no setup failure counts as sensitivity.
"""
import importlib.util,json
from pathlib import Path
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location('bp03_matrix',Path(__file__).with_name('execute.py'));matrix=importlib.util.module_from_spec(spec);spec.loader.exec_module(matrix)

def main(argv=None):
    args=matrix.parser().parse_args(argv);tools=matrix.bindings(args)
    if any(not getattr(args,name).is_absolute() or '..' in getattr(args,name).parts for name in ['source_bpf','source_testkit','bpf_archive','testkit_archive','output','config','cargo_home','build_wrapper']):raise ValueError('explicit absolute input/output bindings required')
    helper=matrix.load(args.source_testkit/'tests/fixtures/bp03/run_consumers.py');helper.lexical_path(args.output)
    for source in [args.source_bpf,args.source_testkit,args.bpf_archive,args.testkit_archive,args.config,args.cargo_home,args.build_wrapper,*tools.values()]:
        if args.output.resolve().is_relative_to(source.resolve()):raise ValueError('output inside selected input')
    if args.output.exists() or args.output.resolve().is_relative_to(matrix.ROOT):raise ValueError('fresh output outside worktree required')
    args.output.mkdir(parents=True);helper=matrix.load(args.source_testkit/'tests/fixtures/bp03/run_consumers.py');parent=None
    required=[dict(id=f'{kind}/{version}/{subject}',input=kind,compiler=version,subject=subject,status='NOT_RUN') for kind in ['source','archive'] for version in tools for subject in ['bpf-public','adapter']]
    report=dict(schema_version=1,kind='BP03_HOST_CONTROL_CAMPAIGN',status='INCOMPLETE',required=required,scope='T0 host/model; no native qualification')
    try:
        helper.inspect_packages(args.source_bpf,args.source_testkit)
        bpf=matrix.unpack(args.bpf_archive,args.output/'archives/bpf','scopebase-bpf');testkit=matrix.unpack(args.testkit_archive,args.output/'archives/testkit','scopebase-testkit');helper.inspect_packages(bpf,testkit)
        report['archive_mappings']={'scopebase-bpf':matrix.archive_mapping(helper,args.source_bpf,args.bpf_archive,bpf),'scopebase-testkit':matrix.archive_mapping(helper,args.source_testkit,args.testkit_archive,testkit)};inputs={'source':(args.source_bpf,args.source_testkit),'archive':(bpf,testkit)}
        expectations={row['id']:dict(root=str(args.output/'controls'/row['id']),kind='BP03_BPF_PUBLIC_CONTROLS' if row['subject']=='bpf-public' else 'BP03_ADAPTER_SOURCE_CONTROLS') for row in required}
        parent=helper.ParentEvents(args.output,dict(kind=report['kind'],child_invocations=expectations,inputs={k:[str(p) for p in v] for k,v in inputs.items()},tools={k:str(v) for k,v in tools.items()},config=dict(path=str(args.config),sha256=helper.sha(args.config)),cargo_home=str(args.cargo_home),wrapper=dict(path=str(args.build_wrapper),sha256=helper.sha(args.build_wrapper)),archive_mappings=report['archive_mappings']),required);matrix.bind_child_invocations(parent,expectations);parent.checkpoint(report)
        for row in required:
            parent.reserve_row(row);matrix.start_child(parent,row['id']);bp,tp=inputs[row['input']];out=args.output/'controls'/row['id'];version=row['compiler'];common=['--package',str(bp),'--out',str(out),'--toolchain',version,'--toolchain-root',str(tools[version]),'--cargo-home',str(args.cargo_home),'--cargo-config',str(args.config),'--build-wrapper',str(args.build_wrapper)]
            if row['subject']=='bpf-public':
                module=matrix.load(bp/'tests/support/check_bp03_controls.py');completion=module.bpf_controls_main(common)
            else:
                module=matrix.load(tp/'tests/fixtures/bp03/run_consumers.py');parsed=module.arguments(True).parse_args(common+['--testkit-package',str(tp)]);completion=module.run_adapter_controls(parsed)
            actual,reference=matrix.accept_child(parent,module,completion,row['id'])
            if actual['status']!='PASS':raise ValueError('incomplete actual controls '+row['id'])
            row.update(status='PASS',child_reference=reference);parent.checkpoint(report)
        report['status']='PASS';return matrix.finish_parent(parent,report)
    except BaseException as e:
        if parent is not None:raise parent.abort(e,report)
        raise
if __name__=='__main__':main()
