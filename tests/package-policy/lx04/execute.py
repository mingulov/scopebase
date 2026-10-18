#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""LX04 bounded evidence adapter; no dependency acquisition or acceptance authority."""
import argparse
import json
import shutil
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'tools/build'))
import common as p


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--spec', type=Path)
    parser.add_argument('--mode', choices=['red','final','controls'], required=True)
    args = parser.parse_args()
    root = args.root.resolve(); output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    matrix = p.read_json(root/'package-policy.json')
    ex = p.Execution('lx04', root/'package-policy.json', matrix, output, root/'Cargo.toml', scope=args.mode)
    ex.report['adapter_sha256'] = p.sha(__file__)
    drivers=output/'drivers';drivers.mkdir()
    for path in Path(__file__).parent.glob('*.py'): shutil.copyfile(path,drivers/path.name)
    ex.report['retained_drivers']=[dict(path=str(path),sha256=p.sha(path)) for path in sorted(drivers.glob('*.py'))]
    ex.report['helper_sha256']=p.sha(root/'tools/build/common.py')
    ex.report['invocation']={'argv':sys.argv,'cwd':str(Path.cwd())}
    ex.staging = p.stage_inputs(matrix['cargo_inputs'], output)
    ex.report['staged_inputs'] = [{k:str(v) if isinstance(v,Path) else v for k,v in r.items()} for r in ex.staging['staged_inputs']]
    # Every actual cargo invocation is under the shared host/user lease.
    def command(ident, toolchain, cwd, argv, target=None, expect_failure=None):
        if ident not in ex.by_id: ex.reserve(ident, toolchain=toolchain['id'], phase=args.mode)
        def action(row):
            env = p.clean_env(output, toolchain, target or output/'target'/toolchain['id'])
            lock = cwd/'Cargo.lock'; before = p.sha(lock) if lock.exists() else None
            row.update(environment=env, input_sha256=p.tree_digest(cwd/'crates/scopebase-linux' if (cwd/'crates/scopebase-linux').is_dir() else cwd), lock_path=str(lock), lock_sha256_before=before)
            result = p.run([root/'bin/scopebase-build','--',Path(toolchain['root'])/'bin/cargo',*argv], cwd, env, output/'logs'/ident)
            ex.attach(row,result)
            row['run_result'] = result
            row['lock_sha256'] = p.sha(lock) if lock.exists() else None
            row['input_sha256_after'] = p.tree_digest(cwd/'crates/scopebase-linux' if (cwd/'crates/scopebase-linux').is_dir() else cwd)
            row['expected'] = expect_failure or {'exit_code':0}
            if '--locked' in argv and before != row['lock_sha256']: raise p.PolicyError('LOCK_CHANGED')
            if '--locked' in argv and row['input_sha256'] != row['input_sha256_after']: raise p.PolicyError('SOURCE_CHANGED')
            row['source_root'] = str(cwd/'crates/scopebase-linux' if (cwd/'crates/scopebase-linux').is_dir() else cwd)
            if expect_failure:
                if result['reason_code'] or result['cleanup'] != 'complete' or result['exit_code'] is None or result['exit_code'] <= 0:
                    raise p.PolicyError('EXPECTED_FAILURE_NOT_REACHED',detail=result)
                text = p.stdout(result)+Path(result['logs']['stderr']['path']).read_text()
                if isinstance(expect_failure,dict):
                    # Keep accept_refusal retirement/exit/lock predicates above,
                    # then use the accepted exact-primary matcher directly.
                    if not p.rust_refusal(p.stdout(result),expect_failure['code'],expect_failure['contains'],cwd,expected_primary=(expect_failure['source'],expect_failure['line'])):
                        raise p.PolicyError('WRONG_EXACT_COMPILE_REFUSAL',detail=result)
                elif any(needle not in text for needle in expect_failure): raise p.PolicyError('WRONG_RED',detail=result)
            else: p.succeeded(result)
            return result
        return ex.step(ident,action)
    try:
        if args.mode == 'red':
            command('missing-primitives',matrix['toolchains'][0],root,['test','--offline','--locked','-p','scopebase-linux','--test','controls'],expect_failure=['unresolved import `scopebase_linux::control`'])
        elif args.mode == 'final':
            import deliver
            deliver.run(ex,root,matrix,command,p)
        else:
            spec=p.read_json(args.spec)
            ex.report['spec_sha256']=p.sha(args.spec)
            for item in spec: ex.reserve(item['id'],toolchain=item['toolchain'],phase=args.mode)
            for item in spec:
                t=next(t for t in matrix['toolchains'] if t['id']==item['toolchain'])
                command(item['id'],t,Path(item['cwd']),item['argv'],output/'targets'/item.get('target',item['id']),item.get('failure'))
    except Exception as error:
        return ex.abort(error,output/'report.json')
    return ex.finish(output/'report.json')

if __name__ == '__main__': sys.exit(main())
