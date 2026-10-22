#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded BP02 semantic sensitivity experiments, only on private copies."""
import sys
sys.dont_write_bytecode = True
import json,os,re,shutil
from pathlib import Path
from run_consumers import arguments,inspect,run,digest

STALE80_MARKERS={
    'stale80-decoder':'BP02_STALE80_DECODER_REJECTION',
    'stale80-slice':'BP02_STALE80_SLICE_REJECTION',
    'stale80-report':'BP02_STALE80_REPORT_REJECTION',
}

def require_semantic_failure(output,test,marker=None):
    assert f'test {test} ... FAILED' in output and 'panicked at' in output,(test,'missing test assertion failure')
    if marker:
        panic=output.split('panicked at',1)[1].split('note:',1)[0]
        assert marker in panic,(test,'named stale80 rejection assertion was not the failure site')

def replace_once(source,old,new,name):
    if source.count(old)==1:return source.replace(old,new,1)
    wanted=re.sub(r'\s+','',old);matches=[]
    for start,char in enumerate(source):
        if char!=wanted[0]:continue
        end=start;seen=''
        while end<len(source) and len(seen)<len(wanted):
            if not source[end].isspace():seen+=source[end]
            end+=1
        if seen==wanted:matches.append((start,end))
    assert len(matches)==1,(name,'missing or ambiguous mutation anchor',old)
    start,end=matches[0]
    return source[:start]+new+source[end:]

def mutate(source,name,old,new):
    if name=='stale80-decoder':
        # A complete old decoder must accept the 80-byte negative, including
        # its absent provenance tail; a changed length guard alone still refuses.
        changes=[(old,new),('identity_present: lane_u32(bytes, 80)?','identity_present: KWHO_IDENTITY_PRESENT'),('_rsv: lane_u32(bytes, 84)?','_rsv: 0')]
    elif name=='stale80-slice':
        # Old report slicing treated a single 80-byte lane as a full lane.
        changes=[('count.checked_mul(88)','count.checked_mul(80)'),(old,'raw.chunks_exact(80)'),('lanes.push(vwho_from_bytes(bytes).ok_or("WHO lane decode")?);','let mut padded = [0u8; 88]; padded[..80].copy_from_slice(bytes); padded[80..84].copy_from_slice(&KWHO_IDENTITY_PRESENT.to_le_bytes()); lanes.push(vwho_from_bytes(&padded).ok_or("WHO lane decode")?);')]
    else:
        changes=[(old,new)]
    for before,after in changes:source=replace_once(source,before,after,name)
    return source

def main():
    args=arguments().parse_args();args.package=args.package.resolve();args.out=args.out.resolve();assert not args.out.exists();args.out.mkdir(parents=True)
    assert args.toolchain_root.is_absolute() and args.cargo_home.is_absolute()
    rows=[];receipt={'status':'FAILED','input':inspect(args.package),'route':str(args.build_wrapper) if args.build_wrapper else 'explicit-direct-children','commands':rows,'mutants':[],'tier_note':'Cargo invokes every case directly; tests/support/who_fixture.rs mutations are delivered test-model checks, not direct production-library checks.'}
    tools=args.toolchain_root/'bin';env={**os.environ,'CARGO_HOME':str(args.cargo_home),'RUSTC':str(tools/'rustc'),'RUSTDOC':str(tools/'rustdoc'),'CARGO_NET_OFFLINE':'true'}
    # All selected mutants execute pure/model/codec paths only. Never direct bad
    # geometry/source authority into a real production lengthless value copy.
    cases=[
      ('unrounded','src/maps/geometry.rs','.checked_add(7)','.checked_add(0)','maps_pure','stride_1_7_8_9_13'),
      ('overlap','src/maps/topology.rs','previous.is_some_and(|p| lo <= p)','false','maps_pure','overlap_missing_and_overflow_refuse'),
      ('stale80-decoder','tests/support/who_fixture.rs','bytes.len() != 88','bytes.len() != 80','who_preservation','who88_every_lookup_path'),
      ('stale80-slice','tests/support/who_fixture.rs','raw.chunks_exact(88)','raw.chunks_exact(80)','who_preservation','who88_every_lookup_path'),
      ('stale80-report','tests/support/who_fixture.rs','count.checked_mul(88)','count.checked_mul(80)','who_preservation','who88_every_lookup_path'),
      ('sentinel','tests/support/who_fixture.rs','lane.calls == u64::MAX','false','who_preservation','individual_max_refuses_but_exact_sum_max_accepts'),
      ('final-max','tests/support/who_fixture.rs','out.calls = out.calls.checked_add(lane.calls)?;','out.calls = out.calls.checked_add(lane.calls)?; if out.calls == u64::MAX { return None; }','who_preservation','individual_max_refuses_but_exact_sum_max_accepts'),
      ('saturate','tests/support/who_fixture.rs','out.calls.checked_add(lane.calls)?','out.calls.saturating_add(lane.calls)','who_preservation','individual_max_refuses_but_exact_sum_max_accepts'),
      ('task-text','src/maps/provenance.rs','if current!=saved','if false','lib','maps::provenance::tests::same_inode_different_task_text_refuses'),
      ('task-read','src/maps/provenance.rs','match io.read(&fd,&mut byte).map_err(loss)?','match 1usize','lib','maps::provenance::tests::reused_numbers_dead_original_refuse'),
      ('complete-cpulist','src/maps/provenance.rs','if used >= 4095','if false','lib','maps::provenance::tests::sysfs_complete_prefix_or_refusal'),
      ('postcheck','src/maps/handle.rs','io.revalidate(w,existing)?;','let _ = io.revalidate(w,existing);','lib','maps::handle::tests::topology_change_invalidates_sample'),
    ]
    try:
      version=run(args,[tools/'rustc','--version'],args.out,env,rows,'rustc-version').stdout;assert version.startswith('rustc '+args.toolchain+' ')
      receipt['tools']={n:{'path':str(tools/n),'sha256':digest(tools/n)} for n in ['cargo','rustc','rustdoc']}
      receipt['feature_modes']=['default','no-default']
      for mode in ['default','no-default']:
        extra=['--no-default-features'] if mode=='no-default' else []
        for base_name,rel,old,new,target,test in cases:
          name=mode+'-'+base_name
          root=args.out/name;shutil.copytree(args.package,root,ignore=shutil.ignore_patterns('target','.git'))
          manifest=root/'Cargo.toml';text=manifest.read_text();text+='\n[workspace]\n';manifest.write_text(text);inspect(root)
          env['CARGO_TARGET_DIR']=str(args.out/'targets'/mode)
          run(args,[tools/'cargo','generate-lockfile','--offline'],root,env,rows,name+'-lock');lock_sha=digest(root/'Cargo.lock')
          cmd=[tools/'cargo','test','--locked','--offline']+extra+(['--lib'] if target=='lib' else ['--test',target])+['--',test,'--exact']
          run(args,cmd,root,env,rows,name+'-positive')
          file=root/rel;original=file.read_text();original_sha=digest(file)
          # Match whitespace independently of rustfmt without changing token text.
          mutated=mutate(original,base_name,old,new)
          file.write_text(mutated);mutated_sha=digest(file)
          r=run(args,cmd,root,env,rows,name+'-mutant',1)
          assert 'could not compile' not in r.stdout and 'error[E' not in r.stdout,(name,'mutation compile/setup failure')
          require_semantic_failure(r.stdout,test,STALE80_MARKERS.get(base_name))
          file.write_text(original);run(args,cmd,root,env,rows,name+'-restored')
          receipt['mutants'].append({'name':base_name,'feature':mode,'tier':'test-model' if rel.startswith('tests/support/') else 'production-library','required_failure_marker':STALE80_MARKERS.get(base_name),'lock_sha256':lock_sha,'manifest_sha256':digest(manifest),'source_before_sha256':original_sha,'source_mutant_sha256':mutated_sha,'source_restored_sha256':digest(file),'file':rel,'test':test,'status':'SEMANTIC_FAILURE_RESTORED_PASS','positive_log':name+'-positive.log','mutant_log':name+'-mutant.log','restored_log':name+'-restored.log'})
      assert len(receipt['mutants'])==24 and {m['feature'] for m in receipt['mutants']}=={'default','no-default'}
      receipt['counts']={'direct_production_library_checks':sum(m['tier']=='production-library' for m in receipt['mutants']),'test_model_checks':sum(m['tier']=='test-model' for m in receipt['mutants'])}
      assert receipt['counts']=={'direct_production_library_checks':12,'test_model_checks':12}
      receipt['status']='PASS'
    finally:(args.out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'status':receipt['status'],'mutants':len(receipt['mutants'])}))
if __name__=='__main__':main()
