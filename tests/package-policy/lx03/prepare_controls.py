#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded LX03 semantic mutations, each paired with exact passing source twins."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',required=True,type=Path);ap.add_argument('--output',required=True,type=Path);a=ap.parse_args()
    root=a.root.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    if out.is_relative_to(root):raise ValueError('output must be outside checkout')
    rel='crates/scopebase-linux/src/file/read.rs';testrel='crates/scopebase-linux/src/file/read/tests.rs';src=(root/rel).read_text();tests=(root/testrel).read_text();cases=[]
    def change(s,old,new):
        if s.count(old)!=1:raise ValueError((old,s.count(old)))
        return s.replace(old,new)
    def add(name,test,old,new,needle,path=rel):cases.append(dict(name=name,test=test,path=path,source=change(tests if path==testrel else src,old,new),needle=needle))
    # Public nonempty cursor fixture starts with a proven incoming offset and alias.
    old='io::pread(held, bytes, offset)'
    add('cursor-read','shared_cursor_does_not_create_suffix_success',old,'io::read(held, bytes)','called `Result::unwrap()` on an `Err` value')
    suffix=src.replace('let result = fs::fstat(held);','let result = fs::fstat(held).map(|mut s| { s.st_size -= fs::seek(held, fs::SeekFrom::Current(0)).unwrap() as i64 - self.read.bytes_read as i64; s });').replace(old,'io::read(held, bytes)')
    cases.append(dict(name='successful-suffix',test='shared_cursor_does_not_create_suffix_success',path=rel,source=suffix,needle='positional reads must return literal full bytes'))
    late=change(src,'    if size > limits.max_bytes {\n        return Err(LimitKind::InputBytes);\n    }','').replace('    ops.checkpoint(control, Point::AfterReserve)?;','    ops.checkpoint(control, Point::AfterReserve)?;\n    if before.len()>limits.max_bytes { return Err(ops.semantic(Reason::LimitExceeded(LimitKind::InputBytes))); }')
    cases.append(dict(name='late-cap',test='r14_caps_empty_and_huge_before_allocation',path=rel,source=late,needle='cap refuses before reservation'))
    sentinel=change(src,'    loop {\n        let call = ops.read.read_calls;','    loop {\n        if offset == payload_len { break; }\n        let call = ops.read.read_calls;').replace('            requested\n                .checked_sub(offset)','            payload_len\n                .checked_sub(offset)')
    cases.append(dict(name='omit-sentinel',test='growth_requires_positive_sentinel',path=rel,source=sentinel,needle='called `Result::unwrap_err()` on an `Ok` value'))
    add('accept-early-zero','an_early_zero_read_is_rejected_as_a_short_read','            if offset != payload_len {','            if false && offset != payload_len {','called `Result::unwrap_err()` on an `Ok` value')
    add('requested-advance','short_positive_reads_advance_only_local_offset','            .checked_add(n)\n','            .checked_add(request)\n','called `Result::unwrap()` on an `Err` value')
    add('omit-final-equality','final_identity_and_size_changes_refuse','    if before != after {','    if false && before != after {','called `Result::unwrap_err()` on an `Ok` value')
    add('inode-only','final_identity_and_size_changes_refuse','    if before != after {','    if before.key().inode() != after.key().inode() {','called `Result::unwrap_err()` on an `Ok` value')
    add('ignore-times','raced_file_read_is_discarded_clean_sibling_survives','    if before != after {','    if before.key() != after.key() || before.len() != after.len() {','called `Result::unwrap_err()` on an `Ok` value')
    proof=change(src,'pub enum ContentSnapshot {\n    NotProven,\n}','pub enum ContentSnapshot {\n    NotProven, Proven,\n}').replace('        ContentSnapshot::NotProven','        ContentSnapshot::Proven')
    cases.append(dict(name='false-snapshot-proof',test='raced_file_read_is_discarded_clean_sibling_survives',path=rel,source=proof,needle='metadata never proves snapshot'))
    add('ignore-mtime','raced_file_read_is_discarded_clean_sibling_survives','    if before != after {','    if before.key() != after.key() || before.len() != after.len() || before.ctime() != after.ctime() {','called `Result::unwrap_err()` on an `Ok` value')
    add('ignore-ctime','raced_file_read_is_discarded_clean_sibling_survives','    if before != after {','    if before.key() != after.key() || before.len() != after.len() || before.mtime() != after.mtime() {','called `Result::unwrap_err()` on an `Ok` value')
    deep=change(src,'#[derive(Clone)]\npub struct FileRead','pub struct FileRead')+'\nimpl Clone for FileRead { fn clone(&self)->Self { Self { data:Arc::new((*self.data).clone()), observations:self.observations, charges:self.charges } } }\n'
    cases.append(dict(name='deep-clone',test='clone_keeps_one_payload_and_capacity',path=rel,source=deep,needle='clone shares payload allocation'))
    add('copy-publication','clone_keeps_one_payload_and_capacity','        data: Arc::new(data),','        data: Arc::new(data.clone()),','publication does not relocate payload')
    add('uncharge-eintr','eintr_budget_counts_every_attempt','            Err(e) if e == Errno::INTR && post.is_ok() => continue,','            Err(e) if e == Errno::INTR && post.is_ok() => { ops.read.read_calls-=1; continue; },','called `Result::unwrap_err()` on an `Ok` value')
    add('retry-past-budget','eintr_budget_counts_every_attempt','            .filter(|n| *n <= max_read_calls)','            .filter(|n| *n <= max_read_calls + 1)','called `Result::unwrap_err()` on an `Ok` value')
    # Hooks run first so deleted production checkpoint classes cannot erase setup.
    needle='        result.map_err(|stop| stop.into_error(Stage::ReadFile, self.effect(), self.charges()))'
    for name,point in [('entry','Point::Entry'),('stat','Point::AfterInitialStat | Point::AfterFinalStat'),('getfl','Point::AfterGetFl'),('reserve','Point::AfterReserve'),('init','Point::AfterInit(_)'),('read','Point::AfterRead(_)'),('arc','Point::BeforeArc'),('publish','Point::Publish')]:
        add('omit-checkpoint-'+name,'control_before_effect_and_after_success',needle,'        if matches!(_point, '+point+') { return Ok(()); }\n'+needle,'called `Result::unwrap_err()` on an `Ok` value' if name=='publish' else 'checkpoint stops following CPU/publication effect')
    add('refund-charges','control_before_effect_and_after_success','            read: Some(self.read),','            read: Some(ReadCharges { read_calls:0,bytes_read:0,..self.read }),','read work must not be refunded')
    add('replace-primary-errno','primary_errno_survives_concurrent_stop','            Err(e) => Err(self.errno(e)),','            Err(e) => { post?; Err(self.errno(e)) },','semantic refusal')
    add('replace-read-errno','primary_errno_survives_concurrent_stop','            Err(e) => return Err(ops.errno(e)),','            Err(e) => { post?; return Err(ops.errno(e)); },','semantic refusal')
    overflow=src.replace('    let requested = size\n        .checked_add(1)','    let requested = Some(size.wrapping_add(1))').replace('    checked_offset(size).ok_or(LimitKind::BufferCapacity)?;','')
    cases.append(dict(name='unchecked-capacity',test='capacity_allocation_and_overflow_are_distinct',path=rel,source=overflow,needle='overflow refuses before allocation'))
    add('erase-overgrant','capacity_allocation_and_overflow_are_distinct','    ops.read.granted_capacity = data.capacity();','    ops.read.granted_capacity = requested;','overgrant remains historical')
    add('ignore-allocation-failure','capacity_allocation_and_overflow_are_distinct','        .map_err(|_| ops.semantic(Reason::Allocation))?;','        .or_else(|_| reserve_exact(requested)).map_err(|_| ops.semantic(Reason::Allocation))?;','called `Result::unwrap_err()` on an `Ok` value')
    add('large-request','requests_never_exceed_64k_or_initial_plus_one','        let request = 65536.min(','        let request = 1_048_576.min(','request must be at most 64 KiB')
    add('large-initialization','requests_never_exceed_64k_or_initial_plus_one','        data.resize(data.len() + 65536.min(requested - data.len()), 0);','        data.resize(data.len() + 1_048_576.min(requested - data.len()), 0);','initialization must be at most 64 KiB')
    add('wrapped-offset','requests_never_exceed_64k_or_initial_plus_one','    i64::try_from(offset).ok().map(|_| offset)','    Some(offset as i64 as u64)','signed offsets refuse wrapping')
    # This bounded wrong invocation owner reports before its still-owned inner
    # worker returns. It subsequently joins it, ensuring negative cleanup too.
    old='''                let e = read_all_with(&h, limits(), &control, &mut o).unwrap_err();
                done_tx.send(e).unwrap();'''
    new='''                let read_control=control.clone();
                let inner=std::thread::spawn(move || read_all_with(&h, limits(), &read_control, &mut o));
                while control.checkpoint().is_ok() { std::thread::yield_now(); }
                done_tx.send(ReadOps::default().semantic(Reason::Cancelled)).unwrap();
                let _ = inner.join().unwrap();'''
    # Deterministic deadline seam is bypassed for this control's first cancel branch.
    add('report-before-release','blocked_read_is_not_cancelled_until_return',old,new,'synchronous read retains custody until explicit release',testrel)
    add('reopen-authority','read_errors_keep_original_authority','            Err(e) => return Err(ops.errno(e)),','            Err(e) => { use std::os::fd::{AsFd,AsRawFd}; let reopened=std::fs::File::open(format!("/proc/self/fd/{}",held.as_fd().as_raw_fd())).unwrap(); let mut changed=ops.errno(e); changed.charges.acquired=1; drop(reopened); return Err(changed); },','assertion `left == right` failed')
    # Privacy controls prove that a deliberately public field changes the exact
    # compiler refusal into a successful downstream compile.
    for name,field,test in [('public-payload','    data: Arc<Vec<u8>>,','read_private'),('public-observations','    before: StatObservation,','read_observations_private'),('public-charges','    pub(crate) read_calls: u64,','read_charges_private')]:
        cases.append(dict(name=name,test=test,path=rel,source=change(src,field,field.replace('pub(crate) ','pub ') if 'pub(crate)' in field else field.replace('    ','    pub ',1)),privacy=True))
    restored=out/'restored'
    def copy(dest):
        dest.mkdir();shutil.copytree(root/'crates',dest/'crates')
        for f in ['Cargo.toml','Cargo.lock']:shutil.copyfile(root/f,dest/f)
    copy(restored);spec=[];bindings=[]
    policy=json.loads((root/'package-policy.json').read_text())
    for case in cases:
        dest=out/case['name'];copy(dest);(dest/case['path']).write_text(case['source'])
        bindings.append(dict(control=case['name'],test=case['test'],path=case['path'],source_sha256=sha(root/case['path']),mutated_sha256=sha(dest/case['path']),restored_sha256=sha(restored/case['path']),tier='invocation-owner' if case['path']==testrel else 'actual-read-primitive'))
        for t in policy['toolchains']:
            for cfg,flags in [('minimal',['--no-default-features']),('default',[]),('union',['--all-features'])]:
                prefix=t['id']+'-'+cfg+'-'+case['name'];base=['test','--offline','--locked','-p','scopebase-linux',*flags]
                if case.get('privacy'):
                    ui=next(c for c in json.loads((root/'crates/scopebase-linux/tests/ui/cases.json').read_text())['cases'] if c['id']==case['test'])
                    for form,subject in [('twin',restored),('negative',dest),('restored',restored)]:
                        client=out/'privacy-clients'/prefix/form;(client/'src/bin').mkdir(parents=True)
                        shutil.copyfile(root/'crates/scopebase-linux'/ui['source'],client/'src/bin/refusal.rs')
                        shutil.copyfile(root/'crates/scopebase-linux/tests/ui/read_positive.rs',client/'src/bin/positive.rs')
                        features=['mapping','process','supervision','walk'] if cfg=='union' else []
                        manifest='[package]\nname = '+json.dumps('lx03-'+prefix+'-'+form)+'\nversion = "0.1.0"\nedition = "2021"\n[workspace]\n[dependencies]\nscopebase-linux = { path = '+json.dumps(str(subject/'crates/scopebase-linux'))+', version = "=0.1.0", default-features = '+str(cfg=='default').lower()+', features = '+json.dumps(features)+' }\n'
                        (client/'Cargo.toml').write_text(manifest)
                        target='privacy-'+prefix+'-'+form
                        spec.append(dict(id=prefix+'-'+form+'-lock',toolchain=t['id'],cwd=str(client),argv=['generate-lockfile','--offline'],target=target))
                        spec.append(dict(id=prefix+'-'+form+'-positive',toolchain=t['id'],cwd=str(client),argv=['run','--offline','--locked','--bin','positive'],target=target))
                        row=dict(id=prefix+'-'+form+'-privacy',toolchain=t['id'],cwd=str(client),argv=['check','--offline','--locked','--bin','refusal','--message-format=json'],target=target)
                        if form!='negative':row['failure']=dict(code=ui['code'],contains=ui['contains'],source='src/bin/refusal.rs',line=ui['line'])
                        else:row['semantic_control']='forbidden field access deliberately became accepted'
                        spec.append(row)
                    continue
                public=case['test']=='shared_cursor_does_not_create_suffix_success'
                selector=['--test','positional_read',case['test']] if public else ['--lib','file::read::tests::'+case['test']]
                argv=base+selector+['--','--exact','--nocapture']
                twin=prefix+'-twin';negative=prefix+'-negative';restored_id=prefix+'-restored';target=t['id']+'-'+cfg+'-'+case['name']
                spec.extend([dict(id=twin,toolchain=t['id'],cwd=str(restored),argv=argv,target=t['id']+'-'+cfg+'-restored'),dict(id=negative,toolchain=t['id'],cwd=str(dest),argv=argv,target=target,failure=[case['test']+' ... FAILED',case['needle']]),dict(id=restored_id,toolchain=t['id'],cwd=str(restored),argv=argv,target=t['id']+'-'+cfg+'-restored')])
    (out/'spec.json').write_text(json.dumps(spec,indent=2)+'\n');(out/'bindings.json').write_text(json.dumps(bindings,indent=2)+'\n');print(out/'spec.json')
if __name__=='__main__':main()
