#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Materialize independent LX04 wrong-control workspaces and restored twins."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();root=args.root.resolve();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    control='crates/scopebase-linux/src/control.rs';tests='crates/scopebase-linux/src/control/tests.rs'
    source=(root/control).read_text();test_source=(root/tests).read_text()
    def change(s,a,b):
        assert s.count(a)==1,(a,s.count(a));return s.replace(a,b)
    cases=[]
    def add(name,test,old,new,needles,fixture=False):
        cases.append((name,test,tests if fixture else control,change(test_source if fixture else source,old,new),needles))
    add('ignore-cancel','cancel_before_first_effect','if self.cancel.cancelled.load(Ordering::Acquire) {','if false && self.cancel.cancelled.load(Ordering::Acquire) {',['assertion `left == right` failed'])
    add('strict-greater','deadline_equality_is_expired','now() >= deadline.at','now() > deadline.at',['assertion `left == right` failed'])
    add('overflow-unlimited','deadline_overflow_is_invalid_input','.checked_add(duration)','.checked_add(duration).or(Some(start))',['called `Result::unwrap_err()` on an `Ok` value'])
    add('deadline-poisons-token','independent_controls_do_not_share_deadline_state','return Err(ControlStop::Deadline);','self.cancel.cancel(); return Err(ControlStop::Deadline);',['assertion `left == right` failed'])
    first=source.replace('cancelled: Arc<AtomicBool>,','cancelled: Arc<AtomicBool>,\n    first_deadline: Arc<AtomicBool>,').replace('cancelled: Arc::new(AtomicBool::new(false)),','cancelled: Arc::new(AtomicBool::new(false)),\n            first_deadline: Arc::new(AtomicBool::new(false)),').replace('if self.cancel.cancelled.load(Ordering::Acquire) {','if self.cancel.first_deadline.load(Ordering::Acquire) { return Err(ControlStop::Deadline); }\n        if self.cancel.cancelled.load(Ordering::Acquire) {').replace('return Err(ControlStop::Deadline);\n        }\n        Ok(())','self.cancel.first_deadline.store(true,Ordering::Release);\n            return Err(ControlStop::Deadline);\n        }\n        Ok(())')
    cases.append(('first-reason-latch','reused_control_observes_current_stop_precedence',control,first,['assertion `left == right` failed']))
    clone=change(source,'#[derive(Clone)]\npub struct CancelToken','pub struct CancelToken')+'\nimpl Clone for CancelToken { fn clone(&self)->Self { Self { cancelled: Arc::new(AtomicBool::new(self.cancelled.load(Ordering::Acquire))) } } }\n'
    cases.append(('independent-clone','cancel_race_has_a_checkpoint_boundary',control,clone,['assertion `left == right` failed']))
    add('erase-context','cancel_after_success_preserves_metadata','            effect,\n            charges,','            effect: EffectSummary { attempted:0, completed:0, cleanup:CleanupDisposition::NotNeeded, flags:DescriptorFlagEffect::NotAttempted },\n            charges: ResourceCharges { syscalls:0, acquired:0, peak:0, read:None },',['metadata must not be refunded'])
    add('replace-errno','failed_syscall_wins_concurrent_cancel','    let post = control.checkpoint();\n    match result {\n        Err(source) => Err(LinuxError {\n            stage: Stage::ValidateFile,\n            reason: Reason::Unreadable,\n            source: Some(source),\n            effect: effect(1, 0),','    let post = control.checkpoint();\n    if let Err(stop)=post { return Err(stop.into_error(Stage::ValidateFile,effect(1,0),charges(1))); }\n    match result {\n        Err(source) => Err(LinuxError {\n            stage: Stage::ValidateFile,\n            reason: Reason::Unreadable,\n            source: Some(source),\n            effect: effect(1, 0),',['failed syscall stays primary'],True)
    add('deadline-first','expired_and_cancelled_prefers_cancel','    fn checkpoint_using(&self, now: impl FnOnce() -> Instant) -> Result<(), ControlStop> {','    fn checkpoint_using(&self, now: impl FnOnce() -> Instant) -> Result<(), ControlStop> {\n        if self.deadline.is_some() { return Err(ControlStop::Deadline); }',['assertion `left == right` failed'])
    add('omit-post-read','blocked_inner_read_is_not_claimed_interrupted','            post.map_err(|s| s.into_error(Stage::ValidateFile, effect(1, completed), charges(1)))?;','            let _ = post;',['unpublished bytes must be discarded'],True)
    add('refund-read','blocked_inner_read_is_not_claimed_interrupted','            post.map_err(|s| s.into_error(Stage::ValidateFile, effect(1, completed), charges(1)))?;','            post.map_err(|s| s.into_error(Stage::ValidateFile, effect(0, 0), charges(0)))?;',['incurred read charges must survive cancellation'],True)
    # The wrong owner reports cancellation while its actual entered Read is still
    # waiting. It retains a join solely for safe destructive-control cleanup.
    old='''    let worker = thread::spawn(move || {
        let result = one_read(
            EnteredRead {
                entered: entered_tx,
                release: release_rx,
            },
            &worker_control,
            &work_ledger,
        );
        done_tx.send(result).unwrap();
    });'''
    new='''    let worker = thread::spawn(move || {
        let read_control=worker_control.clone();
        let read_worker=thread::spawn(move || one_read(EnteredRead { entered:entered_tx, release:release_rx }, &read_control,&work_ledger));
        while worker_control.checkpoint().is_ok() { thread::yield_now(); }
        done_tx.send(Err(ControlStop::Cancelled.into_error(Stage::ValidateFile,effect(1,0),charges(1)))).unwrap();
        let _ = read_worker.join().unwrap();
    });'''
    add('report-before-release','blocked_inner_read_is_not_claimed_interrupted',old,new,['synchronous read must retain custody until release'],True)
    add('clock-domain-offset','clock_domains_do_not_convert','now() >= deadline.at','now() + Duration::from_secs(1000) >= deadline.at',['assertion `left == right` failed'])
    add('swallow-clock-panic','clock_callback_panic_unwinds_without_effect','now() >= deadline.at','std::panic::catch_unwind(std::panic::AssertUnwindSafe(now)).unwrap_or(deadline.at - Duration::from_secs(1)) >= deadline.at',['assertion failed: catch_unwind'])
    add('debug-time','controls_have_declared_traits_and_bounded_debug','f.write_str("MonotonicDeadline")','write!(f,"{{{:?}}}",self.at)',['assertion failed: !label.contains'])
    drop=source+'\nimpl Drop for CancelToken { fn drop(&mut self) { self.cancelled.store(false,Ordering::Release); } }\n'
    cases.append(('drop-reset','cancel_clone_drop_does_not_reset',control,drop,['assertion `left == right` failed']))
    spec=[];bindings=[]
    def copy(dest):
        dest.mkdir();shutil.copytree(root/'crates',dest/'crates')
        for name in ['Cargo.toml','Cargo.lock']:shutil.copyfile(root/name,dest/name)
    restored=out/'restored';copy(restored)
    for name,test,path,mutated,needles in cases:
        dest=out/name;copy(dest);(dest/path).write_text(mutated)
        target=['--test','controls',test] if name=='debug-time' else ['--lib','control::tests::'+test]
        argv=['test','--offline','--locked','-p','scopebase-linux',*target,'--','--exact','--nocapture']
        spec.append(dict(id=name+'-negative',toolchain='msrv',cwd=str(dest),argv=argv,failure=[test+' ... FAILED',*needles]))
        spec.append(dict(id=name+'-restored',toolchain='msrv',cwd=str(restored),argv=argv,target='restored'))
        bindings.append(dict(control=name,path=path,source_sha256=digest(root/path),mutated_sha256=digest(dest/path),restored_sha256=digest(restored/path),test=test,evidence_tier='fixture-operation-owner' if path==tests else 'production-primitive'))
    # C11 real-stream fixture receives the exact omitted-post-read mutation too.
    argv=['test','--offline','--locked','-p','scopebase-linux','--lib','control::tests::real_stream_read_control_boundary','--','--exact','--nocapture']
    spec += [dict(id='real-stream-omit-post-negative',toolchain='msrv',cwd=str(out/'omit-post-read'),argv=argv,failure=['real_stream_read_control_boundary ... FAILED','unpublished bytes must be discarded']),dict(id='real-stream-restored',toolchain='msrv',cwd=str(restored),argv=argv,target='restored')]
    (out/'commands.json').write_text(json.dumps(spec,indent=2)+'\n');(out/'bindings.json').write_text(json.dumps(bindings,indent=2)+'\n')
    print(out/'commands.json')
if __name__=='__main__':main()
