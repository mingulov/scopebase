use scopebase_bpf::attach::*;
fn no_clone<B: AttachBackend>(s: AttachmentSet<B>, u: UnresolvedAttachments<B>, p: RetirementPool<B>) {
    let _ = s.clone();
    let _ = u.clone();
    let _ = p.clone();
}
fn main() {}
