use scopebase_bpf::attach::*;
// Double-retire is inexpressible: the ticket moves into the first call.
fn double_retire<B: AttachBackend>(set: AttachmentSet<B>, pool: &mut RetirementPool<B>) {
    let _ = set.retire(pool);
    let _ = set.retire(pool);
}
fn main() {}
