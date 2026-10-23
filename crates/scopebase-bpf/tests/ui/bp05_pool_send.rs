use scopebase_bpf::attach::*;
struct Stub;
#[derive(Debug)]
struct Link;
#[derive(Debug)]
struct Uncertain;
// SAFETY: UI stub; contract-honoring outcomes only.
unsafe impl AttachBackend for Stub {
    type Authority = ();
    type Link = Link;
    type Uncertain = Uncertain;
    fn custody_charge(
        &self,
        _: &Self::Authority,
        sites: &[Site],
    ) -> Result<CustodyCharge, scopebase_bpf::OperationError> {
        Ok(CustodyCharge { link_slots: sites.len(), retained_bytes: 0 })
    }
    fn attach(
        &mut self,
        _: &Self::Authority,
        _: &[Site],
        _: AttachMode,
    ) -> NativeAttach<Self::Link, Self::Uncertain> {
        NativeAttach::Attached(Link)
    }
    fn retire(&mut self, _: &mut Self::Link) -> NativeRetire {
        NativeRetire::Retired
    }
    fn retire_uncertain(&mut self, _: &mut Self::Uncertain) -> NativeRetire {
        NativeRetire::Retired
    }
}
fn send<T: Send>() {}
fn main() {
    send::<RetirementPool<Stub>>();
}
