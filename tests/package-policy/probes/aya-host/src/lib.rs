// SPDX-License-Identifier: Apache-2.0
//! Compile-only potentially effectful APIs. None of these functions is invoked.
#[allow(dead_code)]
fn loader_api(bytes: &[u8]) -> Result<aya::Ebpf, aya::EbpfError> {
    aya::EbpfLoader::new().load(bytes)
}
#[allow(dead_code)]
fn lookup_api(bpf: &mut aya::Ebpf) {
    let _map: Option<&mut aya::maps::Map> = bpf.map_mut("probe");
    let _program: Option<&mut aya::programs::Program> = bpf.program_mut("probe");
}
#[allow(dead_code)]
fn ring_api(map: &mut aya::maps::Map) -> Result<(), aya::maps::MapError> {
    let mut ring = aya::maps::RingBuf::try_from(map)?;
    let _item = ring.next();
    Ok(())
}
#[allow(dead_code)]
fn attach_api(
    probe: &mut aya::programs::UProbe,
    point: aya::programs::uprobe::UProbeAttachPoint<'_>,
    path: &std::path::Path,
    scope: aya::programs::uprobe::UProbeScope,
) {
    let _ = probe.attach(point, path, scope);
}
#[test]
fn effectful_apis_typecheck() {
    let _loader: fn(&[u8]) -> Result<aya::Ebpf, aya::EbpfError> = loader_api;
    let _lookup: fn(&mut aya::Ebpf) = lookup_api;
    let _ring: fn(&mut aya::maps::Map) -> Result<(), aya::maps::MapError> = ring_api;
    let _attach = attach_api;
}
