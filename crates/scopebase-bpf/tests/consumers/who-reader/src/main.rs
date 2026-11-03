// SPDX-License-Identifier: Apache-2.0
#[path="who_fixture.rs"] mod who;
#[path="native_fixture.rs"] mod fixture;
use scopebase_bpf::ValidatedMap;
fn main()->Result<(),Box<dyn std::error::Error>>{
 let args:Vec<_>=std::env::args().collect();let root=std::path::PathBuf::from(args.get(1).ok_or("fixture directory required")?);
 let key=std::fs::read(root.join("kwho-key16.bin"))?;
 let rows=if args.get(2).is_some_and(|a|a=="--native"){
  fixture::require_offline();let fd=fixture::create(5,16,88,2,0,None)?;let mut data=vec![0;65536*88];let lane=who::load_two_lane_bytes(&root.join("who88-two-lanes.bin"))?;data[..176].copy_from_slice(&lane);fixture::update(&fd,&key,&data)?;
  let mut map=ValidatedMap::from_owned_fd(fd,&fixture::expected(5,16,88,2,0),&fixture::limits())?;let count=map.topology().count();who::report_rows(&[&key],count,|k|map.lookup(k).map_err(|e|e.to_string()))?
 }else{
  let file=args.get(2).map(std::path::PathBuf::from).unwrap_or(root.join("who88-two-lanes.bin"));let data=std::fs::read(file)?;who::report_rows(&[&key],2,|_|Ok(Some(data.clone())))?
 };
 for(k,v)in rows{println!("{},{},{},{},{},{},{},{},{}",k.tgid,v.calls,v.tid,v.uid,v.stack,v.cgroup,v.ppid,v.first_ns,v.last_ns);}Ok(())
}
