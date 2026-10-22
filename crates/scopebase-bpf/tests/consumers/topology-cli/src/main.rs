// SPDX-License-Identifier: Apache-2.0
use scopebase_bpf::{CpuTopology,PerCpuGeometry};
fn main()->Result<(),Box<dyn std::error::Error>>{
 let args:Vec<_>=std::env::args().collect();let input=std::fs::read(args.get(1).ok_or("usage: possible_topology CPULIST_FILE VALUE_SIZE")?)?;let size=args.get(2).ok_or("missing value size")?.parse()?;
 let t=CpuTopology::parse_possible(&input,65535,65536)?;let g=PerCpuGeometry::checked(size,t.count(),usize::MAX)?;
 println!("{:?} {} {}",t.ids(),g.stride(),g.buffer_len());Ok(())
}
