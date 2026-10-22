use scopebase_bpf::{CpuTopology,LiveCpuTopology};
fn main(){let _:LiveCpuTopology=CpuTopology::parse_possible(b"0",0,1).unwrap();}
