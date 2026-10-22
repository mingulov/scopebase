use scopebase_bpf::{LiveCpuTopology,ValidatedMap};
fn no_clone(t:LiveCpuTopology,m:ValidatedMap){let _=t.clone();let _=m.clone();}
fn main(){}
