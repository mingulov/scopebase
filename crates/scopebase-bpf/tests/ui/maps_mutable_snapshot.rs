use scopebase_bpf::{LiveCpuTopology,CpuTopology};
fn no_mutation(t:LiveCpuTopology){let _: &mut CpuTopology=t.snapshot();}
fn main(){}
