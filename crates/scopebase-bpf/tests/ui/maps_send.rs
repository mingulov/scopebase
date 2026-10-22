use scopebase_bpf::{LiveCpuTopology,ValidatedMap};
fn send<T:Send>(){}
fn main(){send::<LiveCpuTopology>();send::<ValidatedMap>();}
