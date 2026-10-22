use scopebase_bpf::{LiveCpuTopology,ValidatedMap};
fn debug<T:std::fmt::Debug>(){}
fn main(){debug::<LiveCpuTopology>();debug::<ValidatedMap>();}
