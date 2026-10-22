use scopebase_bpf::{LiveCpuTopology,ValidatedMap};
fn sync<T:Sync>(){}
fn main(){sync::<LiveCpuTopology>();sync::<ValidatedMap>();}
