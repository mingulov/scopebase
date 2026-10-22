use scopebase_bpf::ValidatedMap;
use std::os::fd::AsRawFd;
fn no_raw_fd(t:ValidatedMap){let _=t.as_raw_fd();}
fn main(){}
