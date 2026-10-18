// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::{file::{ContentSnapshot, FileRead, HeldFile, ReadCharges, ReadLimits, ReadObservations},control::OperationControl,error::LinuxError};
fn check<T:Send+Sync>(){}
fn observe(r:&FileRead){let _: &[u8]=r.bytes();let o:&ReadObservations=r.observations();let _:ContentSnapshot=o.content_snapshot();let _=(o.before(),o.after());let c:ReadCharges=r.charges();let _=(c.read_calls(),c.bytes_read(),c.requested_capacity(),c.granted_capacity(),c.retained_capacity());let _:FileRead=r.clone();}
fn main(){check::<FileRead>();check::<ReadLimits>();check::<ReadObservations>();check::<ReadCharges>();check::<ContentSnapshot>();let _:fn(&HeldFile,ReadLimits,&OperationControl)->Result<FileRead,LinuxError>=HeldFile::read_all;let _:fn(&FileRead)=observe;}
