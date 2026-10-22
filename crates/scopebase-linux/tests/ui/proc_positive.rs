// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::procfs::{parse_maps,parse_mountinfo,ParseLimits};
fn main(){ let l=ParseLimits{max_bytes:4096,max_entries:64,max_line_bytes:512};let s=parse_maps(b"1-2 r-xp 0 0:0 1 /a\n",l).unwrap();let e=s.entries().next().unwrap();assert_eq!(e.file_key().inode(),1);let t=parse_mountinfo(b"17 1 0:42 / / rw - fs s rw\n",l).unwrap();let m=t.entries().next().unwrap();assert_eq!(m.id(),t.entry_by_number(17).unwrap().id()); }
