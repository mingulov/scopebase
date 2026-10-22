#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent fixed-offset/bigint oracle. No ScopeBase/donor code imported."""
import argparse, hashlib, json, struct
from pathlib import Path

def vectors():
    header=struct.pack('<HBBIIIII',0xeb9f,1,0,24,0,32,32,9)
    types=struct.pack('<IIII',1,1<<24,4,32)+struct.pack('<IIII',5,1<<24,8,64)
    def lane(comm,tid,uid,cgroup,ppid,pcomm,stack,calls,first,last,marker):
        return struct.pack('<16sIIQI16siQQQII',comm,tid,uid,cgroup,ppid,pcomm,stack,calls,first,last,marker,0)
    who=lane(b'inserter',100,0,291,4,b'parent',0,5,11,22,1)+lane(b'latest',101,999,999,999,b'noise',7,7,33,44,0)
    geometry=[dict(value=v,count=n,stride=((v+7)//8)*8,extent=((v+7)//8)*8*n) for v in [1,7,8,9,13] for n in [1,3,9]]
    return {'btf-u32-u64.bin':header+types+b'\0u32\0u64\0','who88-two-lanes.bin':who,'kwho-key16.bin':struct.pack('<QII',0x8e834f55dbe259a5,4242,0),'geometry.json':(json.dumps(geometry,indent=2)+'\n').encode()}

def main():
    a=argparse.ArgumentParser();a.add_argument('--check',action='store_true');args=a.parse_args();root=Path(__file__).resolve().parent
    manifest=json.loads((root/'manifest.json').read_text())
    for name,data in vectors().items():
        if name.endswith('.bin'):
            field={'btf-u32-u64.bin':'btf','who88-two-lanes.bin':'who','kwho-key16.bin':'kwho_key'}[name]
            assert hashlib.sha256(data).hexdigest()==manifest[field]['sha256'],name
        if args.check:assert (root/name).read_bytes()==data,name
        else:(root/name).write_bytes(data)
    print('PASS independent fixed vectors')
if __name__=='__main__':main()
