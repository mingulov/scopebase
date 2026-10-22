#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Two focused R1 binder mutations in private copies; no Cargo or build lease."""
import argparse,hashlib,json,os,pathlib,shutil,sys
ROOT=pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools/build'));import common as p

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);a=ap.parse_args();out=pathlib.Path(a.output).resolve();out.mkdir(mode=0o700);source=out/'qualification';(source/'tests').mkdir(parents=True);shutil.copy(ROOT/'tools/qualification/bind_consumer.py',source/'bind_consumer.py');shutil.copy(ROOT/'tools/qualification/tests/test_bind_consumer.py',source/'tests/test_bind_consumer.py');file=source/'bind_consumer.py';original=file.read_bytes();text=original.decode();results=[]
 selected=next(line for line in text.splitlines()if 'len(paths)!=1 or any'in line)
 mutants=[('r1-selected-source-to-build',selected,selected[:len(selected)-len(selected.lstrip())]+'if False:raise BindingError("SubjectMismatch: selected source-to-build")','test_bound_actual_records_and_swaps','BindingError not raised'),('r1-descriptor-preflight',text,text.replace('  if expected is not None:digest(expected)\n','').replace('   actual=h.hexdigest()\n','   actual=h.hexdigest()\n   if expected is not None:digest(expected)\n'),'test_review_a5_invalid_digest_is_zero_io','invalid descriptor must precede all file I/O')]
 mutants.append(('r1-file-descriptor-path', " for value in record['artifact_files'].values():path_descriptor(value)", '', 'test_bound_actual_records_and_swaps', 'invalid descriptor path must precede all file I/O'))
 def run(identity,test,expected):
  r=p.run([sys.executable,'-m','unittest','test_bind_consumer.BindingTests.'+test,'-v'],source/'tests',dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),out/identity,timeout=60);results.append({'id':identity,**r})
  if r['exit_code']!=expected or r['reason_code']or r['cleanup']!='complete':raise AssertionError((identity,r))
  return pathlib.Path(r['logs']['stderr']['path']).read_text()
 try:
  for identity,before,after,test,marker in mutants:
   assert text.count(before)==1;run(identity+'-baseline',test,0);mutated=text.replace(before,after).encode();file.write_bytes(mutated);(out/(identity+'.json')).write_text(json.dumps({'before_sha256':hashlib.sha256(original).hexdigest(),'after_sha256':hashlib.sha256(mutated).hexdigest(),'target':str(file),'test':test,'marker':marker},indent=2)+'\n')
   try:
    diagnostic=run(identity+'-mutant',test,1);assert marker in diagnostic and 'FAIL:'in diagnostic and 'ERROR:'not in diagnostic,'intended semantic assertion must fail'
   finally:file.write_bytes(original)
   run(identity+'-restored',test,0)
  (out/'results.json').write_text(json.dumps({'status':'PASS','required':[m[0]for m in mutants],'results':results,'resources':'All bounded Python process groups/pipes retired; private binder restored byte-exactly; no Cargo or lease acquired'},indent=2)+'\n')
 except Exception as e:(out/'results.json').write_text(json.dumps({'status':'FAIL','results':results,'exception':repr(e)},indent=2)+'\n');raise
if __name__=='__main__':main()
