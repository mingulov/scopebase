#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent Python corpus truth and binding checks; never runs a domain profile."""
import argparse,hashlib,json,pathlib,re

def pairs(v):
 out={}
 for k,x in v:
  if k in out:raise ValueError('duplicate key')
  out[k]=x
 return out

def read(p):return json.loads(p.read_bytes().decode(),object_pairs_hook=pairs,parse_float=lambda _:(_ for _ in ()).throw(ValueError('float')))
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def require(x,reason):
 if not x:raise ValueError(reason)

def check(root):
 root=pathlib.Path(root);catalog=read(root/'catalog.json');c=read(root/'contract.json');b=read(root/'bundle.json');truth=read(root/'expectations.json')
 require(truth['sum']=='5' and truth['bad_sum']=='6' and truth['tier']=='T0','literal independent truth')
 require((root/'operands.bytes').read_bytes()==b'2\n3\n','independent operands')
 numbers=(root/'operands.bytes').read_text().splitlines();total=sum(int(x)for x in numbers)
 require(str(total)==truth['sum'],'wrong arithmetic value')
 expected=read(root/'expected.json');require(expected=={'schema_version':1,'kind':'tt02-u64-expected','steps':[{'step_id':'sum','value':'5'}]},'literal expected')
 require(c['catalog_sha256']==digest(root/'catalog.json'),'catalog exact bytes')
 require(c['selection']['required']==[{'case_id':'H01.sum','case_version':1,'cell_id':'model','tier':'T0','implementation_status':'REGISTERED_EXECUTABLE','required_by':['tt02-harness-v1']}],'literal selection')
 require(b['run_contract_sha256']==digest(root/'contract.json'),'bundle contract')
 reg=catalog['cases'][0]['registration']
 for key in ('executable','fixture','oracle','bad_control'):
  a=reg[key];require(a['sha256']==digest(root/pathlib.Path(a['path']).name),'registered source')
 for file in b['files']:
  path=root/({'operands':'operands.bytes','expected':'expected.json','ledger':'ledger.json'}[file['file_id']]);require(file['sha256']==digest(path)and file['length']==str(path.stat().st_size),'actual vector bytes')
 ledger=read(root/'ledger.json');require(ledger['key']==b['invocations'][0]['key'],'ledger exact invocation')
 require(ledger['coverage']==[{'id':n,'step_ids':['sum'],'achieved':'1'}for n in ('excluded','positive','setup','trigger')],'active authored model populations')
 row=read(root/'unsupported-row.json');error=row['outcome']['error']
 require(error['category']=='unsupported_schema'and error['step_id']is None and error['completed_steps']==[]and error['partial_observation']is None and error['errno']is None and error['cause']['cause']=='unknown','typed no-operation rejection')
 require(row['capability']['state']=='unknown'and row['oracle_verdict']['checks'][0]['status']=='not_judged','preflight is not operation support')
 require(all(x['raw_achieved']=='1'and x['effective_achieved']==('1'if x['id']=='setup'else'0')for x in row['coverage']),'literal raw/effective preflight activity')
 for n in truth['malformed']:
  try:read(root/n)
  except (ValueError,UnicodeError):pass
  else:raise ValueError('malformed control accepted')
 return {'tier':'T0','sum':'5','bad_sum':'6','catalog_sha256':digest(root/'catalog.json'),'contract_sha256':digest(root/'contract.json')}

def main():
 p=argparse.ArgumentParser();p.add_argument('root',nargs='?',default=str(pathlib.Path(__file__).resolve().parents[2]/'crates/scopebase-testkit/tests/fixtures/harness'));a=p.parse_args();print(json.dumps(check(a.root),sort_keys=True))
if __name__=='__main__':main()
