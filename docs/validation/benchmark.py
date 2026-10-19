"""Repeatable public training benchmark; expected answers never enter solver inputs."""
import asyncio
import hashlib
import json
import secrets
import time
from pathlib import Path

from bs4 import BeautifulSoup

from ctf.agent import Agent
from ctf.challenges import load, save

base = Path('/home/anonim/ctf-workspace')
source = base/'benchmark-source'
workspace = base/'benchmark-run'
workspace.mkdir(exist_ok=True)
page = BeautifulSoup((source/'cryptohack.html').read_text(), 'html.parser').get_text(' ', strip=True)
cases = []

def case(identifier, category, data, expected, provenance, filename='challenge.txt', hint=False):
    folder = workspace/'inputs'/identifier
    folder.mkdir(parents=True, exist_ok=True)
    (folder/filename).write_bytes(data)
    cases.append({'id': identifier, 'category': category, 'source': str(folder), 'expected': expected,
                  'provenance': provenance, 'hint': hint, 'sha256': hashlib.sha256(data).hexdigest()})

url='https://cryptohack.org/challenges/general/'
inputs = [
    ('cryptohack-ascii', '[99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]', 'crypto{ASCII_pr1nt4bl3}'),
    ('cryptohack-hex', '63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d', 'crypto{You_will_be_working_with_hex_strings_a_lot}'),
    ('cryptohack-integer', '11515195063862318899931685488813747395775516287289682636499965282714637259206269', 'crypto{3nc0d1n6_4ll_7h3_w4y_d0wn}'),
    ('cryptohack-favourite-byte', '73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d', 'crypto{0x10_15_my_f4v0ur173_by7e}'),
    ('cryptohack-repeating-xor', '0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104', 'crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll}'),
]
for identifier, payload, expected in inputs:
    assert payload in page, identifier+' source mismatch'
    case(identifier, 'crypto', payload.encode(), expected, url)

template=(source/'client-side.html').read_text()
flag='picoCTF{client_is_bad_'+secrets.token_hex(3)+'}'
for i in range(8):
    value=flag[i*4:(i+1)*4] if i<7 else flag[i*4:]
    template=template.replace('{{flag'+str(i+1)+'}}', value)
case('pico-client-side', 'web', template.encode(), flag,
     'https://github.com/picoCTF/picoCTF-2019-example-problems/tree/master/client-side-java', 'index.html')
case('pico-store-source', 'pwn', (source/'store.c').read_bytes(), None,
     'https://github.com/picoCTF/picoCTF-2019-example-problems/tree/master/store', 'store.c')

registry={'schema':1,'challenges':{c['id']:{k:c[k] for k in ('id','source','category')} for c in cases}}
save(workspace,registry)
started=time.monotonic()
agent=Agent(workspace)
asyncio.run(agent.run('balanced',2,45))
states={c['id']:c for c in agent.store.snapshot()['challenges']}
records=[]
for c in cases:
    item=states[c['id']]
    exact=c['expected'] is not None and any(f['flag']==c['expected'] for f in item['candidates'])
    attempts=item['attempts']
    records.append({
        'id':c['id'],'category':c['category'],'source_url':c['provenance'],'input_sha256':c['sha256'],
        'solved_exactly':exact,'platform_submitted':False,'hints':c['hint'],'seconds':item['elapsed'],
        'attempts':len(attempts),'strategies':[a['phase'] for a in attempts],
        'peak_rss_kib':max((a.get('max_rss_kib',0) for a in attempts),default=0),
        'cpu_seconds':sum(a.get('cpu_seconds',0) for a in attempts),
        'candidates':item['candidates'],
        'reason':'exact_reference_match' if exact else 'requires interactive runtime and exploit synthesis' if c['expected'] is None else item.get('reason'),
    })
report={'generated_at_unix':time.time(),'elapsed':time.monotonic()-started,
        'solved':sum(r['solved_exactly'] for r in records),'total':len(records),
        'hints':0,'tests':records,
        'limits':['Small training sample, not representative of all CTF difficulties.',
                  'CryptoHack expected answers are held outside the solver inputs; no submissions made.',
                  'pico-client-side is an instance of the official public template with a fresh random suffix.',
                  'pico-store-source is source-only; no local service or hidden flag was supplied.',
                  'No real SolarCTF challenge was available before the competition start.']}
(base/'benchmark-report.json').write_text(json.dumps(report,indent=2,ensure_ascii=False))
print(json.dumps(report,indent=2,ensure_ascii=False))
