"""Fresh randomized end-to-end fixtures, separate from public training benchmark."""
import asyncio
import base64
import gzip
import io
import json
import math
import secrets
import time
import wave
import zipfile
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.number import getPrime
from Crypto.Util.Padding import pad
from PIL import Image

from ctf.agent import Agent
from ctf.challenges import save

base = Path('/home/anonim/ctf-workspace')
workspace = base / ('upgrade-benchmark-'+secrets.token_hex(4))
cases = []


def case(name, payload, category='crypto', suffix='.txt', flag=None):
    folder = workspace/'inputs'/name
    folder.mkdir(parents=True)
    (folder/('challenge'+suffix)).write_bytes(payload)
    cases.append({'id': name, 'source': str(folder), 'category': category, 'expected': flag})


def fresh():
    return ('SOLARCTF{'+secrets.token_hex(8)+'}').encode()


for name, encode in [('utf16', lambda f: f.decode().encode('utf-16-le')),
                     ('reversed-base64', lambda f: base64.b64encode(f)[::-1]),
                     ('spaced-hex', lambda f: b' '.join(f'{b:02x}'.encode() for b in f))]:
    flag = fresh()
    case(name, encode(flag), flag=flag.decode())
flag = fresh()
buffer = io.BytesIO()
with zipfile.ZipFile(buffer, 'w') as archive:
    archive.writestr('nested.gz', gzip.compress(base64.b64encode(flag)))
case('nested-archive', buffer.getvalue(), 'forensics', '.zip', flag.decode())

flag = fresh()
secret = secrets.token_bytes(16)
encrypted = AES.new(secret, AES.MODE_ECB).encrypt(pad(flag, 16))
case('aes-supplied-key', f'key={secret.hex()}\nciphertext={encrypted.hex()}'.encode(), flag=flag.decode())

for name in ('rsa-wiener', 'rsa-small-factor', 'rsa-broadcast'):
    flag = fresh()
    message = int.from_bytes(flag, 'big')
    if name == 'rsa-broadcast':
        params = {'e': 3}
        for i in range(1, 4):
            modulus = getPrime(144)*getPrime(144)
            params[f'n{i}'], params[f'c{i}'] = modulus, pow(message, 3, modulus)
    else:
        p = getPrime(144) if name == 'rsa-wiener' else 65537
        q = getPrime(240)
        n, phi = p*q, (p-1)*(q-1)
        if name == 'rsa-wiener':
            d = 3
            while math.gcd(d, phi) != 1:
                d += 2
            e = pow(d, -1, phi)
        else:
            e = 65537
        params = {'n': n, 'e': e, 'c': pow(message, e, n)}
    case(name, json.dumps(params).encode(), flag=flag.decode())

flag = fresh()
checker = f'def verify(s):\n    assert len(s) == {len(flag)}\n    assert ord(s[0]) == {flag[0]}\n'
for i in range(len(flag)-1):
    checker += f'    assert ord(s[{i}]) + ord(s[{i+1}]) == {flag[i]+flag[i+1]}\n'
case('z3-coupled-equations', checker.encode(), 'reverse', '.py', flag.decode())

flag = fresh()
pixels = bytearray([128, 128, 128, 252]*len(flag)*8)
for i, bit in enumerate(int(b) for value in flag for b in f'{value:08b}'):
    pixels[4*i+3] |= bit << 1
buffer = io.BytesIO()
Image.frombytes('RGBA', (len(flag)*8, 1), bytes(pixels)).save(buffer, format='PNG')
case('png-alpha-second-plane', buffer.getvalue(), 'forensics', '.png', flag.decode())

flag = fresh()
buffer = io.BytesIO()
frames = b''.join(bytes([int(bit), 0]) for value in flag for bit in f'{value:08b}')
with wave.open(buffer, 'wb') as audio:
    audio.setnchannels(1)
    audio.setsampwidth(2)
    audio.setframerate(8000)
    audio.writeframes(frames)
case('wav-lsb', buffer.getvalue(), 'forensics', '.wav', flag.decode())
case('negative-random', secrets.token_bytes(4096), 'misc', '.bin')
case('negative-prose', b'This is an ordinary project README. It does not contain a challenge solution.', 'misc')
save(workspace, {'schema': 1, 'challenges': {c['id']: {k: c[k] for k in ('id', 'source', 'category')} for c in cases}})
agent = Agent(workspace)
started = time.monotonic()
asyncio.run(agent.run('balanced', 2, 45))
states = {c['id']: c for c in agent.store.snapshot()['challenges']}
report = {'type': 'randomized synthetic regression, not competition win probability',
          'elapsed': time.monotonic()-started, 'tests': []}
for case in cases:
    result = states[case['id']]
    candidates = [c['flag'] for c in result['candidates']]
    expected = case['expected']
    report['tests'].append({'id': case['id'], 'passed': (expected in candidates) if expected else not candidates,
                            'negative_control': expected is None, 'seconds': result['elapsed'],
                            'unexpected_candidates': [c for c in candidates if c != expected],
                            'candidates': candidates, 'reason': result.get('reason'),
                            'attempts': [{k: a.get(k) for k in ('phase', 'reason', 'error', 'max_rss_kib')} for a in result['attempts']]})
report['passed'] = sum(c['passed'] for c in report['tests'])
report['total'] = len(cases)
(base/'upgrade-benchmark-report.json').write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
