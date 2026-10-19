"""Real offline worker soak; never contacts a competition or submits flags."""
import asyncio
import json
import resource
import secrets
import time
from pathlib import Path

import ctf.agent as module
from ctf.challenges import add

base = Path('/home/anonim/ctf-workspace')
workspace = base/('soak-'+secrets.token_hex(4))
calls = 0
original = module.run_phase


async def counted(*args, **kwargs):
    global calls
    calls += 1
    return await original(*args, **kwargs)


module.run_phase = counted
expected = {}


def insert(name):
    source = workspace/'inputs'/name
    source.mkdir(parents=True)
    flag = 'SOLARCTF{'+secrets.token_hex(8)+'}'
    (source/'data').write_text(flag)
    expected[name] = flag
    add(workspace, name, source)


async def main():
    insert('first')
    insert('second')
    agent = module.Agent(workspace)
    started = time.monotonic()
    rss = []
    for cycle in range(60):
        if cycle == 20:
            insert('third')
        if cycle == 35:
            expected['first'] = 'SOLARCTF{'+secrets.token_hex(8)+'}'
            (workspace/'inputs/first/data').write_text(expected['first'])
        if cycle == 45:
            agent = module.Agent(workspace)
        await agent.run('fast', 2, 10, incremental=True)
        state = agent.store.snapshot()
        assert not state['running']
        for item in state['challenges']:
            assert any(c['flag'] == expected[item['id']] for c in item['candidates'])
        assert not any((workspace/'agent-work').iterdir())
        rss.append(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        await asyncio.sleep(1)
    assert calls == 4, calls
    report = {'cycles': 60, 'worker_launches': calls, 'elapsed': time.monotonic()-started,
              'tasks': 3, 'input_changes': 1, 'agent_restarts': 1, 'temporary_directories_left': 0,
              'peak_rss_kib_start': rss[0], 'peak_rss_kib_end': rss[-1], 'passed': True,
              'limitations': 'Offline soak for about a minute, not a 24-hour endurance or live platform test.'}
    (base/'soak-report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report))


asyncio.run(main())
