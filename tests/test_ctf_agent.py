import asyncio
import base64
import io
import json
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from ctf.agent import Agent, run_phase, sandbox_command
from ctf.agent_worker import graph
from ctf.challenges import add
from ctf.techniques import crypto, source_constraints


@pytest.mark.parametrize("payload", [
    base64.b32encode(b"SOLARCTF{base32}"),
    base64.b64encode(b"534f4c41524354467b6c61796572737d"),
    b"[83,79,76,65,82,67,84,70,123,97,114,114,97,121,125]",
    b"".join(format(c, "08b").encode() for c in b"SOLARCTF{bits}"),
    str(int.from_bytes(b"SOLARCTF{integer}", "big")).encode(),
])
def test_transform_graph(payload):
    findings, count = graph(payload)
    assert findings and count <= 400
    assert all(not f["verified"] for f in findings)
    assert any(f["method"] != "plain" for f in findings)


def test_archive_boundaries_and_nested_decoding():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as z:
        z.writestr("../escape", "SOLARCTF{unsafe}")
        z.writestr("good.txt", base64.b64encode(b"SOLARCTF{nested}"))
    findings, _ = graph(stream.getvalue())
    assert {f["flag"] for f in findings} == {"SOLARCTF{nested}"}
    assert findings[0]["method"].startswith("zip:good.txt")


def test_tar_does_not_follow_links():
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        symlink = tarfile.TarInfo("link")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "/etc/passwd"
        archive.addfile(symlink)
        info = tarfile.TarInfo("data")
        data = base64.b64encode(b"SOLARCTF{tar}")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    assert {f["flag"] for f in graph(stream.getvalue())[0]} == {"SOLARCTF{tar}"}


def test_rsa_root_and_common_modulus():
    message = int.from_bytes(b"flag{rsa}", "big")
    result = crypto(f"e=3\nc={message**3}".encode())
    assert ("rsa-exact-small-exponent", b"flag{rsa}") in result
    n = (2**127-1)*(2**61-1)
    data = f"n={n}\ne1=7\ne2=11\nc1={pow(message, 7, n)}\nc2={pow(message, 11, n)}".encode()
    assert ("rsa-common-modulus", b"flag{rsa}") in crypto(data)


def test_complete_source_constraints_only():
    source = b'''String x = userInput.substring("picoCTF{".length(),userInput.length()-1);
    return password.length() == 3 && password.charAt(2) == 'c' && password.charAt(0) == 'a' && password.charAt(1) == 'b';'''
    assert source_constraints(source) == [("source-character-constraints", b"picoCTF{abc}")]
    assert not source_constraints(source.replace(b"password.charAt(1) == 'b'", b"true"))


def test_no_crib_forced_flags_from_plaintext():
    data = b"def test(): return 123\nThis is an ordinary README without a hidden flag."
    assert graph(data, smart=True)[0] == []
    flags = graph(b"flag{watcher_verified}", smart=True)[0]
    assert {f["flag"] for f in flags} == {"flag{watcher_verified}"}


def test_xor_after_hex_with_independent_crib_validation():
    message = b"crypto{short_xor_key}"
    payload = bytes(v ^ 16 for v in message).hex().encode()
    assert {f["flag"] for f in graph(payload, smart=True)[0]} == {message.decode()}


@pytest.mark.skipif(sys.platform != "linux", reason="Linux Bubblewrap boundary")
def test_real_worker_isolation_and_result(tmp_path):
    source, scratch = tmp_path/"source", tmp_path/"scratch"
    source.mkdir()
    scratch.mkdir()
    (source/"encoded.txt").write_bytes(base64.b64encode(b"SOLARCTF{isolated}"))
    result = asyncio.run(run_phase(source, "fast", 10, 512, scratch))
    assert result["reason"] == "strategies_exhausted", result
    assert any(c["flag"] == "SOLARCTF{isolated}" for c in result["candidates"])
    assert result["max_rss_kib"] > 0


def test_sandbox_excludes_home_and_network(tmp_path):
    command = sandbox_command(tmp_path, tmp_path/"job")
    assert "--unshare-all" in command and "--clearenv" in command
    assert "--share-net" not in command
    assert str(Path.home()) not in command


def test_scheduler_cache_and_changed_inputs(tmp_path):
    source = tmp_path/"source"
    source.mkdir()
    (source/"data").write_bytes(base64.b64encode(b"SOLARCTF{one}"))
    workspace = tmp_path/"workspace"
    add(workspace, "case", source, "crypto")
    agent = Agent(workspace)
    asyncio.run(agent.run("fast", 1, 10))
    first = agent.store.snapshot()["challenges"][0]
    assert first["status"] == "candidates", first
    assert agent.store.snapshot()["solved"] == 0
    asyncio.run(agent.run("fast", 1, 10))
    assert agent.store.snapshot()["challenges"][0]["attempts"][0]["cached"]
    (source/"data").write_bytes(base64.b64encode(b"SOLARCTF{two}"))
    asyncio.run(agent.run("fast", 1, 10))
    changed = agent.store.snapshot()["challenges"][0]
    assert changed["signature"] != first["signature"]
    assert not changed["attempts"][0]["cached"]


def test_stop_reaps_running_and_queued(tmp_path, monkeypatch):
    source = tmp_path/"source"
    source.mkdir()
    (source/"data").write_text("no flags")
    workspace = tmp_path/"workspace"
    for i in range(3):
        add(workspace, f"case-{i}", source)
    active = asyncio.Event()
    async def fake(*args):
        active.set()
        await asyncio.sleep(100)
    monkeypatch.setattr("ctf.agent.run_phase", fake)
    agent = Agent(workspace)
    async def exercise():
        task = asyncio.create_task(agent.run("fast", 1, 10))
        await active.wait()
        agent.stop()
        await task
    asyncio.run(exercise())
    assert not agent.store.snapshot()["running"]
    assert all(i["status"] == "interrupted" for i in agent.store.snapshot()["challenges"])


def test_solar_waits_without_querying_tasks(tmp_path):
    httpx = pytest.importorskip("httpx")
    from ctf.solar import Solar
    (tmp_path/"solar-session.json").write_text(json.dumps({"cookies": [
        {"name": "token", "domain": "solarctf.ru", "value": "test-token"}]}))
    requests = []
    def handler(request):
        requests.append(request.url.path)
        assert request.headers["authorization"] == "Bearer test-token"
        return httpx.Response(200, json={"status": "Not Started"})
    adapter = Solar(tmp_path, httpx.MockTransport(handler))
    assert asyncio.run(adapter.discover())["discovered"] == 0
    assert requests == ["/get-status"]


def test_solar_submission_disabled_and_deduplicated(tmp_path):
    httpx = pytest.importorskip("httpx")
    from ctf.solar import Solar
    (tmp_path/"solar-session.json").write_text(json.dumps({"cookies": [
        {"name": "token", "domain": "solarctf.ru", "value": "test-token"}]}))
    requests = []
    def handler(request):
        requests.append(request.url.path)
        return httpx.Response(200, json={"status": "Playing", "toast": "success"})
    adapter = Solar(tmp_path, httpx.MockTransport(handler))
    with pytest.raises(ValueError):
        asyncio.run(adapter.submit("SOLARCTF{test}", False))
    assert not requests
    assert asyncio.run(adapter.submit("SOLARCTF{test}", True))["verified"]
    assert asyncio.run(adapter.submit("SOLARCTF{test}", True))["verified"]
    assert requests == ["/get-status", "/check-flag"]


def test_attachment_credentials_never_leak(tmp_path, monkeypatch):
    httpx = pytest.importorskip("httpx")
    from ctf.solar import Solar
    monkeypatch.setattr("ctf.solar.socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])
    def handler(request):
        assert "authorization" not in request.headers
        return httpx.Response(200, content=b"organizer attachment")
    asyncio.run(Solar(tmp_path, httpx.MockTransport(handler)).download("https://example.org/file", tmp_path/"out"))
    assert (tmp_path/"out").read_bytes() == b"organizer attachment"


def test_panel_submits_only_registered_platform_tasks(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from ctf.challenges import save
    from ctf.panel import Control

    entries = {
        "solar-ready": {}, "solar-99": {}, "solar-4": {"platform_id": 5},
        "solar-6": {"platform_id": 6, "platform_solved": True},
        "solar-7": {"platform_id": 7},
    }
    save(tmp_path, {"schema": 1, "challenges": entries})
    items = [{"id": key, "candidates": [{"flag": f"SOLARCTF{{{key}}}"}]}
             for key in entries]
    sent = []

    async def run(**kwargs):
        pass

    async def submit(self, flag, enabled):
        sent.append(flag)
        return {"verified": True}

    monkeypatch.setattr("ctf.solar.Solar.submit", submit)
    control = object.__new__(Control)
    control.workspace = tmp_path
    control.busy = True
    store = SimpleNamespace(snapshot=lambda: {"challenges": items},
                            put=lambda *args: None, meta=lambda *args: None)
    control.agent = SimpleNamespace(run=run, store=store, stop_requested=False)
    asyncio.run(control.cycle_once({"solar": False, "submit": True}))
    assert sent == ["SOLARCTF{solar-7}"]


def test_web_platform_and_private_target_excluded():
    from ctf.web_probe import probe
    for url in ("https://solarctf.ru/team/690", "https://backend.solarctf.ru/", "http://127.0.0.1:8765/"):
        with pytest.raises(ValueError):
            asyncio.run(probe(url))


def test_generated_solver_cannot_read_home(tmp_path):
    source, scratch = tmp_path/"source", tmp_path/"scratch"
    source.mkdir()
    scratch.mkdir()
    script = "from pathlib import Path\nassert not Path('/home/anonim/.ssh').exists()\nprint('flag{isolated_generated}')\n"
    result = asyncio.run(run_phase(source, "llm", 5, 512, scratch, script))
    assert result["reason"] == "completed", result
    assert result["candidates"][0]["confidence"] == "unverified_generated_solution"
    assert not result["candidates"][0]["verified"]


def test_generated_solver_hard_deadline(tmp_path):
    import time
    source, scratch = tmp_path/"source", tmp_path/"scratch"
    source.mkdir()
    scratch.mkdir()
    start = time.monotonic()
    result = asyncio.run(run_phase(source, "llm", 1, 512, scratch, "import time\ntime.sleep(60)"))
    assert result["reason"] == "timeout", result
    assert time.monotonic()-start < 6
