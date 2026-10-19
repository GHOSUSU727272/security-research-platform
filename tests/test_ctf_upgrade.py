import asyncio
import bz2
import gzip
import io
import json
import lzma
import random
import time
import wave

import httpx
import pytest

from ctf.advanced import periodic_xor, python_constraints, rsa
from ctf.agent import Agent, Store, signature
from ctf.agent_worker import graph
from ctf.challenges import add, load
from ctf.media import recover
from ctf.panel import Control
from ctf.solar import Solar


@pytest.mark.parametrize("compress", [gzip.compress, bz2.compress, lzma.compress])
def test_compressed_non_tar_payload(compress):
    flag = b"SOLARCTF{compressed_payload_937}"
    assert any(f["flag"].encode() == flag for f in graph(compress(flag))[0])


def test_xor_long_crib_has_independent_body_validation():
    flag = b"crypto{sample_independent_body_1234567890}"
    key = b"newKEY8!"
    # Key length is 8; last byte supplies the missing byte when len(flag)%8=0.
    flag = flag[:-1]+b"X"*((-len(flag))%8)+b"}"
    cipher = bytes(v ^ key[i % len(key)] for i, v in enumerate(flag))
    assert any(v == flag for _, v in periodic_xor(cipher))
    rng = random.Random(1729)
    for _ in range(100):
        assert not periodic_xor(rng.randbytes(48))
    assert not periodic_xor(b"Read this document for a general example of the task.")


@pytest.mark.parametrize("encode", [lambda f: f.decode().encode("utf-16-le"),
                                  lambda f: f[::-1],
                                  lambda f: b" ".join(f"{b:02x}".encode() for b in f),
                                  lambda f: b"".join(f"\\x{b:02x}".encode() for b in f)])
def test_additional_encoding_roundtrips(encode):
    flag = b"SOLARCTF{new_codec_937}"
    assert any(item["flag"].encode() == flag for item in graph(encode(flag))[0])


def test_rsa_missing_modulus_and_private_exponent():
    p, q, e = 1000000007, 1000000009, 65537
    m = int.from_bytes(b"test123", "big")
    n = p*q
    c = pow(m, e, n)
    source = json.dumps({"p": p, "q": q, "e": e, "c": c}).encode()
    assert any(v == b"test123" for _, v in rsa(source))
    d = pow(e, -1, (p-1)*(q-1))
    assert any(v == b"test123" for _, v in rsa(f"n={n}\ne={e}\nd={d}\nc={c}".encode()))


def test_rsa_broadcast_verified():
    m = 12345678
    moduli = [1000000007*1000000009, 1000000033*1000000087, 1000000093*1000000097]
    params = {"e": 3}
    for i, n in enumerate(moduli, 1):
        params[f"n{i}"], params[f"c{i}"] = n, pow(m, 3, n)
    assert any(int.from_bytes(v, "big") == m for _, v in rsa(json.dumps(params).encode()))


def checker(flag):
    return ("def check(s):\n    assert len(s) == "+str(len(flag))+"\n"+
            "".join(f"    assert (ord(s[{i}]) ^ {17+i}) == {value ^ (17+i)}\n" for i, value in enumerate(flag))).encode()


def test_z3_unique_checker_and_rejects_incomplete_or_malicious(tmp_path):
    flag = b"SOLARCTF{constraints_937}"
    assert python_constraints(checker(flag)) == [("python-z3-unique-constraints", flag)]
    assert not python_constraints(b"assert len(s)==20\nassert ord(s[0])==83")
    assert not python_constraints(b"assert len(s)==20\nassert __import__('os').system('id')==0")
    assert not python_constraints(checker(flag)+b"    assert ord(s[0]) == 1\n")
    assert not python_constraints(b"assert len(s)==4\nif False:\n    assert ord(s[0])==88")


def test_wav_lsb():
    flag = b"SOLARCTF{sound_data_937}"
    frames = bytes(int(b) for value in flag for b in f"{value:08b}")
    stream = io.BytesIO()
    with wave.open(stream, "wb") as audio:
        audio.setnchannels(1)
        audio.setsampwidth(1)
        audio.setframerate(8000)
        audio.writeframes(frames)
    assert any(flag in value for _, value in recover(stream.getvalue()))


def test_png_alpha_second_bitplane():
    from PIL import Image
    flag = b"SOLARCTF{alpha_plane_937}"
    pixels = bytearray([128, 128, 128, 252]*len(flag)*8)
    for i, bit in enumerate(int(b) for value in flag for b in f"{value:08b}"):
        pixels[4*i+3] |= bit << 1
    picture = Image.frombytes("RGBA", (len(flag)*8, 1), bytes(pixels))
    stream = io.BytesIO()
    picture.save(stream, format="PNG")
    assert any(flag in value for _, value in recover(stream.getvalue()))


def test_signature_ignores_bookkeeping(tmp_path):
    (tmp_path/"input").write_text("data")
    assert signature(tmp_path, {"category": "crypto", "status": "new"}) == signature(tmp_path, {"category": "crypto", "status": "analyzed"})
    assert signature(tmp_path, {"scope": [{"url": "https://example.org/a"}]}) != signature(tmp_path, {"scope": []})


def test_incremental_skips_completed_but_detects_changed_input(tmp_path, monkeypatch):
    source = tmp_path/"input"
    source.mkdir()
    (source/"data").write_text("one")
    workspace = tmp_path/"workspace"
    add(workspace, "local", source)
    calls = []

    async def phase(*args):
        calls.append(args)
        return {"reason": "strategies_exhausted", "candidates": []}

    monkeypatch.setattr("ctf.agent.run_phase", phase)
    agent = Agent(workspace)
    asyncio.run(agent.run("fast", 1, 10, incremental=True))
    asyncio.run(agent.run("fast", 1, 10, incremental=True))
    assert len(calls) == 1
    (source/"data").write_text("two")
    asyncio.run(agent.run("fast", 1, 10, incremental=True))
    assert len(calls) == 2
    asyncio.run(agent.run("fast", 1, 10, include_local=False))
    assert len(calls) == 2


def control_without_thread(tmp_path):
    control = object.__new__(Control)
    control.workspace = tmp_path
    control.agent = Agent(tmp_path)
    control.busy, control.cycle, control.state = True, 0, "idle"
    control.next_check = None
    return control


def test_watch_backoff_and_finished(tmp_path, monkeypatch):
    control = control_without_thread(tmp_path)
    delays = []
    statuses = iter(["needs_attention", "needs_attention", "Not Started", "Finished"])

    async def cycle(settings):
        control.agent.store.meta("platform", {"status": next(statuses)})

    async def sleep(delay):
        delays.append(round(delay))

    control.cycle_once = cycle
    monkeypatch.setattr("ctf.panel.asyncio.sleep", sleep)
    asyncio.run(control.pipeline({"continuous": True, "interval": 30}, time.time()+3600))
    assert delays == [60, 120, 30]
    assert control.cycle == 4
    assert not control.busy
    assert not control.agent.store.meta("watch_intent")["active"]


def test_watch_cancel_during_wait(tmp_path):
    control = control_without_thread(tmp_path)
    ready = asyncio.Event()

    async def cycle(settings):
        ready.set()

    control.cycle_once = cycle

    async def exercise():
        task = asyncio.create_task(control.pipeline({"continuous": True, "interval": 30}, time.time()+3600))
        await ready.wait()
        task.cancel()
        await task

    asyncio.run(exercise())
    assert not control.busy
    assert control.agent.stop_requested


def test_watch_resumes_only_unexpired_intent(tmp_path, monkeypatch):
    Store(tmp_path).meta("watch_intent", {"active": True, "until": time.time()+3600,
                                         "settings": {"continuous": True, "submit": False}})
    called = []
    monkeypatch.setattr(Control, "start", lambda self, settings, until=None: called.append((settings, until)))
    control = Control(tmp_path)
    control.loop.call_soon_threadsafe(control.loop.stop)
    control.thread.join(timeout=2)
    control.loop.close()
    assert len(called) == 1
    assert called[0][0]["submit"] is False


def test_discovery_incremental_refresh_and_changed_attachment(tmp_path, monkeypatch):
    (tmp_path/"solar-session.json").write_text(json.dumps({"cookies": [{"name": "token", "domain": "solarctf.ru", "value": "test"}]}))
    paths = []
    version = [b"version-one"]
    monkeypatch.setattr("ctf.solar.socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])
    def handler(request):
        paths.append(request.url.path)
        if request.url.path == "/file.bin":
            assert "authorization" not in request.headers
            return httpx.Response(200, content=version[0])
        responses = {"/get-status": {"status": "Playing"}, "/get-categories": {"categories": [{"category_name": "Crypto"}]},
                     "/get-tasks": {"tasks": [{"task_id": 7}]},
                     "/get-task": {"task": {"task_name": "Example", "task_description": "test", "task_links": [
                         {"type": {"name": "sources"}, "url": "https://example.org/file.bin"}]}}}
        return httpx.Response(200, json=responses[request.url.path])
    async def run():
        for _ in range(2):
            await Solar(tmp_path, httpx.MockTransport(handler)).discover()
    asyncio.run(run())
    assert paths.count("/get-task") == 1
    assert load(tmp_path)["challenges"]["solar-7"]["platform_id"] == 7
    assert (tmp_path/"solar-inputs/solar-7/attachment-0.bin").read_bytes() == b"version-one"
    assert paths.count("/file.bin") == 1
    version[0] = b"version-two"
    (tmp_path/"solar-index.json").write_text("{}")
    asyncio.run(Solar(tmp_path, httpx.MockTransport(handler)).discover())
    assert (tmp_path/"solar-inputs/solar-7/attachment-0.bin").read_bytes() == b"version-two"


def test_attachment_private_redirect_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr("ctf.solar.socket.getaddrinfo", lambda host, *a, **k: [(2, 1, 6, "", ("127.0.0.1" if host == "localhost" else "93.184.216.34", 443))])
    def handler(request):
        return httpx.Response(302, headers={"Location": "https://localhost/secrets"})
    with pytest.raises(ValueError, match="non-public"):
        asyncio.run(Solar(tmp_path, httpx.MockTransport(handler)).download("https://example.org/file", tmp_path/"out"))
    assert not (tmp_path/"out").exists()


def test_watch_deadline_cancels_active_cycle(tmp_path):
    control = control_without_thread(tmp_path)
    async def cycle(settings):
        await asyncio.sleep(60)
    control.cycle_once = cycle
    start = time.monotonic()
    asyncio.run(control.pipeline({"continuous": True}, time.time()+0.05))
    assert time.monotonic()-start < 2
    assert not control.busy
    assert control.agent.stop_requested


def test_interrupted_discovery_reuses_completed_attachments(tmp_path, monkeypatch):
    downloads = []
    cancelled = [False]
    async def request(self, path, payload=None):
        return {"/get-status": {"status": "Playing"}, "/get-categories": {"categories": [{"category_name": "misc"}]},
                "/get-tasks": {"tasks": [{"task_id": 8}]},
                "/get-task": {"task": {"task_description": "two files", "task_links": [
                    {"type": {"name": "sources"}, "url": f"https://example.org/{i}.txt"} for i in range(2)]}}}[path]
    async def download(self, url, destination):
        downloads.append(url)
        if url.endswith("1.txt") and not cancelled[0]:
            cancelled[0] = True
            raise asyncio.CancelledError
        destination.write_bytes(b"completed attachment")
    monkeypatch.setattr(Solar, "request", request)
    monkeypatch.setattr(Solar, "download", download)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(Solar(tmp_path).discover())
    asyncio.run(Solar(tmp_path).discover())
    assert downloads.count("https://example.org/0.txt") == 1
    assert downloads.count("https://example.org/1.txt") == 2
    assert "solar-8" in load(tmp_path)["challenges"]
