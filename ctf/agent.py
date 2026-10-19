"""Durable async orchestration over existing CTF solvers with hard process boundaries."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

from ctf.agent_worker import artifacts
from ctf.challenges import load

VERSION = "agent-2.1"
MODES = {"fast": (30, 0, 0), "balanced": (20, 120, 0), "deep": (20, 120, 360)}


class Store:
    def __init__(self, workspace: Path):
        self.workspace = workspace.resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.path = self.workspace / "autosolver.sqlite3"
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS attempts (
                    signature TEXT, phase TEXT, budget INTEGER, result TEXT,
                    PRIMARY KEY(signature,phase,budget));
                CREATE TABLE IF NOT EXISTS current (id TEXT PRIMARY KEY, data TEXT);
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
            """)
        self.path.chmod(0o600)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.execute("PRAGMA journal_mode=WAL")
        return db

    def put(self, identifier: str, item: dict):
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO current VALUES (?,?)", (identifier, json.dumps(item)))

    def meta(self, key: str, value=None):
        with self.connect() as db:
            if value is not None:
                db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, json.dumps(value)))
            row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def cached(self, signature, phase, budget):
        with self.connect() as db:
            row = db.execute("SELECT result FROM attempts WHERE signature=? AND phase=? ORDER BY budget DESC LIMIT 1",
                             (signature, phase)).fetchone()
        return json.loads(row[0]) if row else None

    def cache(self, signature, phase, budget, result):
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO attempts VALUES (?,?,?,?)",
                       (signature, phase, budget, json.dumps(result)))

    def snapshot(self):
        with self.connect() as db:
            items = [json.loads(r[0]) for r in db.execute("SELECT data FROM current ORDER BY id")]
        return {"running": bool(self.meta("running")), "platform": self.meta("platform"),
                "challenges": items, "discovered": len(items),
                "solved": sum(i.get("status") == "verified" for i in items),
                "candidates": sum(len(i.get("candidates", [])) for i in items)}


def signature(source: Path, item: dict) -> str:
    stable = {k: item.get(k) for k in ("category", "scope", "platform_id", "description")}
    stable["llm"] = [os.environ.get("CTF_LLM_MODEL"), bool(os.environ.get("CTF_LLM_URL"))]
    digest = hashlib.sha256((VERSION+json.dumps(stable, sort_keys=True)).encode())
    for label, data in artifacts(source):
        digest.update(label.encode())
        digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest()


def sandbox_command(source: Path, job: Path):
    root = Path(__file__).resolve().parent.parent
    venv = Path(sys.prefix)
    args = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/etc"]
    for name in ("/usr", "/bin", "/lib", "/lib64", "/etc/ld.so.cache", "/etc/fonts", "/etc/java-21-openjdk"):
        if Path(name).exists():
            args += ["--ro-bind", name, name]
    args += ["--ro-bind", str(root / "ctf"), str(root / "ctf"),
             "--ro-bind", str(venv), str(venv),
             "--ro-bind", str(source), "/input", "--bind", str(job), "/job",
             "--chdir", str(root), "--clearenv", "--setenv", "PATH", "/usr/bin:/bin",
             "--setenv", "HOME", "/tmp", "--setenv", "LANG", "C.UTF-8",
             "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
             "--", str(Path(sys.executable)), "-m", "ctf.agent_worker", "/job/request.json"]
    return args


async def run_phase(source: Path, phase: str, budget: int, memory_mb: int, scratch: Path, script=None):
    with tempfile.TemporaryDirectory(dir=scratch) as directory:
        job = Path(directory)
        (job / "request.json").write_text(json.dumps({"phase": phase, "budget": budget, "memory_mb": memory_mb}))
        if script:
            (job / "solver.py").write_text(script, encoding="utf-8")
        with (job / "stderr.txt").open("wb") as errors:
            launch = asyncio.create_task(asyncio.create_subprocess_exec(*sandbox_command(source, job),
                stdout=asyncio.subprocess.DEVNULL, stderr=errors, start_new_session=True))
            interrupted = False
            try:
                process = await asyncio.shield(launch)
            except asyncio.CancelledError:
                process = await launch
                interrupted = True
            try:
                if interrupted:
                    raise asyncio.CancelledError
                await asyncio.wait_for(process.wait(), budget+2)
                output = job / "result.json"
                if process.returncode != 0 or not output.exists():
                    message = (job / "stderr.txt").read_bytes()[:2000].decode("utf-8", "replace")
                    if output.exists() and output.stat().st_size <= 16*1024**2:
                        try:
                            partial = json.loads(output.read_text())
                            partial.update(reason="worker_error_partial", error=message)
                            return partial
                        except (OSError, ValueError):
                            pass
                    return {"reason": "worker_error", "error": message, "candidates": []}
                if output.stat().st_size > 16*1024**2:
                    return {"reason": "output_limit", "candidates": []}
                return json.loads(output.read_text())
            except TimeoutError:
                output = job / "result.json"
                if output.exists() and output.stat().st_size <= 16*1024**2:
                    try:
                        partial = json.loads(output.read_text())
                        partial["reason"] = "timeout_partial"
                        return partial
                    except (ValueError, OSError):
                        pass
                return {"reason": "timeout", "candidates": [], "elapsed": budget}
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()


class Agent:
    def __init__(self, workspace: Path):
        self.store = Store(workspace)
        self.stop_requested = False
        self.tasks = []
        self.store.meta("running", False)
        for item in self.store.snapshot()["challenges"]:
            if item.get("status") in ("running", "queued"):
                item.update(status="interrupted", reason="service_restarted")
                self.store.put(item["id"], item)

    async def run(self, mode="balanced", workers=2, budget=180, memory_mb=768, include_local=True, incremental=False):
        if mode not in MODES or not 1 <= workers <= 4 or not 5 <= budget <= 600 or not 256 <= memory_mb <= 1024:
            raise ValueError("Invalid mode/resources: workers 1–4, seconds 5–600, memory 256–1024 MiB")
        if self.store.meta("running"):
            raise ValueError("Already running")
        self.stop_requested = False
        self.store.meta("running", True)
        self.store.meta("last_error", "")
        scratch = self.store.workspace / "agent-work"
        scratch.mkdir(exist_ok=True)
        semaphore = asyncio.Semaphore(workers)
        previous = {i["id"]: i for i in self.store.snapshot()["challenges"]}

        async def solve(identifier, original):
            item = {"id": identifier, "category": original.get("category", "unknown"),
                    "name": original.get("name", identifier), "platform_id": original.get("platform_id"),
                    "warnings": original.get("warnings", []),
                    "status": "queued", "candidates": [], "attempts": [], "elapsed": 0,
                    "mode": mode, "budget": budget, "updated_at": time.time()}
            self.store.put(identifier, item)
            async with semaphore:
                if original.get("platform_solved"):
                    item.update(status="verified", reason="platform_already_solved")
                    self.store.put(identifier, item)
                    return
                if self.stop_requested:
                    item.update(status="interrupted", reason="user_stop")
                    self.store.put(identifier, item)
                    return
                started = time.monotonic()
                try:
                    source = Path(original["source"]).resolve(strict=True)
                    if not source.is_dir():
                        raise ValueError("Input is not a directory")
                    # Hashing is bounded identically to the worker's input scan.
                    key = await asyncio.to_thread(signature, source, original)
                    item["signature"] = key
                    old = previous.get(identifier, {})
                    same = old.get("signature") == key
                    if same and old.get("status") == "verified":
                        item = old
                        return
                    if (incremental and same and old.get("mode") == mode and old.get("budget") == budget
                            and (not original.get("scope") or old.get("candidates") or time.time()-old.get("updated_at", 0) < 900)
                            and old.get("status") in ("candidates", "unsolved")):
                        item = old
                        return
                    for phase, allocation in zip(("fast", "smart", "deep"), MODES[mode]):
                        remaining = int(budget-(time.monotonic()-started))
                        if not allocation or remaining <= 0 or self.stop_requested:
                            continue
                        allowance = min(remaining, allocation)
                        item.update(status="running", phase=phase, elapsed=time.monotonic()-started)
                        self.store.put(identifier, item)
                        result = self.store.cached(key, phase, allowance)
                        cached = result is not None
                        if result is None:
                            result = await run_phase(source, phase, allowance, memory_mb, scratch)
                            if result["reason"] == "strategies_exhausted":
                                self.store.cache(key, phase, allowance, result)
                        item["attempts"].append({"phase": phase, "cached": cached, **result})
                        known = {v["flag"] for v in item["candidates"]}
                        item["candidates"].extend(v for v in result.get("candidates", []) if v["flag"] not in known)
                        item["elapsed"] = time.monotonic()-started
                        item["reason"] = result["reason"]
                        self.store.put(identifier, item)
                        if item["candidates"]:
                            item["reason"] = "candidate_found"
                            break
                    remaining = budget-(time.monotonic()-started)
                    if mode != "fast" and remaining > 2 and original.get("scope") and not item["candidates"]:
                        from ctf.web_probe import probe
                        for target in original["scope"][:2]:
                            url = target.get("url", "")
                            if not url.startswith(("https://", "http://")):
                                continue
                            try:
                                async with asyncio.timeout(max(0.1, budget-(time.monotonic()-started))):
                                    result = await probe(url)
                                item["attempts"].append({"phase": "web", **result})
                                item["candidates"].extend(result["candidates"])
                            except (ValueError, TimeoutError) as exc:
                                item["attempts"].append({"phase": "web", "error": str(exc) or "budget"})
                    remaining = budget-(time.monotonic()-started)
                    if mode == "deep" and remaining > 5 and not item["candidates"]:
                        from ctf.llm import propose
                        description = "\n".join(data[:3000].decode("utf-8", "replace") for _, data in list(artifacts(source))[:3])
                        try:
                            async with asyncio.timeout(max(0.1, remaining)):
                                for _ in range(3):
                                    if budget-(time.monotonic()-started) < 5 or item["candidates"]:
                                        break
                                    proposal = await propose(description, json.dumps(item["attempts"])[-6000:])
                                    if not proposal:
                                        item["attempts"].append({"phase": "llm", "reason": "not_configured"})
                                        break
                                    if not proposal["python"] or any(a.get("script") == proposal["python"] for a in item["attempts"]):
                                        break
                                    allowance = max(1, int(budget-(time.monotonic()-started)))
                                    result = await run_phase(source, "llm", min(30, allowance), memory_mb, scratch, proposal["python"])
                                    item["attempts"].append({"phase": "llm", "hypothesis": proposal["hypothesis"],
                                                             "script": proposal["python"], **result})
                                    item["candidates"].extend(result["candidates"])
                        except Exception as exc:
                            item["attempts"].append({"phase": "llm", "error": type(exc).__name__})
                    if not item["candidates"] and any(a.get("reason") in ("worker_error", "timeout", "output_limit") for a in item["attempts"]):
                        item["reason"] = "resource_limit_or_worker_failure"
                    item["candidates"] = list({c["flag"]: c for c in item["candidates"]}.values())
                    item["status"] = "candidates" if item["candidates"] else "unsolved"
                    if self.stop_requested:
                        item.update(status="interrupted", reason="user_stop")
                except asyncio.CancelledError:
                    item.update(status="interrupted", reason="user_stop")
                except Exception as exc:
                    item.update(status="error", reason=f"{type(exc).__name__}: {exc}")
                finally:
                    if item is not previous.get(identifier):
                        item["elapsed"] = time.monotonic()-started
                        item["updated_at"] = time.time()
                    self.store.put(identifier, item)
        try:
            registry = load(self.store.workspace)["challenges"]
            if not include_local:
                registry = {k: v for k, v in registry.items()
                            if type(v.get("platform_id")) is int and k == f"solar-{v['platform_id']}"}
            ordered = sorted(registry.items(), key=lambda pair: (pair[0] in previous,
                             pair[1].get("category") not in ("crypto", "misc"), pair[0]))
            self.tasks = [asyncio.create_task(solve(identifier, item)) for identifier, item in ordered]
            await asyncio.gather(*self.tasks, return_exceptions=True)
        finally:
            for task in self.tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*self.tasks, return_exceptions=True)
            for item in self.store.snapshot()["challenges"]:
                if item.get("status") in ("running", "queued"):
                    item.update(status="interrupted", reason="user_stop")
                    self.store.put(item["id"], item)
            self.tasks = []
            self.store.meta("running", False)

    def stop(self):
        self.stop_requested = True
        for task in self.tasks:
            if not task.done():
                task.cancel()
