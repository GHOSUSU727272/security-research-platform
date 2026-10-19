"""Loopback-only live control panel. Expose remotely only through SSH forwarding."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ctf.agent import Agent


class Control:
    def __init__(self, workspace):
        self.agent = Agent(workspace)
        self.workspace = workspace
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.future = None
        self.busy = False
        self.login_process = None
        self.login_started_at = 0.0
        self.lock = threading.Lock()
        self.cycle = 0
        self.next_check = None
        self.state = "idle"
        saved = self.agent.store.meta("watch_intent") or {}
        if saved.get("active") and saved.get("until", 0) > time.time():
            self.start(saved["settings"], until=saved["until"])

    async def cycle_once(self, settings):
        try:
            if settings.get("solar", True):
                from ctf.solar import Solar
                try:
                    async with asyncio.timeout(90):
                        platform = await Solar(self.workspace).discover()
                except Exception as exc:
                    platform = {"status": "needs_attention", "message": str(exc)[:300]}
                self.agent.store.meta("platform", platform)
            await self.agent.run(mode=settings.get("mode", "balanced"),
                                 workers=int(settings.get("workers", 2)), budget=int(settings.get("budget", 180)),
                                 include_local=settings.get("include_local", False),
                                 incremental=settings.get("continuous", False))
            if settings.get("submit", False):
                from ctf.challenges import load
                from ctf.solar import Solar
                solar = Solar(self.workspace)
                registry = load(self.workspace)["challenges"]
                for item in self.agent.store.snapshot()["challenges"]:
                    original = registry.get(item["id"], {})
                    platform_id = original.get("platform_id")
                    if (type(platform_id) is not int or item["id"] != f"solar-{platform_id}"
                            or original.get("platform_solved") or self.agent.stop_requested):
                        continue
                    for candidate in item.get("candidates", []):
                        if candidate.get("confidence") in ("heuristic", "unverified_generated_solution"):
                            candidate["submission"] = {"status": "manual_review_required"}
                            continue
                        try:
                            result = await solar.submit(candidate["flag"], enabled=True)
                            candidate["submission"] = result
                            if result["verified"]:
                                candidate.update(verified=True, confidence="platform_accepted")
                                item.update(status="verified", reason="platform_accepted")
                                break
                        except Exception as exc:
                            candidate["submission"] = {"error": str(exc)[:300]}
                    self.agent.store.put(item["id"], item)
        except asyncio.CancelledError:
            self.agent.stop()
        except Exception as exc:
            self.agent.store.meta("last_error", f"{type(exc).__name__}: {exc}")

    async def pipeline(self, settings, until=None):
        until = until or time.time()+86400
        failures = 0
        try:
            while True:
                if settings.get("continuous") and time.time() >= until:
                    break
                self.state = "analyzing"
                self.next_check = None
                self.cycle += 1
                try:
                    if settings.get("continuous"):
                        async with asyncio.timeout(max(0.01, until-time.time())):
                            await self.cycle_once(settings)
                    else:
                        await self.cycle_once(settings)
                except TimeoutError:
                    self.agent.stop()
                    break
                platform = self.agent.store.meta("platform") or {}
                failed = platform.get("status") == "needs_attention" or bool(self.agent.store.meta("last_error"))
                failures = min(failures+1, 4) if failed else 0
                if (self.agent.stop_requested or not settings.get("continuous")
                        or time.time() >= until or platform.get("status") == "Finished"):
                    break
                interval = min(900, int(settings.get("interval", 120)) * 2**failures)
                self.next_check = min(time.time()+interval, until)
                self.state = "retrying" if failed else "waiting"
                await asyncio.sleep(max(0, self.next_check-time.time()))
        except asyncio.CancelledError:
            self.agent.stop()
        finally:
            self.agent.store.meta("watch_intent", {"active": False})
            self.next_check = None
            self.state = "idle"
            self.busy = False

    def start(self, settings, until=None):
        with self.lock:
            if self.busy:
                raise ValueError("Работа уже идёт")
            # Validate before launching or contacting the platform.
            if settings.get("mode", "balanced") not in ("fast", "balanced", "deep"):
                raise ValueError("Unknown mode")
            if not 1 <= int(settings.get("workers", 2)) <= 4 or not 5 <= int(settings.get("budget", 180)) <= 600:
                raise ValueError("Параллельность 1–4; бюджет 5–600 секунд")
            if not 30 <= int(settings.get("interval", 120)) <= 900:
                raise ValueError("Интервал проверки: 30–900 секунд")
            if settings.get("continuous") and not settings.get("solar", True):
                raise ValueError("Длительный режим требует подключения SolarCTF")
            until = until or time.time()+24*60*60
            self.agent.stop_requested = False
            self.agent.store.meta("last_error", "")
            self.agent.store.meta("watch_intent", {"active": bool(settings.get("continuous")),
                                                   "until": until, "settings": settings})
            self.busy = True
            self.future = asyncio.run_coroutine_threadsafe(self.pipeline(settings, until), self.loop)

    def stop(self):
        self.agent.store.meta("watch_intent", {"active": False})
        self.loop.call_soon_threadsafe(self.agent.stop)
        if self.future:
            self.future.cancel()

    def login(self):
        with self.lock:
            if self.login_process and self.login_process.poll() is None:
                return
            env = {**os.environ, "DISPLAY": ":0", "XAUTHORITY": str(Path.home()/".Xauthority")}
            self.login_started_at = time.time()
            self.login_process = subprocess.Popen([sys.executable, "-m", "ctf.solar", str(self.workspace)],
                 env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


def serve(workspace: Path, port=8765):
    control = Control(workspace)
    csrf = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, data, status=200, content_type="application/json; charset=utf-8"):
            raw = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(raw)

        def valid_host(self):
            return self.headers.get("Host", "") in {f"127.0.0.1:{port}", f"localhost:{port}"}

        def do_GET(self):
            if not self.valid_host():
                return self.send({"error": "Host rejected"}, 403)
            if self.path == "/":
                page = Path(__file__).with_name("panel.html").read_text(encoding="utf-8").replace("__CSRF__", csrf)
                return self.send(page.encode(), content_type="text/html; charset=utf-8")
            if self.path in ("/api/state", "/api/report"):
                state = control.agent.store.snapshot()
                state["running"] = control.busy
                state["controller"] = {"state": control.state, "cycle": control.cycle,
                                       "next_check": control.next_check,
                                       "intent": control.agent.store.meta("watch_intent")}
                state["llm_configured"] = bool(os.environ.get("CTF_LLM_URL") and os.environ.get("CTF_LLM_MODEL"))
                state["error"] = control.agent.store.meta("last_error")
                state["session_ready"] = (workspace/"solar-session.json").exists()
                session_file = workspace / "solar-session.json"
                session_refreshed = session_file.exists() and session_file.stat().st_mtime >= control.login_started_at
                if control.login_process and control.login_process.poll() not in (None, 0) and not session_refreshed:
                    state["error"] = "Вход не завершён. Войдите на рабочий стол Kali под anonim и снова нажмите «Войти в SolarCTF»."
                if self.path == "/api/state":
                    # Polling must not transfer disassembly and generated scripts every two seconds.
                    for item in state["challenges"]:
                        item["attempts"] = [{k: a[k] for k in ("phase", "cached", "reason", "elapsed", "error",
                                                              "cpu_seconds", "max_rss_kib", "hypothesis", "requests") if k in a}
                                            for a in item.get("attempts", [])]
                return self.send(state)
            if self.path == "/api/benchmark":
                report = workspace/"benchmark-report.json"
                if report.exists():
                    return self.send(report.read_bytes())
                return self.send({"error": "Benchmark has not run"}, 404)
            return self.send({"error": "Not found"}, 404)

        def do_POST(self):
            if not self.valid_host() or self.headers.get("X-Control-Token") != csrf:
                return self.send({"error": "Forbidden"}, 403)
            try:
                length = int(self.headers.get("Content-Length", 0))
                if not 0 <= length <= 4096:
                    raise ValueError("Request too large")
                settings = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(settings, dict):
                    raise ValueError("Settings must be an object")
                if self.path == "/api/start":
                    control.start(settings)
                elif self.path == "/api/stop":
                    control.stop()
                elif self.path == "/api/login":
                    control.login()
                else:
                    return self.send({"error": "Not found"}, 404)
                return self.send({"ok": True})
            except (ValueError, TypeError) as exc:
                return self.send({"error": str(exc)}, 400)

    print(f"CTF AutoSolver: http://127.0.0.1:{port}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


def main():
    parser = argparse.ArgumentParser(description="Local CTF AutoSolver panel")
    parser.add_argument("--workspace", type=Path, default=Path.home()/"ctf-workspace")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    serve(args.workspace.resolve(), args.port)


if __name__ == "__main__":
    main()
