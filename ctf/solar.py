"""SolarCTF adapter derived from first-party main.d9059984.js on 2026-10-16.

Only documented-by-frontend operations are used. No platform probing.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import socket
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from ctf.challenges import load, save

FRONTEND = "https://solarctf.ru"
BACKEND = "https://backend.solarctf.ru"


class Solar:
    def __init__(self, workspace: Path, transport=None):
        self.workspace = workspace
        self.session = workspace / "solar-session.json"
        self.transport = transport
        self.last_request = 0.0
        self.requests = 0

    def token(self):
        if not self.session.exists():
            raise ValueError("Нужна авторизация SolarCTF: нажмите «Войти» в панели")
        data = json.loads(self.session.read_text())
        for cookie in data.get("cookies", []):
            if cookie.get("name") == "token" and cookie.get("domain", "").lstrip(".") == "solarctf.ru":
                return cookie["value"]
        raise ValueError("В сессии нет cookie token SolarCTF; войдите снова")

    async def request(self, path: str, payload=None):
        allowed = {"/get-status", "/get-categories", "/get-tasks", "/get-task", "/check-flag"}
        if path not in allowed:
            raise ValueError("Unsupported platform operation")
        self.requests += 1
        if self.requests > 200:
            raise ValueError("Platform request budget reached; resume with another run")
        await asyncio.sleep(max(0, 0.5-(time.monotonic()-self.last_request)))
        self.last_request = time.monotonic()
        async with httpx.AsyncClient(timeout=20, follow_redirects=False, transport=self.transport) as client:
            async with client.stream("GET" if payload is None else "POST", BACKEND+path,
                headers={"Authorization": "Bearer "+self.token(), "Accept-Language": "ru"}, json=payload) as response:
                response.raise_for_status()
                body = bytearray()
                async for block in response.aiter_bytes():
                    body.extend(block)
                    if len(body) > 2*1024**2:
                        raise ValueError("Platform response exceeds 2 MiB")
                result = json.loads(body)
        if not isinstance(result, dict):
            raise ValueError("Unknown platform response schema")
        if result.get("toast") == "error":
            raise ValueError(str(result.get("msg", "Platform rejected request"))[:300])
        return result

    async def download(self, url: str, destination: Path):
        async with httpx.AsyncClient(timeout=30, follow_redirects=False, transport=self.transport, trust_env=False) as client:
            for _ in range(4):
                parsed = urlparse(url)
                if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                    raise ValueError("Attachment must be a public HTTPS URL")
                addresses = await asyncio.to_thread(socket.getaddrinfo, parsed.hostname, parsed.port or 443,
                                                    type=socket.SOCK_STREAM)
                if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
                    raise ValueError("Attachment points to a non-public address")
                # Explicit organizer-linked CDN files are allowed, without the platform token.
                headers = {}
                if parsed.hostname in {"solarctf.ru", "backend.solarctf.ru"} and parsed.port in (None, 443):
                    headers["Authorization"] = "Bearer "+self.token()
                async with client.stream("GET", url, headers=headers) as response:
                    if response.is_redirect:
                        url = urljoin(url, response.headers["location"])
                        continue
                    response.raise_for_status()
                    content = bytearray()
                    async for block in response.aiter_bytes():
                        content.extend(block)
                        if len(content) > 16*1024**2:
                            raise ValueError("Attachment exceeds 16 MiB")
                temporary = destination.with_suffix(destination.suffix+".part")
                temporary.write_bytes(content)
                temporary.replace(destination)
                return
        raise ValueError("Too many attachment redirects")

    async def discover(self):
        status = (await self.request("/get-status")).get("status")
        if status != "Playing":
            return {"status": status or "unknown", "discovered": 0,
                    "message": "Ожидание старта" if status == "Not Started" else "Соревнование не активно"}
        response = await self.request("/get-categories")
        categories = response.get("categories")
        if not isinstance(categories, list):
            raise ValueError("Unknown category schema; integration needs review")
        registry = load(self.workspace)
        index_path = self.workspace / "solar-index.json"
        try:
            discovery_index = json.loads(index_path.read_text())
        except (OSError, ValueError):
            discovery_index = {}

        def persist_index():
            pending = index_path.with_suffix(".tmp")
            pending.write_text(json.dumps(discovery_index))
            pending.replace(index_path)

        count, warnings = 0, []
        for category in categories[:30]:
            category_name = category["category_name"]
            tasks = (await self.request("/get-tasks", {"category_name": category_name})).get("tasks")
            if not isinstance(tasks, list):
                raise ValueError("Unknown task-list schema")
            for brief in tasks[:100]:
                identifier = int(brief["task_id"])
                slug = f"solar-{identifier}"
                if time.time()-discovery_index.get(slug, 0) < 600 and slug in registry["challenges"]:
                    count += 1
                    continue
                detail = (await self.request("/get-task", {"task_id": identifier})).get("task")
                if not isinstance(detail, dict):
                    raise ValueError("Unknown task-detail schema")
                folder = self.workspace / "solar-inputs" / slug
                folder.mkdir(parents=True, exist_ok=True)
                description = detail.get("task_description", "")
                (folder / "description.html").write_text(description, encoding="utf-8")
                links = detail.get("task_links", [])
                scope = []
                task_warnings = []
                active_files = set()
                for link_index, link in enumerate(links[:30]):
                    kind = link.get("type", {}).get("name")
                    url = link.get("url", "")
                    if kind == "sources":
                        extension = Path(urlparse(url).path).suffix[:12]
                        if not re.fullmatch(r"\.[A-Za-z0-9]+", extension):
                            extension = ".bin"
                        dest = folder / f"attachment-{link_index}{extension}"
                        active_files.add(dest.name)
                        cache_key = f"{slug}/{dest.name}/"+hashlib.sha256(url.encode()).hexdigest()
                        try:
                            if not dest.exists() or time.time()-discovery_index.get(cache_key, 0) >= 600:
                                await self.download(url, dest)
                                discovery_index[cache_key] = time.time()
                                persist_index()
                        except (ValueError, OSError, httpx.HTTPError) as exc:
                            warning = {"task": slug, "error": str(exc)[:300]}
                            warnings.append(warning)
                            task_warnings.append(warning)
                    else:
                        scope.append({"type": kind, "url": url})
                normalized = category_name.lower()
                if "rev" in normalized:
                    normalized = "reverse"
                if "steg" in normalized:
                    normalized = "forensics"
                registry["challenges"][slug] = {
                    "id": slug, "source": str(folder.resolve()), "category": normalized,
                    "name": detail.get("task_name", slug), "difficulty": detail.get("task_level"),
                    "platform_id": identifier, "platform_solved": bool(detail.get("task_solved")),
                    "scope": scope, "status": "new", "candidate_count": 0,
                    "warnings": task_warnings,
                }
                for old_file in folder.glob("attachment-*"):
                    if old_file.name not in active_files and old_file.is_file() and not old_file.is_symlink():
                        old_file.unlink()
                if not task_warnings:
                    discovery_index[slug] = time.time()
                count += 1
                save(self.workspace, registry)
                persist_index()
        save(self.workspace, registry)
        return {"status": status, "discovered": count, "warnings": warnings}

    async def submit(self, flag: str, enabled: bool):
        if not enabled:
            raise ValueError("Automatic submission is disabled")
        if not re.fullmatch(r"SOLARCTF\{[A-Za-z0-9_]{1,160}\}", flag):
            raise ValueError("Not a SolarCTF flag")
        from ctf.agent import Store
        store = Store(self.workspace)
        key = "submission:"+hashlib.sha256(flag.encode()).hexdigest()
        existing = store.meta(key)
        if existing:
            return existing
        if (await self.request("/get-status")).get("status") != "Playing":
            raise ValueError("Competition is not active")
        # Persist before sending: an uncertain network response must not cause a duplicate.
        store.meta(key, {"status": "unknown", "verified": False, "reason": "submission_started"})
        response = await self.request("/check-flag", {"flag": flag})
        result = {"status": response.get("toast"), "verified": response.get("toast") == "success",
                  "message": response.get("msg", "")}
        store.meta(key, result)
        return result


async def login(workspace: Path):
    from playwright.async_api import async_playwright
    workspace.mkdir(parents=True, exist_ok=True)
    profile = workspace / "solar-browser"
    profile.mkdir(exist_ok=True, mode=0o700)
    async with async_playwright() as p:
        import shutil
        executable = shutil.which("chromium")
        context = await p.chromium.launch_persistent_context(str(profile), headless=False,
                    executable_path=executable, chromium_sandbox=True, args=["--no-first-run"])
        try:
            page = context.pages[0] if context.pages else await context.new_page()
            await page.goto(FRONTEND+"/team/690", wait_until="domcontentloaded", timeout=45000)
            for _ in range(600):
                cookies = await context.cookies(FRONTEND)
                if any(c["name"] == "token" for c in cookies):
                    state = await context.storage_state()
                    dest = workspace / "solar-session.json"
                    descriptor = os.open(dest, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
                    with os.fdopen(descriptor, "w") as stream:
                        json.dump(state, stream)
                    dest.chmod(0o600)
                    return
                await asyncio.sleep(1)
            raise ValueError("Authorization timed out")
        finally:
            await context.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("workspace", type=Path)
    args = parser.parse_args()
    asyncio.run(login(args.workspace))
