"""Small, same-origin challenge probes. Competition and authentication hosts are excluded."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx

from ctf.agent_worker import graph
from ctf.deep import inspect_web


def origin(url):
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Invalid challenge URL")
    return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)


async def probe(url: str, request_limit=10):
    scope = origin(url)
    host = scope[1]
    if host in {"solarctf.ru", "backend.solarctf.ru"}:
        raise ValueError("The competition platform is not a challenge target")
    addresses = await asyncio.to_thread(socket.getaddrinfo, host, scope[2], type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
        raise ValueError("Non-public target requires a separately configured lab adapter")
    findings, observations = [], []
    queue = [(url, "provided-url")]
    seen = set()
    async with httpx.AsyncClient(timeout=8, follow_redirects=False, trust_env=False) as client:
        while queue and len(seen) < min(request_limit, 10):
            target, method = queue.pop(0)
            if target in seen or origin(target) != scope:
                continue
            seen.add(target)
            await asyncio.sleep(0.5)
            try:
                async with client.stream("GET", target) as response:
                    payload = bytearray()
                    async for chunk in response.aiter_bytes():
                        payload.extend(chunk)
                        if len(payload) > 512*1024:
                            raise ValueError("Response exceeds 512 KiB")
                    observations.append({"url": target, "method": method, "status": response.status_code})
                    if 300 <= response.status_code < 400:
                        redirect = urljoin(target, response.headers.get("location", ""))
                        if origin(redirect) == scope:
                            queue.append((redirect, "same-origin-redirect"))
                        continue
                for candidate in graph(bytes(payload), smart=True)[0]:
                    findings.append({**candidate, "source": target, "method": method+" > "+candidate["method"]})
                text = payload.decode("utf-8", "replace")
                if method == "provided-url":
                    page = inspect_web(bytes(payload))
                    for relative in page["external_scripts"][:4]:
                        script = urljoin(target, relative)
                        if origin(script) == scope:
                            queue.append((script, "linked-script"))
                    parsed = urlsplit(target)
                    parameters = parse_qsl(parsed.query, keep_blank_values=True)
                    if parameters:
                        name, value = parameters[0]
                        for label, replacement in (("sql-error-probe", value+"'"), ("template-expression-probe", "{{731*977}}")):
                            query = urlencode([(name, replacement), *parameters[1:]])
                            queue.append((urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, "")), label))
                if method == "sql-error-probe" and any(marker in text.lower() for marker in ("sql syntax", "sqlite3.operationalerror", "unterminated quoted string")):
                    observations.append({"hypothesis": "SQL error exposed", "url": target, "confirmed_exploit": False})
                if method == "template-expression-probe" and "714187" in text:
                    observations.append({"hypothesis": "Template expression evaluated", "url": target, "confirmed_exploit": False})
            except (httpx.HTTPError, ValueError) as exc:
                observations.append({"url": target, "error": type(exc).__name__})
    return {"candidates": findings, "history": observations, "reason": "bounded_web_pass", "requests": len(seen)}
