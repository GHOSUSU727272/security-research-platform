"""Bounded, offline CTF candidate solvers. Never executes challenge code.

A candidate flag is NOT proof of a correct solution; humans must verify it.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import html
import json
import math
import re
import urllib.parse
from collections import deque
from pathlib import Path
from typing import Any

from ctf.triage import FLAG_PATTERN

MAX_INPUT = 2 * 1024 * 1024
MAX_NODES = 120
MAX_DEPTH = 3
MAX_TOKEN = 32768
BASE64 = re.compile(rb"(?<![a-zA-Z0-9_+/=-])[a-zA-Z0-9_+/-]{12,}={0,2}(?![a-zA-Z0-9_+/=-])")
HEX = re.compile(rb"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){6,}(?![0-9a-fA-F])")
PERCENT = re.compile(rb"(?:%[0-9a-fA-F]{2}){3,}(?:[%a-zA-Z0-9_-]*)")
CHARSETS = (b"flag{", b"ctf{", b"solarctf{", b"solar{")

def _flags(data: bytes, flag_pattern: re.Pattern[bytes]) -> list[str]:
    return sorted({m.group().decode("ascii", "replace") for m in flag_pattern.finditer(data)})

def _caesar(data: bytes, shift: int) -> bytes:
    def letter(value: int) -> int:
        if 65 <= value <= 90:
            return 65 + (value - 65 + shift) % 26
        if 97 <= value <= 122:
            return 97 + (value - 97 + shift) % 26
        return value
    return data.translate(bytes.maketrans(bytes(range(256)), bytes(letter(i) for i in range(256))))

def _atbash(data: bytes) -> bytes:
    def letter(value: int) -> int:
        if 65 <= value <= 90:
            return 90 - (value - 65)
        if 97 <= value <= 122:
            return 122 - (value - 97)
        return value
    return data.translate(bytes.maketrans(bytes(range(256)), bytes(letter(i) for i in range(256))))

def _decodings(data: bytes) -> list[tuple[str, bytes]]:
    results: list[tuple[str, bytes]] = []
    for match in BASE64.finditer(data):
        token = match.group()
        if len(token) > MAX_TOKEN or len(token) % 4 == 1:
            continue
        for name, transform in (("base64", base64.b64decode), ("base64url", base64.urlsafe_b64decode)):
            try:
                decoded = transform(token + b"=" * (-len(token) % 4))
                if decoded and decoded != token:
                    results.append((name, decoded))
            except (ValueError, binascii.Error):
                continue
    for match in HEX.finditer(data):
        token = match.group()
        if len(token) <= MAX_TOKEN:
            try:
                results.append(("hex", bytes.fromhex(token.decode("ascii"))))
            except ValueError:
                pass
    for match in PERCENT.finditer(data):
        token = match.group()
        if len(token) <= MAX_TOKEN:
            decoded = urllib.parse.unquote_to_bytes(token.decode("ascii", "replace"))
            if decoded != token:
                results.append(("url-percent", decoded))
    if len(data) <= MAX_TOKEN:
        text = data.decode("utf-8", "replace")
        entity = html.unescape(text).encode()
        if entity != data:
            results.append(("html-entities", entity))
        for shift in range(1, 26):
            results.append((f"caesar({shift})", _caesar(data, shift)))
        results.append(("atbash", _atbash(data)))
        # Known-plaintext XOR is only applied to small blobs to bound the search.
        if 5 <= len(data) <= 4096:
            for prefix in CHARSETS:
                if len(data) < len(prefix):
                    continue
                for offset in range(min(64, len(data) - len(prefix) + 1)):
                    key = data[offset] ^ prefix[0]
                    if all(data[offset + i] ^ key == b for i, b in enumerate(prefix)):
                        decoded = bytes(v ^ key for v in data)
                        results.append((f"single-byte-xor(0x{key:02x})", decoded))
    return results

def _rsa_small(data: bytes) -> list[tuple[str, bytes]]:
    text = data[:MAX_TOKEN].decode("ascii", "ignore")
    params = {}
    for key in ("n", "e", "c"):
        match = re.search(rf"(?im)^\s*{key}\s*[:=]\s*(\d+)\s*$", text)
        if match is None:
            return []
        params[key] = int(match.group(1))
    n, e, c = params["n"], params["e"], params["c"]
    if not 3 <= n <= 10**18 or not 1 < e < n or not 0 <= c < n:
        return []
    p = 0
    if n % 2 == 0:
        p = 2
    else:
        for trial in range(3, min(math.isqrt(n), 2000001) + 1, 2):
            if n % trial == 0:
                p = trial
                break
    if p == 0:
        return []
    q = n // p
    if p == q:
        phi = p * (p - 1)
    else:
        phi = (p - 1) * (q - 1)
    try:
        d = pow(e, -1, phi)
    except ValueError:
        return []
    integer = pow(c, d, n)
    decoded = integer.to_bytes(max(1, (integer.bit_length() + 7) // 8), "big")
    return [("rsa-small-factor", decoded)]

def solve_bytes(
    data: bytes, *, category: str = "unknown", flag_pattern: re.Pattern[bytes] = FLAG_PATTERN,
) -> dict[str, Any]:
    """Find concrete flag candidates with reproducible transformation paths."""
    payload = data[:MAX_INPUT]
    queue: deque[tuple[bytes, tuple[str, ...]]] = deque([(payload, ())])
    seen: set[bytes] = {payload}
    found: dict[str, dict[str, Any]] = {}
    visited = 0
    while queue and visited < MAX_NODES:
        value, steps = queue.popleft()
        visited += 1
        for flag in _flags(value, flag_pattern):
            candidate = {"flag": flag, "steps": list(steps),
                         "confidence": "candidate_only"}
            if flag not in found or len(steps) < len(found[flag]["steps"]):
                found[flag] = candidate
        if len(steps) >= MAX_DEPTH:
            continue
        transforms = _decodings(value)
        if category == "crypto" and not steps:
            transforms += _rsa_small(value)
        for name, transformed in transforms:
            if not transformed or len(transformed) > MAX_INPUT or transformed in seen:
                continue
            if len(seen) >= MAX_NODES:
                break
            seen.add(transformed)
            queue.append((transformed, (*steps, name)))
    return {"solver": "offline-transform-v1",
            "candidates": sorted(found.values(), key=lambda item: (len(item["steps"]), item["flag"])),
            "nodes_examined": visited, "truncated_input": len(data) > MAX_INPUT,
            "limits_reached": bool(queue)}

def main() -> None:
    parser = argparse.ArgumentParser(description="Solve simple offline CTF encodings")
    parser.add_argument("file", type=Path)
    parser.add_argument("--category", default="unknown")
    parser.add_argument("--flag-regex", help="ASCII bytes regex for this event")
    args = parser.parse_args()
    try:
        pattern = re.compile(args.flag_regex.encode("ascii")) if args.flag_regex else FLAG_PATTERN
        with args.file.open("rb") as stream:
            result = solve_bytes(stream.read(MAX_INPUT + 1), category=args.category,
                                 flag_pattern=pattern)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (OSError, ValueError, re.error) as exc:
        parser.error(str(exc))

if __name__ == "__main__":
    main()
