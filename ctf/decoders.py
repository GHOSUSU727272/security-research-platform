"""Bounded, offline decoding suggestions for CTF text artifacts."""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any

from ctf.triage import FLAG_PATTERN

MAX_INPUT = 2 * 1024 * 1024
BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/=])")
HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){6,}(?![0-9a-fA-F])")
PERCENT = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")

def decode_candidates(data: bytes, max_candidates: int = 150) -> list[dict[str, Any]]:
    """Try one decoding layer only; never evaluate or execute decoded text."""
    text = data[:MAX_INPUT].decode("utf-8", errors="replace")
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, raw: str, decoded: bytes) -> None:
        if len(candidates) >= max_candidates or len(decoded) > MAX_INPUT:
            return
        matches = [m.group().decode("ascii", errors="replace")
                   for m in FLAG_PATTERN.finditer(decoded)]
        if not matches:
            return
        key = (kind, raw)
        if key not in seen:
            seen.add(key)
            candidates.append({"encoding": kind, "source_excerpt": raw[:120],
                               "candidate_flags": sorted(set(matches))})

    for match in BASE64.finditer(text):
        if len(candidates) >= max_candidates:
            break
        value = match.group()
        if len(value) % 4 == 1:
            continue
        try:
            decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
        except (ValueError, binascii.Error):
            continue
        add("base64", value, decoded)
    for match in HEX.finditer(text):
        if len(candidates) >= max_candidates:
            break
        try:
            add("hex", match.group(), bytes.fromhex(match.group()))
        except ValueError:
            continue
    for match in PERCENT.finditer(text):
        if len(candidates) >= max_candidates:
            break
        value = match.group()
        add("url-percent", value, urllib.parse.unquote_to_bytes(value))
    return candidates

def main() -> None:
    parser = argparse.ArgumentParser(description="Offline CTF encoding hints")
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    try:
        with args.file.open("rb") as source:
            print(json.dumps(decode_candidates(source.read(MAX_INPUT)), indent=2))
    except OSError as exc:
        parser.error(str(exc))

if __name__ == "__main__":
    main()
