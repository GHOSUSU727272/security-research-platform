"""Deterministic, bounded CTF solvers for common *offline* challenge patterns.

Never executes challenge code, makes outbound requests, or submits flags.
A matched flag is a candidate, not proof of organizer acceptance.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import html
import json
import math
import re
import stat
import urllib.parse
import zipfile
import zlib
from pathlib import Path
from typing import Any

from ctf.decoders import BASE64, HEX, PERCENT
from ctf.triage import FLAG_PATTERN

MAX_FILE = 512 * 1024
MAX_XOR = 256 * 1024
MAX_FINDINGS = 40
MAX_TOKENS = 200
MAX_DEPTH = 3
MAX_ZIP_ENTRIES = 200
MAX_ZIP_OUTPUT = 2 * 1024 * 1024
FLAG_BYTES = 200
JS_CHARCODE = re.compile(r"String\.fromCharCode\(\s*([\d,\s]{1,1500})\)", re.I)
JS_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})")
RSA_NUMBER = re.compile(r"(?im)^\s*(p|q|n|e|c)\s*[:=]\s*(\d{1,2500})\s*[,;]?\s*$")


def flags(data: bytes) -> list[str]:
    return sorted({m.group().decode("ascii") for m in FLAG_PATTERN.finditer(data)})


def _rot(data: bytes, amount: int) -> bytes:
    lower = bytes((i + amount) % 26 + 97 for i in range(26))
    upper = bytes((i + amount) % 26 + 65 for i in range(26))
    table = bytearray(range(256))
    for idx, char in enumerate(lower):
        table[97 + idx] = char
    for idx, char in enumerate(upper):
        table[65 + idx] = char
    return data.translate(bytes(table))


def _xor(data: bytes, key: int) -> bytes:
    return data.translate(bytes(i ^ key for i in range(256)))


def _encoded_tokens(data: bytes) -> list[tuple[str, bytes]]:
    text = data.decode("latin-1")
    result: list[tuple[str, bytes]] = []
    for match in BASE64.finditer(text):
        token = match.group()
        if len(token) > 16000 or len(token) % 4 == 1:
            continue
        try:
            result.append(("base64", base64.b64decode(token + "=" * (-len(token) % 4), validate=True)))
        except (ValueError, binascii.Error):
            pass
        if len(result) >= MAX_TOKENS:
            return result
    for match in HEX.finditer(text):
        token = match.group()
        if len(token) > 16000:
            continue
        try:
            result.append(("hex", bytes.fromhex(token)))
        except ValueError:
            pass
        if len(result) >= MAX_TOKENS:
            return result
    for match in PERCENT.finditer(text):
        token = match.group()
        if len(token) > 16000:
            continue
        result.append(("url-percent", urllib.parse.unquote_to_bytes(token)))
        if len(result) >= MAX_TOKENS:
            return result
    return result


def _rsa_plaintext(data: bytes) -> bytes | None:
    """Decrypt textbook RSA when p/q are supplied, or n is tiny enough to factor."""
    raw = {match.group(1).lower(): int(match.group(2)) for match in RSA_NUMBER.finditer(
        data[:8192].decode("ascii", errors="ignore")
    )}
    if not {"e", "c"}.issubset(raw):
        return None
    p, q = raw.get("p"), raw.get("q")
    n = raw.get("n")
    if p is None or q is None:
        if n is None or n <= 3 or n > 10**10:
            return None
        if n % 2 == 0:
            p, q = 2, n // 2
        else:
            p, q = None, None
            for candidate in range(3, math.isqrt(n) + 1, 2):
                if n % candidate == 0:
                    p, q = candidate, n // candidate
                    break
        if p is None or q is None:
            return None
    computed_n = p * q
    if n is not None and computed_n != n:
        return None
    n = computed_n
    if not 3 < n.bit_length() <= 8192:
        return None
    e, c = raw["e"], raw["c"]
    if not (1 < e < n and 0 <= c < n):
        return None
    try:
        d = pow(e, -1, (p - 1) * (q - 1))
    except ValueError:
        return None
    m = pow(c, d, n)
    if pow(m, e, n) != c:
        return None
    return m.to_bytes(max(1, (m.bit_length() + 7) // 8), "big")


def _png_text_chunks(data: bytes) -> list[bytes]:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return []
    found: list[bytes] = []
    pos = 8
    while pos + 12 <= len(data):
        size = int.from_bytes(data[pos:pos + 4], "big")
        chunk_type = data[pos + 4:pos + 8]
        if size > MAX_FILE or pos + 12 + size > len(data):
            break
        contents = data[pos + 8:pos + 8 + size]
        if chunk_type in (b"tEXt", b"iTXt"):
            found.append(contents)
        elif chunk_type == b"zTXt":
            keyword, separator, compressed = contents.partition(b"\x00")
            if (separator and len(keyword) <= 79 and len(compressed) >= 2
                    and compressed[0] == 0):
                try:
                    inflater = zlib.decompressobj()
                    recovered = inflater.decompress(compressed[1:], MAX_FILE)
                    if inflater.eof and len(recovered) < MAX_FILE:
                        found.append(keyword + b" " + recovered)
                except zlib.error:
                    pass
        pos += 12 + size
        if chunk_type == b"IEND":
            break
    return found


def solve_bytes(data: bytes, category: str = "unknown") -> list[dict[str, Any]]:
    """Produce method-labelled candidate flags; no hidden code execution."""
    data = data[:MAX_FILE]
    findings: list[dict[str, Any]] = []
    observed: set[tuple[str, str]] = set()

    def record(method: str, sample: bytes, evidence: str = "") -> None:
        for flag in flags(sample):
            if len(findings) >= MAX_FINDINGS:
                return
            key = (method, flag)
            if key not in observed:
                observed.add(key)
                findings.append({"method": method, "flag": flag, "evidence": evidence})

    record("plain", data)
    for shift in range(1, 26):
        record("caesar", _rot(data, shift), f"shift={shift}")
        if len(findings) >= MAX_FINDINGS:
            return findings
    for key in range(1, 256):
        record("xor-byte", _xor(data[:MAX_XOR], key), f"key=0x{key:02x}")
        if len(findings) >= MAX_FINDINGS:
            return findings

    # Bounded breadth-first decoding supports layered base64/hex/url encoding.
    nodes: list[tuple[str, bytes]] = [("", data[:MAX_FILE])]
    seen = {data[:MAX_FILE]}
    for _ in range(MAX_DEPTH):
        following: list[tuple[str, bytes]] = []
        for path, contents in nodes[:MAX_TOKENS]:
            for method, decoded in _encoded_tokens(contents):
                if decoded in seen or len(decoded) > MAX_FILE:
                    continue
                seen.add(decoded)
                technique = f"{path}>{method}" if path else method
                record(technique, decoded)
                following.append((technique, decoded))
                if len(findings) >= MAX_FINDINGS or len(following) >= MAX_TOKENS:
                    break
            if len(findings) >= MAX_FINDINGS or len(following) >= MAX_TOKENS:
                break
        nodes = following
        if not nodes or len(findings) >= MAX_FINDINGS:
            break

    text = data.decode("utf-8", errors="replace")
    record("html-entities", html.unescape(text).encode("utf-8"))
    record("js-escapes", JS_ESCAPE.sub(
        lambda m: chr(int(m.group(1) or m.group(2), 16)), text
    ).encode("utf-8"))
    for match in list(JS_CHARCODE.finditer(text))[:50]:
        try:
            codes = [int(n.strip()) for n in match.group(1).split(",")]
            if 1 <= len(codes) <= FLAG_BYTES and all(0 <= n <= 0x10ffff for n in codes):
                record("js-charcode", "".join(map(chr, codes)).encode("utf-8"))
        except (ValueError, UnicodeError):
            continue

    if len(data) % 2 == 0 and b"\0" in data:
        record("utf16-le", data.decode("utf-16-le", errors="ignore").encode("utf-8"))
        record("utf16-be", data.decode("utf-16-be", errors="ignore").encode("utf-8"))

    plaintext = _rsa_plaintext(data)
    if plaintext is not None:
        record("textbook-rsa", plaintext, "RSA modular inverse and encryption verification")

    for chunk in _png_text_chunks(data):
        record("png-text", chunk)
    return findings


def solve_file(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        return []
    if path.suffix.lower() != ".zip":
        with path.open("rb") as source:
            return solve_bytes(source.read(MAX_FILE))
    findings: list[dict[str, Any]] = []
    with zipfile.ZipFile(path) as archive:
        if len(archive.infolist()) > MAX_ZIP_ENTRIES:
            return []
        remaining = MAX_ZIP_OUTPUT
        for item in archive.infolist():
            name = item.filename
            parts = name.replace("\\", "/").split("/")
            unsafe = (name.startswith(("/", "\\")) or ".." in parts
                      or ":" in parts[0] or
                      stat.S_ISLNK((item.external_attr >> 16) & 0xFFFF))
            if (unsafe or item.is_dir() or item.flag_bits & 1
                    or item.file_size > MAX_FILE
                    or item.file_size > remaining
                    or item.file_size / max(item.compress_size, 1) > 100):
                continue
            with archive.open(item) as stream:
                content = stream.read(MAX_FILE + 1)
            if len(content) > MAX_FILE:
                continue
            remaining -= len(content)
            for finding in solve_bytes(content):
                finding["evidence"] = f"zip-entry={name}; {finding['evidence']}"
                findings.append(finding)
                if len(findings) >= MAX_FINDINGS:
                    return findings
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Bounded, offline CTF auto-solvers")
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(solve_file(args.path), ensure_ascii=False, indent=2))
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
