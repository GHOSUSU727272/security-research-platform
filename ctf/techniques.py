"""Bounded, deterministic transformations; no eval or challenge-code execution."""
from __future__ import annotations

import base64
import binascii
import math
import re


def encodings(data: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    if len(data) > 32768:
        return out
    text = data.decode("ascii", "ignore").strip()
    for token in re.findall(r"(?<![A-Z2-7])[A-Z2-7]{8,}={0,6}(?![A-Z2-7])", text)[:50]:
        try:
            out.append(("base32", base64.b32decode(token + "=" * (-len(token) % 8))))
        except (ValueError, binascii.Error):
            pass
    for name, decoder in (("base85", base64.b85decode), ("ascii85", base64.a85decode)):
        if 10 <= len(text) <= 8192 and not any(c.isspace() for c in text):
            try:
                out.append((name, decoder(text.encode())))
            except (ValueError, binascii.Error):
                pass
    for token in re.findall(r"(?<![01])(?:[01]{8}[ \t]*){4,}(?![01])", text)[:30]:
        bits = re.sub(r"\s", "", token)
        out.append(("binary", bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))))
    for token in re.findall(r"\[([\d,\s]{12,8192})\]", text)[:30]:
        try:
            out.append(("ascii-array", bytes(int(x.strip()) for x in token.split(","))))
        except ValueError:
            pass
    for token in re.findall(r"(?<![\w])\d{15,2500}(?![\w])", text)[:30]:
        number = int(token)
        out.append(("big-integer", number.to_bytes((number.bit_length() + 7) // 8, "big")))
    return out


def _root(n: int, e: int) -> int:
    low, high = 0, 1 << ((n.bit_length() + e - 1) // e)
    while low + 1 < high:
        mid = (low + high) // 2
        if mid ** e <= n:
            low = mid
        else:
            high = mid
    return high if high ** e == n else low


def crypto(data: bytes) -> list[tuple[str, bytes]]:
    text = data[:32768].decode("ascii", "ignore")
    out: list[tuple[str, bytes]] = []
    params = {k.lower(): int(v, 16 if v.lower().startswith("0x") else 10)
              for k, v in re.findall(
                  r"(?im)^\s*(n[12]?|p|q|e[12]?|c[12]?)\s*[:=]\s*(0x[0-9a-f]+|\d{1,2500})\s*[,;]?\s*$", text)}

    def add(name: str, m: int) -> None:
        if m >= 0:
            out.append((name, m.to_bytes(max(1, (m.bit_length()+7)//8), "big")))

    n, e, c = (params.get(k, 0) for k in ("n", "e", "c"))
    if 2 <= e <= 7 and c > 0:
        m = _root(c, e)
        if m ** e == c:
            add("rsa-exact-small-exponent", m)
    if n > 3 and e > 1 and 0 <= c < n:
        p, q = params.get("p", 0), params.get("q", 0)
        if p > 1 and n % p == 0:
            q = n // p
        if q > 1 and n % q == 0:
            p = n // q
        if not p:
            a = math.isqrt(n)
            a += a*a < n
            for _ in range(10000):
                b2 = a*a - n
                b = math.isqrt(b2)
                if b*b == b2:
                    p, q = a-b, a+b
                    break
                a += 1
        if p > 1 and q > 1 and p*q == n:
            phi = p*(p-1) if p == q else (p-1)*(q-1)
            try:
                m = pow(c, pow(e, -1, phi), n)
                if pow(m, e, n) == c:
                    add("rsa-known-or-fermat-factors", m)
            except ValueError:
                pass
    if all(k in params for k in ("n1", "n2", "e", "c")):
        p = math.gcd(params["n1"], params["n2"])
        n = params["n1"]
        if 1 < p < n:
            try:
                m = pow(c, pow(e, -1, (p-1)*(n//p-1)), n)
                if pow(m, e, n) == c:
                    add("rsa-shared-prime", m)
            except ValueError:
                pass
    if all(k in params for k in ("n", "e1", "e2", "c1", "c2")):
        e1, e2 = params["e1"], params["e2"]
        if n > 1 and e1 > 1 and e2 > 1 and math.gcd(e1, e2) == 1:
            a = pow(e1, -1, e2)
            b = (1-a*e1)//e2
            try:
                m = pow(params["c1"], a, n) * pow(params["c2"], b, n) % n
                if pow(m, e1, n) == params["c1"] and pow(m, e2, n) == params["c2"]:
                    add("rsa-common-modulus", m)
            except ValueError:
                pass
    # Known plaintext determines short periodic keys, without guessing whole flags.
    if 8 <= len(data) <= 4096:
        for prefix in (b"SOLARCTF{", b"solarctf{", b"crypto{", b"picoCTF{", b"flag{"):
            # At least two complete key periods must agree with independently
            # known plaintext. A key as long as the crib would force any prefix.
            for length in range(1, len(prefix)//2+1):
                key = bytes(data[i] ^ prefix[i] for i in range(length))
                if all(data[i] ^ key[i % length] == prefix[i] for i in range(len(prefix))):
                    out.append((f"xor-periodic:key={key.hex()}",
                                bytes(v ^ key[i % length] for i, v in enumerate(data))))
    # Supplied-key AES (hex fields); no brute force or invented parameters.
    fields = dict(re.findall(r"(?im)^\s*(key|iv|ciphertext)\s*[:=]\s*([0-9a-fA-F]+)\s*$", text))
    if "key" in fields and "ciphertext" in fields:
        try:
            from Crypto.Cipher import AES
            key, encrypted = bytes.fromhex(fields["key"]), bytes.fromhex(fields["ciphertext"])
            if len(key) in (16, 24, 32) and len(encrypted) % 16 == 0:
                if "iv" in fields:
                    cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(fields["iv"]))
                    method = "aes-cbc-supplied-key"
                else:
                    cipher = AES.new(key, AES.MODE_ECB)
                    method = "aes-ecb-supplied-key"
                out.append((method, cipher.decrypt(encrypted)))
        except (ImportError, ValueError):
            pass
    return out


def source_constraints(data: bytes) -> list[tuple[str, bytes]]:
    """Recover complete character-index checks from Java/JS without executing source."""
    text = data[:32768].decode("utf-8", "replace")
    matches = re.findall(r"\b(\w+)\.charAt\((\d{1,3})\)\s*={2,3}\s*['\"]([^'\"\\])['\"]", text)
    groups: dict[str, dict[int, str]] = {}
    inconsistent = set()
    for variable, index, value in matches:
        index = int(index)
        previous = groups.setdefault(variable, {}).get(index)
        if previous is not None and previous != value:
            inconsistent.add(variable)
        groups[variable][index] = value
    out = []
    for variable, chars in groups.items():
        length_match = re.search(rf"{re.escape(variable)}\.length\(\)\s*==\s*(\d{{1,3}})", text)
        if not length_match or variable in inconsistent:
            continue
        size = int(length_match.group(1))
        if not 1 <= size <= 160 or set(chars) != set(range(size)):
            continue
        recovered = "".join(chars[i] for i in range(size))
        # Wrapping only when the source explicitly strips that exact prefix.
        prefix = re.search(r'substring\("((?:picoCTF|SOLARCTF|crypto|flag)\{)"\.length\(\)', text)
        if prefix:
            recovered = prefix.group(1)+recovered+"}"
        out.append(("source-character-constraints", recovered.encode()))
    width = re.search(r"\bsplit\s*=\s*(\d{1,2})\s*;", text)
    if width:
        unit = int(width.group(1))
        slices = re.findall(r"\b(\w+)\.substring\(\s*(0|split(?:\*\d{1,2})?)\s*,\s*(split(?:\*\d{1,2})?)\s*\)\s*={2,3}\s*['\"]([^'\"\\]{1,80})['\"]", text)
        assembled = {}
        conflict = False
        for variable, start, end, value in slices:
            lower = 0 if start == "0" else unit*int(start.split("*")[1] if "*" in start else 1)
            upper = unit*int(end.split("*")[1] if "*" in end else 1)
            if not 0 <= lower < upper <= 200 or len(value) > upper-lower:
                continue
            for index, char in enumerate(value, lower):
                if index in assembled and assembled[index] != char:
                    conflict = True
                assembled[index] = char
        if assembled and not conflict and set(assembled) == set(range(max(assembled)+1)):
            out.append(("source-substring-constraints", "".join(assembled[i] for i in range(len(assembled))).encode()))
    return out
