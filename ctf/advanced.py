"""Bounded offline methods. Heuristic recoveries are explicitly labelled."""
from __future__ import annotations

import ast
import base64
import html
import math
import re


def transforms(data: bytes):
    out = []
    if not 4 <= len(data) <= 32768:
        return out
    for encoding in ("utf-16-le", "utf-16-be"):
        if data.count(b"\0") > len(data)//5:
            try:
                out.append((encoding, data.decode(encoding).encode()))
            except UnicodeError:
                pass
    text = data.decode("utf-8", "replace").strip()
    if "&" in text:
        out.append(("html-entities", html.unescape(text).encode()))
    if "\\x" in text or "\\u" in text:
        decoded = re.sub(r"\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})",
                         lambda m: chr(int(m.group(1) or m.group(2), 16)), text)
        out.append(("escaped-characters", decoded.encode()))
    if len(text) < 8192:
        out.append(("reverse", data[::-1]))
        out.append(("rot47", bytes(33+(v-33+47)%94 if 33 <= v <= 126 else v for v in data)))
    for token in re.findall(r"(?<![\w-])[A-Za-z0-9_-]{12,}={0,2}(?![\w-])", text)[:20]:
        if "-" in token or "_" in token:
            try:
                out.append(("base64-url", base64.urlsafe_b64decode(token+"="*(-len(token)%4))))
            except ValueError:
                pass
    for token in re.findall(r"(?:\b[0-9a-fA-F]{2}[ :]){7,}[0-9a-fA-F]{2}\b", text)[:20]:
        out.append(("spaced-hex", bytes.fromhex(token.replace(":", " "))))
    # Only explicitly supplied keys: no guesses about AES or Vigenere parameters.
    key = re.search(r"(?im)^\s*(?:xor_)?key\s*[:=]\s*['\"]([^'\"\r\n]{1,128})['\"]", text)
    cipher = re.search(r"(?im)^\s*(?:ciphertext|encrypted|ct)\s*[:=]\s*['\"]?([0-9a-fA-F]{8,8192})['\"]?\s*$", text)
    if key and cipher and len(cipher[1]) % 2 == 0:
        raw, secret = bytes.fromhex(cipher[1]), key[1].encode()
        out.append(("xor-supplied-key", bytes(v ^ secret[i % len(secret)] for i, v in enumerate(raw))))
    if key and "vigen" in text.lower():
        encrypted = re.search(r"(?im)^\s*(?:ciphertext|encrypted|ct)\s*[:=]\s*['\"]([A-Za-z{}_0-9 !.-]+)['\"]", text)
        if encrypted and key[1].isalpha() and key[1].isascii():
            secret, position, chars = key[1].lower(), 0, []
            for char in encrypted[1]:
                if char.isascii() and char.isalpha():
                    start = ord("A") if char.isupper() else ord("a")
                    chars.append(chr((ord(char)-start-ord(secret[position % len(secret)])+97)%26+start))
                    position += 1
                else:
                    chars.append(char)
            out.append(("vigenere-supplied-key", "".join(chars).encode()))
    return out


def periodic_xor(data: bytes):
    """Use prefix+closing brace only with at least three periods of validation.

    This is a hypothesis, not proof: never manufacture unconstrained body bytes.
    Every key byte must be fixed by the crib; the entire remaining body must fit.
    """
    if not 18 <= len(data) <= 2048:
        return []
    allowed = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:@!?.+/-")
    out = []
    for prefix in (b"SOLARCTF{", b"solarctf{", b"crypto{", b"picoCTF{", b"flag{"):
        for length in range(2, min(len(prefix)+1, len(data)//3)+1):
            key = [None]*length
            consistent = True
            for index, value in [*enumerate(prefix), (len(data)-1, ord("}"))]:
                part = data[index] ^ value
                if key[index % length] not in (None, part):
                    consistent = False
                    break
                key[index % length] = part
            if not consistent or None in key or not any(key):
                continue
            plain = bytes(v ^ key[i % length] for i, v in enumerate(data))
            if len(plain)-len(prefix)-1 < 8 or not all(v in allowed for v in plain[len(prefix):-1]):
                continue
            out.append(("heuristic-xor-periodic:key="+bytes(key).hex(), plain))
    return out[:4]


def rsa(data: bytes):
    text = data[:32768].decode("ascii", "ignore")
    params = {k.lower(): int(v, 16 if v.lower().startswith("0x") else 10)
              for k, v in re.findall(r'''(?im)(?:^|[,{\n])\s*["']?(n[123]?|e|d|p|q|c[123]?|phi)["']?\s*[:=]\s*(0x[0-9a-f]+|\d{1,2500})''', text)}
    n, e, c = (params.get(k, 0) for k in ("n", "e", "c"))
    out = []
    if not n and params.get("p", 0) > 1 and params.get("q", 0) > 1:
        n = params["p"] * params["q"]

    def accept(m, label):
        if n > 1 and e > 1 and 0 <= c < n and pow(m, e, n) == c:
            out.append((label, m.to_bytes(max(1, (m.bit_length()+7)//8), "big")))

    if n > 3 and e > 1 and 0 <= c < n:
        if params.get("d", 0) > 0:
            accept(pow(c, params["d"], n), "rsa-supplied-private-exponent")
        phi = params.get("phi", 0)
        if not phi and params.get("p", 0)*params.get("q", 0) == n:
            p, q = params["p"], params["q"]
            phi = p*(p-1) if p == q else (p-1)*(q-1)
        if phi > 0:
            try:
                accept(pow(c, pow(e, -1, phi), n), "rsa-supplied-totient-or-primes")
            except ValueError:
                pass
        # Wiener's continued fraction attack, accepted only after exact checks.
        numerator, denominator = e, n
        h0, h1, k0, k1 = 0, 1, 1, 0
        for _ in range(2048):
            if not denominator:
                break
            a, rem = divmod(numerator, denominator)
            numerator, denominator = denominator, rem
            h, k = a*h1+h0, a*k1+k0
            h0, h1, k0, k1 = h1, h, k1, k
            if not h or (e*k-1) % h:
                continue
            candidate_phi = (e*k-1)//h
            s = n-candidate_phi+1
            disc = s*s-4*n
            if disc >= 0 and math.isqrt(disc)**2 == disc:
                p = (s+math.isqrt(disc))//2
                if 1 < p < n and n % p == 0:
                    accept(pow(c, k, n), "rsa-wiener")
                    break
        # Bounded rho, useful for intentionally small factors, not general RSA.
        if n.bit_length() <= 512 and not out:
            factor = 2 if n % 2 == 0 else 1
            x = y = 2
            for _ in range(12000):
                if factor != 1:
                    break
                x = (x*x+1) % n
                y = (y*y+1) % n
                y = (y*y+1) % n
                factor = math.gcd(abs(x-y), n)
            if 1 < factor < n:
                try:
                    accept(pow(c, pow(e, -1, (factor-1)*(n//factor-1)), n), "rsa-small-factor-rho")
                except ValueError:
                    pass
    if e in (3, 5, 7) and all(f"n{i}" in params and f"c{i}" in params for i in (1, 2, 3)):
        moduli = [params[f"n{i}"] for i in (1, 2, 3)]
        if all(v > 1 for v in moduli):
            product = math.prod(moduli)
            try:
                combined = sum(params[f"c{i}"]*(product//moduli[i-1])*pow(product//moduli[i-1], -1, moduli[i-1])
                               for i in (1, 2, 3)) % product
                from ctf.techniques import _root
                m = _root(combined, e)
                if m**e == combined and all(pow(m, e, params[f"n{i}"]) == params[f"c{i}"] for i in (1, 2, 3)):
                    out.append(("rsa-broadcast-crt", m.to_bytes(max(1, (m.bit_length()+7)//8), "big")))
            except ValueError:
                pass
    return out


def python_constraints(data: bytes):
    """Solve a strict straight-line Python checker subset; never execute source.

    Supports assert comparisons on ord(value[index]), integer arithmetic and XOR.
    Rejects non-unique models, control flow, arbitrary calls and unknown symbols.
    """
    if len(data) > 32768:
        return []
    try:
        tree = ast.parse(data.decode("utf-8"))
    except (SyntaxError, UnicodeError):
        return []
    scopes = [tree.body] + [n.body for n in tree.body if isinstance(n, ast.FunctionDef)]
    out = []
    for body in scopes:
        asserts = [n.test for n in body if isinstance(n, ast.Assert)]
        # Assertions nested in conditional branches are not unconditional facts.
        if not asserts or any(isinstance(n, (ast.If, ast.For, ast.While, ast.Try)) for n in body):
            continue
        lengths = []
        for node in asserts:
            if (isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq)
                    and isinstance(node.left, ast.Call) and isinstance(node.left.func, ast.Name)
                    and node.left.func.id == "len" and len(node.left.args) == 1
                    and isinstance(node.left.args[0], ast.Name) and isinstance(node.comparators[0], ast.Constant)
                    and type(node.comparators[0].value) is int):
                lengths.append((node.left.args[0].id, node.comparators[0].value))
        for variable, size in lengths:
            if not 4 <= size <= 160:
                continue
            try:
                import z3
                values = [z3.BitVec(f"c{i}", 32) for i in range(size)]
                solver = z3.Solver()
                solver.set(timeout=1500)
                solver.add(*[z3.And(v >= 32, v <= 126) for v in values])

                def expression(node):
                    if isinstance(node, ast.Constant) and type(node.value) is int and 0 <= node.value < 2**24:
                        return node.value
                    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == variable:
                        if isinstance(node.slice, ast.Constant) and type(node.slice.value) is int and 0 <= node.slice.value < size:
                            return values[node.slice.value]
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and len(node.args) == 1 and not node.keywords:
                        if node.func.id == "ord" and isinstance(node.args[0], ast.Subscript):
                            return expression(node.args[0])
                        if node.func.id == "len" and isinstance(node.args[0], ast.Name) and node.args[0].id == variable:
                            return size
                    if isinstance(node, ast.BinOp):
                        left, right = expression(node.left), expression(node.right)
                        ops = {ast.Add: lambda: left+right, ast.Sub: lambda: left-right,
                               ast.BitXor: lambda: left^right, ast.BitAnd: lambda: left&right,
                               ast.BitOr: lambda: left|right}
                        if type(node.op) in ops:
                            return ops[type(node.op)]()
                    if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
                        return expression(node.left) == expression(node.comparators[0])
                    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
                        return z3.And(*[expression(v) for v in node.values])
                    raise ValueError("Unsupported checker expression")

                solver.add(*[expression(a) for a in asserts])
                if solver.check() != z3.sat:
                    continue
                model = solver.model()
                raw = bytes(model.eval(v).as_long() for v in values)
                solver.add(z3.Or(*[v != b for v, b in zip(values, raw)]))
                if solver.check() == z3.unsat:
                    values = list(raw)
                    if all(z3.is_true(z3.simplify(a)) if isinstance(a, z3.BoolRef) else a
                           for a in [expression(n) for n in asserts]):
                        out.append(("python-z3-unique-constraints", raw))
            except (ImportError, ValueError, TypeError, ArithmeticError):
                continue
    return out
