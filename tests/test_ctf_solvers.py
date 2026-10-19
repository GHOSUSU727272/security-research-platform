import base64
import binascii
import zipfile
from pathlib import Path

from ctf.solvers import solve_bytes, solve_file


def found(data: bytes) -> set[str]:
    return {item["flag"] for item in solve_bytes(data)}


def test_caesar() -> None:
    assert "flag{rot_cipher}" in found(b"synt{ebg_pvcure}")


def test_xor() -> None:
    encrypted = bytes(char ^ 0x4F for char in b"flag{xor_cipher}")
    assert any(f["flag"] == "flag{xor_cipher}" and f["method"] == "xor-byte"
               for f in solve_bytes(encrypted))


def test_nested_base64() -> None:
    encoded = base64.b64encode(base64.b64encode(b"flag{two_layers}"))
    assert "flag{two_layers}" in found(b"encoded = " + encoded)


def test_hex() -> None:
    assert "flag{hex_puzzle}" in found(binascii.hexlify(b"flag{hex_puzzle}"))


def test_html_entities() -> None:
    encoded = "".join(f"&#{ord(c)};" for c in "flag{web_html}")
    assert "flag{web_html}" in found(encoded.encode())


def test_js_escape() -> None:
    encoded = "".join(f"\\x{ord(c):02x}" for c in "flag{web_js}")
    assert "flag{web_js}" in found(encoded.encode())


def test_js_charcode() -> None:
    encoded = "String.fromCharCode(" + ",".join(str(ord(c)) for c in "flag{charcode}") + ")"
    assert "flag{charcode}" in found(encoded.encode())


def test_utf16() -> None:
    assert "flag{unicode}" in found("flag{unicode}".encode("utf-16-le"))


def test_rsa_given_primes() -> None:
    p, q, e = 2**127 - 1, 2**107 - 1, 65537
    m = b"flag{rsa_done}"
    c = pow(int.from_bytes(m, "big"), e, p * q)
    challenge = f"p = {p}\nq = {q}\ne = {e}\nc = {c}\n".encode()
    assert b"flag{" not in challenge
    assert "flag{rsa_done}" in found(challenge)


def test_zip_entries(tmp_path: Path) -> None:
    path = tmp_path / "challenge.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("clue.txt", b"synt{vafvqr_mvc}")
        archive.writestr("../outside", b"flag{dont_use}")
    observed = {item["flag"] for item in solve_file(path)}
    assert "flag{inside_zip}" in observed
    assert "flag{dont_use}" not in observed
