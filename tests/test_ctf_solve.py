import base64
import re

from ctf.solve import _atbash, _caesar, solve_bytes


def candidates(data: bytes, category: str = "crypto") -> set[str]:
    return {c["flag"] for c in solve_bytes(data, category=category)["candidates"]}

def test_base64_two_layers() -> None:
    encoded = base64.b64encode(base64.b64encode(b"flag{twice}"))
    assert "flag{twice}" in candidates(encoded)

def test_caesar_cipher() -> None:
    assert "flag{rot_shift}" in candidates(_caesar(b"flag{rot_shift}", 9))

def test_atbash() -> None:
    assert "flag{atbash}" in candidates(_atbash(b"flag{atbash}"))

def test_xor() -> None:
    cipher = bytes(v ^ 0x42 for v in b"flag{xor_key}")
    assert "flag{xor_key}" in candidates(cipher)

def test_rsa_toy() -> None:
    # Textbook RSA with tiny factors; ciphertext fits the modulus.
    message = b"flag{r}"
    integer = int.from_bytes(message, "big")
    p, q = 1000003, 1000000007
    n = p * q
    assert integer > n  # use smaller plaintext for toy RSA fixture
    integer = int.from_bytes(b"ctf{a}", "big")
    assert integer < n
    e = 65537
    encrypted = pow(integer, e, n)
    data = f"n = {n}\ne = {e}\nc = {encrypted}\n".encode()
    assert "ctf{a}" in candidates(data)

def test_custom_flag_regex() -> None:
    pattern = re.compile(rb"SCTF\{[a-z]+\}")
    result = solve_bytes(b"SCTF{custom}", flag_pattern=pattern)
    assert result["candidates"][0]["flag"] == "SCTF{custom}"

def test_no_false_success_from_irrelevant_file() -> None:
    assert not solve_bytes(b"completely ordinary sample without a flag")["candidates"]
