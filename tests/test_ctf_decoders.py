import base64
from pathlib import Path

from ctf.decoders import decode_candidates


def test_base64_flag() -> None:
    encoded = base64.b64encode(b"flag{base64_example}")
    assert decode_candidates(encoded)[0]["candidate_flags"] == ["flag{base64_example}"]

def test_hex_flag() -> None:
    assert decode_candidates(b"666c61677b6865787d")[0]["candidate_flags"] == ["flag{hex}"]

def test_plain_text_not_reported_as_decoded() -> None:
    assert decode_candidates(b"flag{already_plain}") == []

def test_bounded_input(tmp_path: Path) -> None:
    path = tmp_path / "sample"
    path.write_bytes(b"x" * 100)
    assert decode_candidates(path.read_bytes()) == []
