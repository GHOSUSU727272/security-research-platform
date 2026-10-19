from pathlib import Path

import pytest

from ctf.triage import triage, write_report


def test_flag_detection_and_categories(tmp_path: Path) -> None:
    root = tmp_path / "challenge"
    root.mkdir()
    (root / "readme.txt").write_text("hint solarctf{test_only}", encoding="utf-8")
    (root / "binary.elf").write_bytes(b"\x7fELF" + b"\0" * 10)
    result = triage(root)
    assert result["candidate_count"] == 1
    assert result["categories"]["reverse"] == 1
    assert result["files"][1]["candidate_flags"] == ["solarctf{test_only}"]
    write_report(result, tmp_path / "out")
    assert (tmp_path / "out" / "index.html").exists()

def test_symlink_not_followed(tmp_path: Path) -> None:
    root = tmp_path / "input"
    root.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("flag{outside}")
    (root / "outside.txt").symlink_to(secret)
    assert triage(root)["files"] == []

def test_cross_chunk_flag(tmp_path: Path) -> None:
    root = tmp_path / "input"
    root.mkdir()
    (root / "large.txt").write_bytes(b"A" * (1024 * 1024 - 3) + b"flag{split}")
    assert triage(root)["candidate_count"] == 1

def test_non_directory(tmp_path: Path) -> None:
    file = tmp_path / "a"
    file.write_text("x")
    with pytest.raises(ValueError):
        triage(file)
