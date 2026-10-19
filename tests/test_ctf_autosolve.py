import base64
import re
from pathlib import Path
from zipfile import ZipFile

import pytest

from ctf.autosolve import solve_directory


def test_zip_and_encoded_solution(tmp_path: Path) -> None:
    root = tmp_path / "challenge"
    root.mkdir()
    (root / "cipher.txt").write_bytes(base64.b64encode(b"flag{encoded}"))
    with ZipFile(root / "archive.zip", "w") as archive:
        archive.writestr("secret.txt", "flag{in_zip}")
        archive.writestr("../unsafe.txt", "flag{should_be_ignored}")
    result = solve_directory(root, "crypto")
    flags = {c["flag"] for c in result["candidates"]}
    assert {"flag{encoded}", "flag{in_zip}"} <= flags
    assert "flag{should_be_ignored}" not in flags
    assert result["verified"] is False
    assert any("skipped" in warning for warning in result["warnings"])


def test_custom_flag_format(tmp_path: Path) -> None:
    root = tmp_path / "challenge"
    root.mkdir()
    (root / "note.txt").write_text("SOLAR{specific}")
    result = solve_directory(root, "web", re.compile(rb"SOLAR\{[a-z]+\}"))
    assert result["candidates"][0]["flag"] == "SOLAR{specific}"


def test_directory_input_only(tmp_path: Path) -> None:
    file = tmp_path / "file.txt"
    file.write_text("x")
    with pytest.raises(ValueError):
        solve_directory(file)
