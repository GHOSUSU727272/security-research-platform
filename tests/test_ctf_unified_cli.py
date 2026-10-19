import json
import sys
from pathlib import Path

from core.cli import main


def test_research_ctf_commands(tmp_path: Path, monkeypatch, capsys) -> None:
    folder = tmp_path / "challenge"
    folder.mkdir()
    (folder / "clue.txt").write_text("SOLARCTF{cli_example}")
    workspace = tmp_path / "work"
    commands = [
        ["add", "example", str(folder)],
        ["analyze", "example"],
        ["list"],
        ["dashboard"],
    ]
    outputs = []
    for command in commands:
        monkeypatch.setattr(
            sys, "argv", ["research", "ctf", "--ctf-workspace", str(workspace), *command],
        )
        main()
        outputs.append(capsys.readouterr().out)
    assert '"solarctf_candidates": [' in outputs[1]
    assert "SOLARCTF{cli_example}" in outputs[1]
    assert "example" in json.loads(outputs[2])
    assert (workspace / "index.html").exists()


def test_ctf_is_in_python_package() -> None:
    from setuptools import find_packages
    assert "ctf" in find_packages()
