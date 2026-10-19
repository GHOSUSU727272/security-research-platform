from pathlib import Path

import pytest

from ctf.challenges import load
from ctf.watch import run_once


def test_auto_ingest_and_idempotence(tmp_path: Path) -> None:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    folder = inbox / "challenge1"
    folder.mkdir()
    (folder / "flag.txt").write_text("flag{demo}")
    workspace = tmp_path / "workspace"
    first = run_once(inbox, workspace)
    assert first["added"] == ["challenge1"]
    assert first["analyzed"] == ["challenge1"]
    assert load(workspace)["challenges"]["challenge1"]["candidate_count"] == 1
    assert run_once(inbox, workspace)["analyzed"] == []

def test_reject_workspace_inside_inbox(tmp_path: Path) -> None:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    with pytest.raises(ValueError):
        run_once(inbox, inbox / "workspace")

def test_skip_symlinks(tmp_path: Path) -> None:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (inbox / "linked").symlink_to(outside, target_is_directory=True)
    assert run_once(inbox, tmp_path / "workspace")["added"] == []

def test_reanalyzes_changed_files(tmp_path: Path) -> None:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    source = inbox / "puzzle"
    source.mkdir()
    file = source / "clue.txt"
    file.write_text("initial")
    workspace = tmp_path / "workspace"
    assert run_once(inbox, workspace)["analyzed"] == ["puzzle"]
    assert run_once(inbox, workspace)["analyzed"] == []
    file.write_text("flag{new_answer}")
    assert run_once(inbox, workspace)["analyzed"] == ["puzzle"]
    assert load(workspace)["challenges"]["puzzle"]["solver_candidate_count"] == 1
