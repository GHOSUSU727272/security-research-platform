from pathlib import Path
from zipfile import ZipFile

import pytest

from ctf.archive import inspect_zip
from ctf.challenges import add, analyze, load


def test_registry_and_analysis(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "hint.txt").write_text("flag{demo}")
    workspace = tmp_path / "workspace"
    add(workspace, "demo-1", source, "misc")
    report = analyze(workspace, "demo-1")
    assert report["candidate_count"] == 1
    assert load(workspace)["challenges"]["demo-1"]["status"] == "analyzed"
    assert (workspace / "reports" / "demo-1" / "index.html").exists()

def test_duplicate_and_bad_id(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    add(tmp_path / "ws", "demo", source)
    with pytest.raises(ValueError):
        add(tmp_path / "ws", "demo", source)
    with pytest.raises(ValueError):
        add(tmp_path / "ws", "../escape", source)

def test_zip_manifest_detects_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "demo.zip"
    with ZipFile(archive, "w") as z:
        z.writestr("../outside.txt", "flag{demo}")
        z.writestr("inside.txt", "hello")
    result = inspect_zip(archive)
    assert "unsafe archive paths" in result["warnings"]
    assert result["extracted"] is False

def test_zip_empty(tmp_path: Path) -> None:
    archive = tmp_path / "empty.zip"
    with ZipFile(archive, "w"):
        pass
    assert inspect_zip(archive)["entries"] == []

def test_integrated_encoded_flag_and_archive(tmp_path: Path) -> None:
    import base64

    source = tmp_path / "input"
    source.mkdir()
    (source / "encoded.txt").write_bytes(base64.b64encode(b"flag{integrated}"))
    with ZipFile(source / "files.zip", "w") as z:
        z.writestr("../bad", "x")
    workspace = tmp_path / "ws"
    add(workspace, "integration", source)
    report = analyze(workspace, "integration")
    assert report["decoded_candidate_count"] == 1
    assert any("unsafe archive paths" in entry.get("archive", {}).get("warnings", [])
               for entry in report["files"])
