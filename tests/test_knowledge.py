"""Project isolation, knowledge lifecycle, safe transfer and CLI compatibility."""

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from analysis.knowledge_ingest import ingest
from analysis.source import SourcePlugin
from core.knowledge import GraphEngine, KnowledgeEngine
from core.models import Context
from core.projects import ProjectManager
from database.store import Store
from reports.dashboard import dashboard


def create_knowledge(
    manager: ProjectManager, name: str
) -> tuple[Store, KnowledgeEngine]:
    """Create one isolated project and return its owned database connection."""
    project = manager.create(name)
    store = Store(manager.path(project["id"]) / "research.sqlite3")
    return store, KnowledgeEngine(store)


def test_isolation_and_graph(tmp_path: Path) -> None:
    """Project B never resolves project A's notes, functions or graph endpoints."""
    manager = ProjectManager(tmp_path)
    first, a = create_knowledge(manager, "KESL")
    second, b = create_knowledge(manager, "OTHER")
    try:
        function = a.add("Functions", "check_input")
        library = a.add("Libraries", "libexample.so")
        hypothesis = a.add("Hypotheses", "Input boundary may be inconsistent")
        note = a.note("Trace validation", "manual-review", 1, [function], [library])
        GraphEngine(a).connect(
            hypothesis, function, "concerns", "Review input boundary"
        )
        assert len(GraphEngine(a).neighborhood(note, 2)["nodes"]) == 4
        assert b.entities("Functions") == []
        with pytest.raises(ValueError, match="Unknown"):
            b.get(function)
        own = b.add("Functions", "other")
        with pytest.raises(ValueError):
            GraphEngine(b).connect(own, function, "related", "Cross-project link")
        with pytest.raises(ValueError):
            a.note("Bad typed link", "review", 1, [library], [])
        assert len(a.entities("Notes")) == 1
        assert a.project()["product_version"] == "12.5"
        assert a.project()["last_researched_at"] is None
    finally:
        first.close()
        second.close()
        manager.close()


def test_states_progress_and_false_positives(tmp_path: Path) -> None:
    """Track real review decisions, hypothesis states and reversible dismissals."""
    manager = ProjectManager(tmp_path)
    store, engine = create_knowledge(manager, "KESL")
    try:
        assert engine.summary()["progress"]["percent"] is None
        function = engine.add("Functions", "f")
        engine.add("Libraries", "lib")
        hypothesis = engine.add("Hypotheses", "h")
        finding = engine.add("Findings", "candidate")
        engine.transition(function, "reviewed", "Inspected implementation")
        engine.transition(hypothesis, "testing", "Experiment planned")
        engine.transition(hypothesis, "rejected", "Counterexample in expected behavior")
        engine.transition(finding, "dismissed", "Safe input")
        engine.transition(finding, "dismissed", "Additional confirmation")
        summary = engine.summary()
        assert summary["progress"]["percent"] == 50.0
        assert summary["states"]["Hypotheses"]["rejected"] == 1
        assert summary["false_positives"] == 1
        assert len(engine.entities("FalsePositives")) == 1
        engine.transition(finding, "candidate", "Reopened with new evidence")
        assert engine.summary()["false_positives"] == 0
        engine.add("FalsePositives", "Documented external false positive")
        assert engine.summary()["false_positives"] == 1
        assert engine.entities("ResearchHistory")
        with pytest.raises(ValueError):
            engine.transition(function, "rejected", "Not a function state")
        with pytest.raises(ValueError):
            engine.transition(function, "reviewed", "")
    finally:
        store.close()
        manager.close()


def test_ingest_is_idempotent_and_preserves_review(tmp_path: Path) -> None:
    """Index declared functions even without calls, and never reset reviewed status."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "example.py").write_text(
        "import json\ndef empty():\n    pass\ndef f(x):\n    return eval(x)\n"
    )
    manager = ProjectManager(tmp_path / "workspace")
    store, engine = create_knowledge(manager, "KESL")
    try:
        context = Context(str(target), 4096, ())
        result = asyncio.run(SourcePlugin().run(context))
        job = store.enqueue("source", asdict(context))
        store.finish(job, result)
        assert ingest(engine) == 1
        assert ingest(engine) == 0
        assert len(engine.entities("Functions")) == 2
        assert len(engine.entities("Libraries")) == 1
        assert len(engine.entities("Findings")) == 1
        assert engine.project()["last_researched_at"]
        function = engine.entities("Functions")[0]["id"]
        engine.transition(function, "reviewed", "Reviewed source")
        second = store.enqueue("source", asdict(context))
        store.finish(second, result)
        ingest(engine)
        assert engine.get(function)["status"] == "reviewed"
        assert len(engine.entities("Functions")) == 2
        assert len(engine.entities("Experiments")) == 2
    finally:
        store.close()
        manager.close()


def test_archive_round_trip(tmp_path: Path) -> None:
    """Transfer all database rows, graph links and exact binary artifact bytes."""
    source = ProjectManager(tmp_path / "source")
    destination = ProjectManager(tmp_path / "destination")
    store, engine = create_knowledge(source, "KESL")
    try:
        entity = engine.add("Functions", "test")
        engine.note("Portable note", "review", 2, [entity], [])
        artifact = tmp_path / "evidence.bin"
        artifact.write_bytes(b"\x00\xffresearch\x00")
        attachment = source.attach(engine.project_id, artifact)
        job = store.enqueue("source", asdict(Context("/old/machine", 100, ())))
        store.finish(job, {"findings": []})
        ingest(engine)
        bundle = tmp_path / "project.zip"
        source.export(engine.project_id, bundle)
        metadata = destination.import_archive(bundle)
        assert metadata == engine.project()
        destination.open("KESL")
        assert destination.resolve()["root"] is None  # type: ignore[index]
        restored_store = Store(destination.path(metadata["id"]) / "research.sqlite3")
        try:
            restored = KnowledgeEngine(restored_store)
            assert restored.summary() == engine.summary()
            assert restored.get(entity) == engine.get(entity)
            assert len(GraphEngine(restored).neighborhood(entity)["edges"]) == 1
            blob = restored.get(attachment)["evidence"]["blob"]
            assert (
                destination.path(metadata["id"]) / blob
            ).read_bytes() == artifact.read_bytes()
            assert restored_store.jobs() == store.jobs()
        finally:
            restored_store.close()
        with pytest.raises(ValueError, match="already exists"):
            destination.import_archive(bundle)
    finally:
        store.close()
        source.close()
        destination.close()


@pytest.mark.parametrize("mode", ["tamper", "traversal", "duplicate"])
def test_invalid_archive_is_atomic(tmp_path: Path, mode: str) -> None:
    """Reject damaged and path-manipulated archives without registering projects."""
    manager = ProjectManager(tmp_path / "source")
    project = manager.create("KESL")
    good, bad = tmp_path / "good.zip", tmp_path / "bad.zip"
    manager.export(project["id"], good)
    with zipfile.ZipFile(good) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    if mode == "tamper":
        files["data.json"] += b" "
    if mode == "traversal":
        files["../escape"] = b"outside"
    with zipfile.ZipFile(bad, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
        if mode == "duplicate":
            with pytest.warns(UserWarning):
                archive.writestr("data.json", files["data.json"])
    target = ProjectManager(tmp_path / "target")
    try:
        with pytest.raises(ValueError):
            target.import_archive(bad)
        assert target.list() == []
        assert list(target.directory.iterdir()) == []
        assert not (tmp_path / "escape").exists()
    finally:
        manager.close()
        target.close()


def test_dashboard_escapes_untrusted_content(tmp_path: Path) -> None:
    """Render empty inventory and all dashboard counters without executable markup."""
    manager = ProjectManager(tmp_path)
    store, engine = create_knowledge(manager, "<script>alert(1)</script>")
    try:
        engine.note("<img src=x onerror=alert(1)>", "<script>", 2, [], [])
        path = tmp_path / "dashboard.html"
        dashboard(engine, path)
        page = path.read_text(encoding="utf-8")
        assert "<script>" not in page
        assert "<img" not in page
        assert "&lt;script&gt;" in page
        assert "No inventory yet" in page
        assert "Hypotheses" in page
    finally:
        store.close()
        manager.close()


def test_import_rejects_cross_project_rows(tmp_path: Path) -> None:
    """Valid hashes do not bypass referential integrity and project ownership."""
    manager = ProjectManager(tmp_path / "source")
    store, engine = create_knowledge(manager, "KESL")
    target = ProjectManager(tmp_path / "target")
    try:
        engine.add("Functions", "f")
        good = tmp_path / "good.zip"
        manager.export(engine.project_id, good)
        with zipfile.ZipFile(good) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        data = json.loads(files["data.json"])
        data["KnowledgeEntities"][0]["project_id"] = "foreign-project"
        files["data.json"] = json.dumps(data).encode()
        manifest = json.loads(files["manifest.json"])
        manifest["files"]["data.json"] = {
            "sha256": hashlib.sha256(files["data.json"]).hexdigest(),
            "bytes": len(files["data.json"]),
        }
        files["manifest.json"] = json.dumps(manifest).encode()
        bad = tmp_path / "bad.zip"
        with zipfile.ZipFile(bad, "w") as archive:
            for name, content in files.items():
                archive.writestr(name, content)
        import sqlite3

        with pytest.raises(sqlite3.IntegrityError):
            target.import_archive(bad)
        assert target.list() == []
        assert list(target.directory.iterdir()) == []
    finally:
        store.close()
        manager.close()
        target.close()


def test_dynamic_ingest(tmp_path: Path) -> None:
    """Behavior deltas create candidates connected to their experiment, never confirmations."""
    manager = ProjectManager(tmp_path)
    store, engine = create_knowledge(manager, "KESL")
    try:
        context = asdict(Context("/lab", 100, (), ("test",)))
        for code in (0, 1):
            job = store.enqueue("dynamic", context)
            store.finish(
                job,
                {
                    "returncode": code,
                    "stdout": {"sha256": "a"},
                    "stderr": {"sha256": "a"},
                },
            )
        assert ingest(engine) == 2
        finding = engine.entities("Findings")[0]
        assert finding["status"] == "candidate"
        assert finding["priority"] == 1
        assert finding["evidence"]["changes"] == ["returncode"]
        assert GraphEngine(engine).neighborhood(finding["id"])["edges"]
        assert engine.summary()["confirmed"] == 0
    finally:
        store.close()
        manager.close()


def test_cli_legacy_and_project_flow(tmp_path: Path) -> None:
    """Use installed module entry point to verify old and new CLI behavior end to end."""
    root = Path(__file__).resolve().parents[1]
    target = tmp_path / "target"
    target.mkdir()
    (target / "sample.py").write_text("def f():\n    return 1\n")
    config = tmp_path / "config.yaml"
    config.write_text("root: target\nstate: legacy\n")
    env = {**os.environ, "PYTHONPATH": str(root), "PYTHONIOENCODING": "utf-8"}

    def cli(*args: str) -> Any:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "core.cli",
                "--config",
                str(config),
                "--workspace",
                str(tmp_path / "workspace"),
                *args,
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
        return json.loads(completed.stdout)

    assert cli("status") == []
    cli("scan")
    assert cli("status")[0]["status"] == "done"
    project = cli("create", "KESL")
    cli("open", "KESL", "--root", str(target))
    assert cli("status")["project"]["id"] == project["id"]
    cli("scan")
    assert cli("status")["counts"]["Functions"] == 1
    assert cli("--legacy", "status")[0]["status"] == "done"
    assert len(cli("list")) == 1
    assert Path(cli("dashboard")["dashboard"]).is_file()
    assert Path(cli("export")["archive"]).is_file()
    cli("project-status", "paused")
    with pytest.raises(subprocess.CalledProcessError) as error:
        cli("scan")
    assert "not active" in error.value.stderr
    assert cli("status")["project"]["status"] == "paused"
