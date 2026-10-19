"""Research orchestration behavior, recovery, process isolation and compatibility."""

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any, cast

import pytest

from core.models import Context
from core.projects import LEGACY_TABLES, ProjectManager
from core.research.manager import ResearchManager
from core.research.plan import ResearchPlan, TaskSpec
from core.research.pool import ProcessExecutor
from core.research.scheduler import TaskScheduler
from database.store import Store
from reports.research_dashboard import research_dashboard


@pytest.fixture
def engine(tmp_path: Path) -> Any:
    """Provide a project database with a harmless local Python target."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "sample.py").write_text("def f(x):\n    return eval(x)\n")
    projects = ProjectManager(tmp_path / "workspace")
    project = projects.create("Test research", root=target)
    base = projects.path(project["id"])
    store = Store(base / "research.sqlite3")
    manager = ResearchManager(store, base)
    try:
        yield manager, Context(str(target), 4096, ()), projects
    finally:
        store.close()
        projects.close()


class FakeExecutor(ProcessExecutor):
    """Deterministic controllable executor for scheduler policy tests."""

    active_count = 0
    peak = 0
    delay = 0.02

    async def execute(self, task: dict[str, Any]) -> dict[str, object]:
        """Simulate isolated work while exercising concurrency and retry rules."""
        type(self).active_count += 1
        type(self).peak = max(type(self).peak, type(self).active_count)
        try:
            await asyncio.sleep(type(self).delay)
            if task["task_key"] == "bad" or (
                task["task_key"] == "flaky" and task["attempts"] == 1
            ):
                raise RuntimeError("Controlled failure")
            return {"findings": []}
        finally:
            type(self).active_count -= 1


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> None:
    """Swap only the process boundary; keep all orchestration/storage code real."""
    FakeExecutor.active_count, FakeExecutor.peak, FakeExecutor.delay = 0, 0, 0.02
    monkeypatch.setattr("core.research.manager.ProcessExecutor", FakeExecutor)


def test_dag_validation() -> None:
    """Reject cycles and undefined dependencies before creating persistent tasks."""
    for tasks in (
        (TaskSpec("a", depends_on=("b",)),),
        (TaskSpec("a", depends_on=("b",)), TaskSpec("b", depends_on=("a",))),
        (TaskSpec("a"), TaskSpec("a")),
    ):
        with pytest.raises(ValueError):
            ResearchPlan(tasks=tasks).validate()


def test_priority_and_dependencies(engine: Any) -> None:
    """A high-priority dependent cannot start until its prerequisite completes."""
    manager, context, _ = engine
    run = manager.create(
        ResearchPlan(
            tasks=(
                TaskSpec("low", priority=3),
                TaskSpec("high", priority=1),
                TaskSpec("dependent", priority=1, depends_on=("high",)),
            )
        ),
        context,
    )
    with manager.db:
        manager.db.execute(
            "UPDATE ResearchRuns SET status='running' WHERE id=?", (run,)
        )
    scheduler = TaskScheduler(manager.db, run)
    first = scheduler.claim("one")
    assert first is not None and first["task_key"] == "high"
    next_task = scheduler.claim("two")
    assert next_task is not None and next_task["task_key"] == "low"
    assert scheduler.claim("three") is None
    manager.aggregator.complete(first, {"findings": []}, 0.1)
    third = scheduler.claim("three")
    assert third is not None and third["task_key"] == "dependent"


def test_retries_failure_and_independent_work(engine: Any, fake: None) -> None:
    """Retry transient failures, block failed descendants and finish independent work."""
    manager, context, _ = engine
    plan = ResearchPlan(
        workers=3,
        tasks=(
            TaskSpec("bad", attempts=2),
            TaskSpec("blocked", depends_on=("bad",)),
            TaskSpec("flaky", attempts=2),
            TaskSpec("ok"),
        ),
    )
    run = manager.create(plan, context)
    result = asyncio.run(manager.execute(run, context.root))
    assert result["status"] == "failed"
    assert result["completed"] == 2 and result["blocked"] == 1 and result["failed"] == 1
    assert FakeExecutor.peak > 1
    assert (
        manager.db.execute(
            "SELECT attempts FROM ResearchTasks WHERE task_key='flaky'"
        ).fetchone()[0]
        == 2
    )
    assert len(manager.store.jobs()) == 3
    assert len(manager.knowledge.entities("Experiments")) == 3


def test_pause_resume_and_checkpoints(engine: Any, fake: None) -> None:
    """A durable stop request interrupts workers, checkpoints and resumes pending work."""
    manager, context, _ = engine
    FakeExecutor.delay = 0.5
    run = manager.create(
        ResearchPlan(checkpoint_minutes=0.001, tasks=(TaskSpec("slow"),)), context
    )

    async def pause() -> dict[str, Any]:
        running = asyncio.create_task(manager.execute(run, context.root))
        await asyncio.sleep(0.25)
        # Use an independent connection, like another CLI process.
        other = Store(manager.base / "research.sqlite3")
        try:
            ResearchManager(other, manager.base).stop(run)
        finally:
            other.close()
        return cast(dict[str, Any], await running)

    result = asyncio.run(pause())
    assert result["status"] == "paused" and result["pending"] == 1
    assert manager.db.execute("SELECT attempts FROM ResearchTasks").fetchone()[0] == 0
    assert "periodic" in {c["reason"] for c in manager.checkpoints.list(run)}
    FakeExecutor.delay = 0.01
    assert asyncio.run(manager.execute(run, context.root))["status"] == "completed"
    assert len(manager.store.jobs()) == 1


def test_task_cancellation(engine: Any, fake: None) -> None:
    """Cancellation is permanent for a task and blocks descendants only."""
    manager, context, _ = engine
    run = manager.create(
        ResearchPlan(
            tasks=(
                TaskSpec("cancel"),
                TaskSpec("child", depends_on=("cancel",)),
                TaskSpec("ok"),
            )
        ),
        context,
    )
    manager.stop(run, task="cancel")
    result = asyncio.run(manager.execute(run, context.root))
    assert (
        result["cancelled"] == 1 and result["blocked"] == 1 and result["completed"] == 1
    )


def test_crash_recovery_keeps_completed_results(engine: Any, fake: None) -> None:
    """Committed tasks survive recovery even when the latest checkpoint predates them."""
    manager, context, _ = engine
    run = manager.create(
        ResearchPlan(tasks=(TaskSpec("a"), TaskSpec("b", depends_on=("a",)))), context
    )
    with manager.db:
        manager.db.execute(
            "UPDATE ResearchRuns SET status='running' WHERE id=?", (run,)
        )
    scheduler = TaskScheduler(manager.db, run)
    first = scheduler.claim("orphan")
    assert first is not None
    manager.aggregator.complete(first, {"findings": []}, 0.1)
    assert scheduler.claim("orphan") is not None
    # Reopen a connection to simulate a new supervisor after process death.
    store = Store(manager.base / "research.sqlite3")
    try:
        restarted = ResearchManager(store, manager.base)
        result = asyncio.run(restarted.execute(run, context.root))
        assert result["completed"] == 2
        rows = {
            r["task_key"]: r["attempts"]
            for r in store.db.execute("SELECT * FROM ResearchTasks")
        }
        assert rows == {"a": 1, "b": 2}
        assert len(store.jobs()) == 2
    finally:
        store.close()


def test_real_process_and_archive(engine: Any, tmp_path: Path) -> None:
    """Execute the real worker process, ingest knowledge and transfer all engine tables."""
    manager, context, projects = engine
    run = manager.create(ResearchPlan(), context)
    result = asyncio.run(manager.execute(run, context.root))
    assert result["status"] == "completed"
    assert len(manager.knowledge.entities("Functions")) == 1
    assert len(manager.knowledge.entities("Findings")) == 1
    processes = [
        e for e in manager.timeline.recent(run) if e["event"] == "worker_process"
    ]
    assert processes and processes[0]["details"]["pid"] != os.getpid()
    output = tmp_path / "engine.html"
    research_dashboard(manager, run, output)
    assert "Research Engine" in output.read_text(encoding="utf-8")
    archive = tmp_path / "project.zip"
    projects.export(manager.knowledge.project_id, archive)
    target = ProjectManager(tmp_path / "imported")
    try:
        project = target.import_archive(archive)
        restored_store = Store(target.path(project["id"]) / "research.sqlite3")
        try:
            restored = ResearchManager(restored_store, target.path(project["id"]))
            assert restored.progress.snapshot(run)["completed"] == 1
            assert restored.timeline.recent(run) == manager.timeline.recent(run)
            assert restored.checkpoints.list(run) == manager.checkpoints.list(run)
        finally:
            restored_store.close()
    finally:
        target.close()


def test_real_worker_timeout(engine: Any) -> None:
    """A supervisor timeout terminates even a worker that has not imported its plugin yet."""
    manager, context, _ = engine
    run = manager.create(
        ResearchPlan(tasks=(TaskSpec("short", timeout=0.001, attempts=1),)), context
    )
    result = asyncio.run(manager.execute(run, context.root))
    assert result["failed"] == 1
    assert "TimeoutError" in manager.store.jobs()[0]["error"]


def test_aggregation_failure_is_resumable(
    engine: Any, fake: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Retry knowledge projection after failure without rerunning a successful plugin."""
    manager, context, _ = engine
    run = manager.create(ResearchPlan(), context)
    original = manager.aggregator.flush

    def broken() -> int:
        """Represent a transient downstream failure after the result was committed."""
        raise RuntimeError("Temporary projection failure")

    monkeypatch.setattr(manager.aggregator, "flush", broken)
    with pytest.raises(RuntimeError):
        asyncio.run(manager.execute(run, context.root))
    assert manager.progress.snapshot(run)["status"] == "failed"
    monkeypatch.setattr(manager.aggregator, "flush", original)
    assert asyncio.run(manager.execute(run, context.root))["status"] == "completed"
    assert manager.db.execute("SELECT attempts FROM ResearchTasks").fetchone()[0] == 1
    assert len(manager.store.jobs()) == 1


def test_cli_engine_flow(tmp_path: Path) -> None:
    """Run the public CLI through preparation, stop/resume and status extensions."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "sample.py").write_text("def f():\n    pass\n")
    config = tmp_path / "config.yaml"
    config.write_text("root: target\nstate: legacy\n")
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": str(root), "PYTHONIOENCODING": "utf-8"}

    def cli(*args: str) -> Any:
        result = subprocess.run(
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
            env=env,
            cwd=tmp_path,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
        return json.loads(result.stdout)

    cli("create", "Engine test", "--root", str(target))
    cli("open", "Engine test")
    assert cli("start", "--prepare")["status"] == "ready"
    assert cli("stop")["status"] == "paused"
    assert cli("resume")["status"] == "completed"
    assert cli("status")["research_engine"]["completed"] == 1
    assert cli("progress")["completed"] == 1
    assert cli("timeline")
    assert cli("checkpoints")
    assert Path(cli("dashboard", "--engine")["dashboard"]).is_file()


def test_import_v02_archive(engine: Any, tmp_path: Path) -> None:
    """Continue accepting format-one v0.2 archives without engine tables."""
    manager, _, projects = engine
    archive = tmp_path / "new.zip"
    projects.export(manager.knowledge.project_id, archive)
    with zipfile.ZipFile(archive) as source:
        files = {name: source.read(name) for name in source.namelist()}
    data = json.loads(files["data.json"])
    files["data.json"] = json.dumps(
        {k: v for k, v in data.items() if k in LEGACY_TABLES}
    ).encode()
    manifest = json.loads(files["manifest.json"])
    manifest["version"] = 1
    manifest["files"]["data.json"] = {
        "sha256": hashlib.sha256(files["data.json"]).hexdigest(),
        "bytes": len(files["data.json"]),
    }
    files["manifest.json"] = json.dumps(manifest).encode()
    old = tmp_path / "old.zip"
    with zipfile.ZipFile(old, "w") as output:
        for name, content in files.items():
            output.writestr(name, content)
    imported = ProjectManager(tmp_path / "old-import")
    try:
        project = imported.import_archive(old)
        store = Store(imported.path(project["id"]) / "research.sqlite3")
        try:
            assert (
                store.db.execute("SELECT version FROM ResearchSchema").fetchone()[0]
                == 1
            )
            assert (
                store.db.execute("SELECT count(*) FROM ResearchRuns").fetchone()[0] == 0
            )
        finally:
            store.close()
    finally:
        imported.close()


def test_cancel_crashed_run(engine: Any, fake: None) -> None:
    """Cancellation requested after a crash cannot silently restart pending work."""
    manager, context, _ = engine
    run = manager.create(ResearchPlan(), context)
    with manager.db:
        manager.db.execute(
            "UPDATE ResearchRuns SET status='running' WHERE id=?", (run,)
        )
    assert TaskScheduler(manager.db, run).claim("orphan")
    manager.stop(run, cancel=True)
    result = asyncio.run(manager.execute(run, context.root))
    assert result["status"] == "cancelled"
    assert result["cancelled"] == 1
    assert manager.store.jobs() == []


@pytest.mark.parametrize(
    "fragment",
    ["workers: true", "checkpoint_minutes: .nan", "checkpoint_minutes: true"],
)
def test_invalid_plan_yaml(tmp_path: Path, fragment: str) -> None:
    """Reject ambiguous YAML numeric types and non-finite checkpoint intervals."""
    path = tmp_path / "plan.yaml"
    path.write_text(fragment + "\ntasks:\n  - key: source\n")
    with pytest.raises(ValueError):
        ResearchPlan.load(path)


def test_empty_dashboard(engine: Any, tmp_path: Path) -> None:
    """An untouched project has an honest idle dashboard rather than fabricated runs."""
    manager, _, _ = engine
    destination = tmp_path / "idle.html"
    research_dashboard(manager, None, destination)
    assert "No research started" in destination.read_text(encoding="utf-8")


def test_cancel_running_task(engine: Any, fake: None) -> None:
    """A cancel request reaps an active attempt without repeatedly interrupting cleanup."""
    manager, context, _ = engine
    FakeExecutor.delay = 0.5
    run = manager.create(ResearchPlan(tasks=(TaskSpec("active"),)), context)

    async def cancel() -> dict[str, Any]:
        execution = asyncio.create_task(manager.execute(run, context.root))
        await asyncio.sleep(0.1)
        manager.stop(run, task="active")
        return cast(dict[str, Any], await execution)

    result = asyncio.run(cancel())
    assert result["status"] == "cancelled"
    assert result["cancelled"] == 1
    assert FakeExecutor.active_count == 0


def test_dashboard_escapes_events(engine: Any, tmp_path: Path) -> None:
    """Project/task event text is data, never executable HTML in engine views."""
    manager, context, _ = engine
    run = manager.create(ResearchPlan(name="<script>alert(1)</script>"), context)
    with manager.db:
        manager.timeline.record(run, "<img src=x onerror=alert(1)>")
    destination = tmp_path / "escaped.html"
    research_dashboard(manager, run, destination)
    page = destination.read_text(encoding="utf-8")
    assert "<script>" not in page and "<img " not in page
    assert "&lt;script&gt;" in page
