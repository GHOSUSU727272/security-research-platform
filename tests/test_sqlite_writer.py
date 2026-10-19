"""Regression coverage for WAL snapshots and real multi-process checkpoint writers."""

import asyncio
import json
import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import analysis.knowledge_ingest as projection
import database.checkpoints as persistence
from analysis.plugin_ingest import ingest_records
from core.models import Context
from core.projects import ProjectManager
from core.research.manager import ResearchManager
from core.research.plan import ResearchPlan, TaskSpec
from database.checkpoints import CheckpointClient, CheckpointWriter, PersistenceError
from database.store import Store
from plugins.common import FileAnalyzer
from plugins.config.analyzer import ConfigAnalyzer


@pytest.fixture
def project(tmp_path: Path) -> Iterator[tuple[ResearchManager, Context]]:
    """Create a fully initialized isolated project with real SQLite schemas."""
    target = tmp_path / "target"
    target.mkdir()
    projects = ProjectManager(tmp_path / "workspace")
    metadata = projects.create("Concurrency", root=target)
    base = projects.path(metadata["id"])
    store = Store(base / "research.sqlite3")
    try:
        yield ResearchManager(store, base), Context(str(target), 4096, ())
    finally:
        store.close()
        projects.close()


def test_original_wal_snapshot_failure(tmp_path: Path) -> None:
    """Reproduce error 517 without another Research process or lock timeout."""
    path = tmp_path / "snapshot.db"
    reader = sqlite3.connect(path, timeout=0)
    writer = sqlite3.connect(path, timeout=0)
    try:
        reader.execute("PRAGMA journal_mode=WAL")
        reader.execute("CREATE TABLE jobs(id INTEGER PRIMARY KEY)")
        reader.executemany("INSERT INTO jobs VALUES(?)", [(1,), (2,), (3,)])
        reader.commit()
        cursor = reader.execute("SELECT * FROM jobs ORDER BY id")
        try:
            assert cursor.fetchone() == (1,)
            with writer:
                writer.execute("INSERT INTO jobs VALUES(4)")
            with pytest.raises(sqlite3.OperationalError) as failure:
                reader.execute("BEGIN IMMEDIATE")
            assert failure.value.sqlite_errorcode == sqlite3.SQLITE_BUSY_SNAPSHOT
        finally:
            cursor.close()
    finally:
        reader.close()
        writer.close()


def test_ingest_releases_snapshot_before_every_transaction(
    project: tuple[ResearchManager, Context], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Force a second connection's commit precisely between selection and BEGIN."""
    manager, _ = project
    for _ in range(130):  # Cross multiple bounded ID pages.
        job = manager.store.enqueue("source", {})
        manager.store.finish(job, {"findings": []})
    manager.db.execute("PRAGMA busy_timeout=0")
    other = sqlite3.connect(manager.base / "research.sqlite3", timeout=0)
    original = projection.pending_ids

    def interleaved(db: sqlite3.Connection) -> Iterator[int]:
        """Commit after each closed read cursor; no sleep or timing assumptions."""
        for identifier in original(db):
            with other:
                other.execute(
                    "INSERT OR REPLACE INTO PluginProgress VALUES(?,?,?,?,?)",
                    ("external", "config", "running", identifier, "{}"),
                )
            yield identifier

    monkeypatch.setattr(projection, "pending_ids", interleaved)
    try:
        assert manager.aggregator.flush() == 130
        assert manager.aggregator.flush() == 0
        assert (
            manager.db.execute("SELECT count(*) FROM Experiments").fetchone()[0] == 130
        )
        assert manager.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        other.close()


def test_ingest_rollback_keeps_prior_commits(
    project: tuple[ResearchManager, Context], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A projection error rolls back its job only; restart neither loses nor duplicates."""
    manager, _ = project
    for _ in range(3):
        manager.store.finish(manager.store.enqueue("source", {}), {"findings": []})
    original = ingest_records
    calls = 0

    def fail_second(*args: Any) -> None:
        """Fail after the second experiment was inserted within its transaction."""
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ValueError("controlled projection failure")
        original(*args)

    monkeypatch.setattr(projection, "ingest_records", fail_second)
    with pytest.raises(ValueError, match="controlled"):
        manager.aggregator.flush()
    assert manager.db.execute("SELECT count(*) FROM Experiments").fetchone()[0] == 1
    assert manager.db.execute("SELECT count(*) FROM IngestedJobs").fetchone()[0] == 1
    monkeypatch.setattr(projection, "ingest_records", original)
    assert manager.aggregator.flush() == 2
    assert manager.aggregator.flush() == 0


def test_acknowledged_atomic_commands_and_capabilities(
    project: tuple[ResearchManager, Context], monkeypatch: pytest.MonkeyPatch
) -> None:
    """IPC acknowledges committed data, rolls back failed samples and isolates scopes."""
    manager, context = project
    observer = sqlite3.connect(manager.base / "research.sqlite3", timeout=0)

    def forbidden_connect(*args: Any, **kwargs: Any) -> Any:
        """An IPC checkpoint client must never open SQLite itself."""
        raise AssertionError("Worker opened the project database")

    async def exercise() -> None:
        async with CheckpointWriter(manager.db) as writer:
            scoped = replace(
                context,
                checkpoint_db="must-not-open.sqlite3",
                checkpoint_endpoint=writer.endpoint,
                checkpoint_token=writer.grant("task", "config"),
            )
            monkeypatch.setattr(sqlite3, "connect", forbidden_connect)
            client = CheckpointClient(scoped, "task", "config")
            await client.request("progress", status="running", progress="{}")
            assert (
                observer.execute("SELECT status FROM PluginProgress").fetchone()[0]
                == "running"
            )
            with pytest.raises(PersistenceError, match="KeyError"):
                await client.request("sample", status="completed", progress="{}")
            assert (
                observer.execute("SELECT status FROM PluginProgress").fetchone()[0]
                == "running"
            )
            await client.request(
                "put", path="a", digest="hash", signature="1", result='{"x":1}'
            )
            assert (
                await client.request("get", path="a", digest="hash", signature="1")
                == '{"x":1}'
            )
            invalid = CheckpointClient(scoped, "other-task", "config")
            with pytest.raises(PersistenceError, match="capability"):
                await invalid.request("progress", status="completed", progress="{}")
            writer.revoke(scoped.checkpoint_token)
            with pytest.raises(PersistenceError, match="capability"):
                await client.request("progress", status="completed", progress="{}")
            client.close()
            invalid.close()

    try:
        asyncio.run(exercise())
    finally:
        observer.close()


def test_real_four_workers_with_ingest_checkpoints_and_readers(
    project: tuple[ResearchManager, Context], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Run four real analyzers behind a deterministic process barrier with zero busy timeout."""
    manager, context = project
    for number in range(24):
        for suffix, content in (
            ("json", '{"path":"/tmp/example"}'),
            ("yaml", "enabled: true\n"),
            ("log", "Sep 28 10:00:00 host app[1]: diagnostic event\n"),
        ):
            (Path(context.root) / f"{number}.{suffix}").write_text(content)
    for _ in range(3):
        manager.store.finish(manager.store.enqueue("source", {}), {"findings": []})
    run = manager.create(
        ResearchPlan(
            workers=4,
            tasks=tuple(
                TaskSpec(name, plugin=name, attempts=1)
                for name in ("config", "yaml", "strings", "logs")
            ),
        ),
        context,
    )
    manager.db.execute("PRAGMA busy_timeout=0")
    observer = sqlite3.connect(manager.base / "research.sqlite3", timeout=0)
    snapshot = observer.execute("SELECT id FROM jobs ORDER BY id")
    assert snapshot.fetchone() is not None
    original = persistence.apply_command
    calls = 0
    peak = 0
    imports_during_workers = 0
    writer_threads: set[int] = set()
    first_requests = 0

    class BarrierWriter(CheckpointWriter):
        """Require four independent processes to reach IPC before any can proceed."""

        async def _handle(
            self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            """The first request from each worker waits for its three peers."""
            nonlocal first_requests
            first_requests += 1
            if first_requests <= 4:
                async with asyncio.timeout(20):
                    await barrier.wait()
            await super()._handle(reader, writer)

    def observed(
        db: sqlite3.Connection, namespace: str, plugin: str, command: dict[str, Any]
    ) -> str | None:
        """Interleave real knowledge/checkpoint writes at command boundaries."""
        nonlocal calls, peak, imports_during_workers
        writer_threads.add(threading.get_ident())
        result = original(db, namespace, plugin, command)
        calls += 1
        if calls % 17 == 0:
            status = manager.progress.snapshot(run)
            peak = max(peak, status["running"])
            imports_during_workers += manager.aggregator.flush()
            manager.checkpoints.save(run, "concurrency-test")
        return result

    async def execute() -> dict[str, Any]:
        async with asyncio.timeout(60):
            return await manager.execute(run, context.root)

    barrier = asyncio.Barrier(4)
    monkeypatch.setattr("core.research.manager.CheckpointWriter", BarrierWriter)
    monkeypatch.setattr(persistence, "apply_command", observed)
    try:
        result = asyncio.run(execute())
        assert result["status"] == "completed", result
        assert result["completed"] == 4 and result["errors"] == 0
        assert calls > 300 and peak == 4 and imports_during_workers >= 3
        assert writer_threads == {threading.get_ident()}
        assert len(manager.store.jobs()) == 7
        assert (
            manager.db.execute("SELECT count(*) FROM IngestedJobs").fetchone()[0] == 7
        )
        assert (
            manager.db.execute("SELECT count(*) FROM PluginFileCache").fetchone()[0]
            == 168
        )
        assert {
            r[0] for r in manager.db.execute("SELECT status FROM PluginProgress")
        } == {"completed"}
        for row in manager.db.execute("SELECT result FROM jobs WHERE plugin<>'source'"):
            data = json.loads(row[0])
            assert data["statistics"]["errors"] == 0 and data["warnings"] == []
        processes = [
            e["details"]["pid"]
            for e in manager.timeline.recent(run, 1000)
            if e["event"] == "worker_process"
        ]
        assert len(set(processes)) == 4 and os.getpid() not in processes
        assert manager.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert manager.db.execute("PRAGMA foreign_key_check").fetchall() == []
        assert len(snapshot.fetchall()) == 2  # WAL reader kept its original snapshot.
        snapshot.close()
        assert observer.execute("SELECT count(*) FROM jobs").fetchone()[0] == 7
    finally:
        snapshot.close()
        observer.close()


def test_cancel_and_restart_reuses_acknowledged_cache(
    project: tuple[ResearchManager, Context],
) -> None:
    """Cancel after a committed file, reopen supervisor/endpoint and reuse its cache."""
    manager, context = project
    for name in ("a.json", "b.json"):
        (Path(context.root) / name).write_text('{"x":1}')
    reached = asyncio.Event()

    class BlockingConfig(ConfigAnalyzer):
        """Expose a deterministic cancellation point after the first file committed."""

        async def analyze(self, path: Path, options: dict[str, Any]) -> dict[str, Any]:
            """Block the second file until cancelled by the test."""
            if path.name == "b.json":
                reached.set()
                await asyncio.Future[None]()
            return await super().analyze(path, options)

    async def cancel() -> None:
        async with CheckpointWriter(manager.db) as writer:
            scoped = replace(
                context,
                task_id="resume",
                checkpoint_endpoint=writer.endpoint,
                checkpoint_token=writer.grant("resume", "config"),
            )
            task = asyncio.create_task(BlockingConfig().run(scoped))
            await asyncio.wait_for(reached.wait(), 10)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    asyncio.run(cancel())
    assert (
        manager.db.execute("SELECT status FROM PluginProgress").fetchone()[0]
        == "paused"
    )
    reopened = Store(manager.base / "research.sqlite3")

    async def resume() -> dict[str, object]:
        async with CheckpointWriter(reopened.db) as writer:
            scoped = replace(
                context,
                task_id="resume",
                checkpoint_endpoint=writer.endpoint,
                checkpoint_token=writer.grant("resume", "config"),
            )
            return await ConfigAnalyzer().run(scoped)

    try:
        result: Any = asyncio.run(resume())
        assert result["statistics"]["cached"] == 1
        assert result["statistics"]["processed"] == 2
        assert result["warnings"] == []
    finally:
        reopened.close()


def test_persistence_failure_is_not_a_file_warning(
    project: tuple[ResearchManager, Context], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Failure to persist analysis must fail the task, never report partial success."""
    _, context = project
    (Path(context.root) / "a.json").write_text("{}")
    original = CheckpointClient.request

    async def fail_put(
        self: CheckpointClient, operation: str, **values: Any
    ) -> str | None:
        """Inject a commit failure after file analysis actually completed."""
        if operation == "put":
            raise PersistenceError("controlled commit failure")
        return await original(self, operation, **values)

    monkeypatch.setattr(CheckpointClient, "request", fail_put)
    analyzer: FileAnalyzer = ConfigAnalyzer()
    with pytest.raises(PersistenceError, match="controlled commit"):
        asyncio.run(analyzer.run(context))


def test_shutdown_closes_incomplete_sender(
    project: tuple[ResearchManager, Context], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An incomplete frame cannot hold server shutdown until the read timeout expires."""
    manager, _ = project

    async def exercise() -> None:
        accepted = asyncio.Event()
        server = CheckpointWriter(manager.db)
        original = server._accept

        def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            """Observe registration without relying on wall-clock sleeps."""
            original(reader, writer)
            accepted.set()

        monkeypatch.setattr(server, "_accept", accept)
        async with asyncio.timeout(3):
            async with server:
                reader, connection = await asyncio.open_connection(
                    "127.0.0.1", int(server.endpoint)
                )
                await accepted.wait()
                connection.write(b"\x00")
                await connection.drain()
            # Linux can send RST when unread bytes are discarded; Windows sends EOF.
            with suppress(ConnectionResetError):
                assert await reader.read() == b""
            connection.close()
            with suppress(ConnectionResetError):
                await connection.wait_closed()
            assert not server.handlers
            assert server.consumer is not None and server.consumer.done()

    asyncio.run(exercise())


def test_dead_endpoint_never_falls_back_to_sqlite(
    project: tuple[ResearchManager, Context], tmp_path: Path
) -> None:
    """Supervisor loss fails the task instead of reintroducing an independent writer."""
    manager, context = project
    local_file = tmp_path / "forbidden-fallback.sqlite3"

    async def exercise() -> None:
        async with CheckpointWriter(manager.db) as writer:
            scoped = replace(
                context,
                checkpoint_endpoint=writer.endpoint,
                checkpoint_token=writer.grant("task", "config"),
                checkpoint_db=str(local_file),
            )
        client = CheckpointClient(scoped, "task", "config")
        try:
            with pytest.raises(PersistenceError):
                await asyncio.wait_for(
                    client.request("progress", status="running", progress="{}"), 3
                )
        finally:
            client.close()
        assert not local_file.exists()

    asyncio.run(exercise())
