"""Behavioral regression coverage for queue, evidence and subprocess limits."""

import asyncio
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

from analysis.correlate import aggregate
from analysis.source import SourcePlugin
from core.config import Settings
from core.locking import scheduler_lock
from core.models import Context
from core.scheduler import Scheduler
from database.store import Store
from dynamic.runner import DynamicPlugin
from reports.export import export


def test_queue_recovery(tmp_path: Path) -> None:
    """Expired jobs recover across connection close and obey retry limits."""
    path = tmp_path / "db"
    store = Store(path)
    job = store.enqueue("source", {})
    assert store.claim(2, -1)["id"] == job  # type: ignore[index]
    store.close()
    store = Store(path)
    assert store.claim(2, -1)["id"] == job  # type: ignore[index]
    assert store.claim(2, 30) is None
    assert store.jobs()[0]["status"] == "failed"
    store.close()


def test_source_and_reports(tmp_path: Path) -> None:
    """Duplicate scans retain history while presenting one review identity."""
    (tmp_path / "code.py").write_text("def f(x):\n    return eval(x)\n")
    (tmp_path / "broken.py").write_text("def !!!")
    context = Context(str(tmp_path), 4096, ())
    result = asyncio.run(SourcePlugin().run(context))
    assert len(result["findings"]) == 1  # type: ignore[arg-type]
    assert result["warnings"]
    store = Store(tmp_path / "db")
    for _ in range(2):
        job = store.enqueue("source", asdict(context))
        store.finish(job, result)
    report = aggregate(store)
    assert report["summary"]["candidates"] == 1
    finding = report["findings"][0]
    store.review(finding["fingerprint"], "investigating", "<script>alert(1)</script>")
    export(aggregate(store), tmp_path / "report")
    content = (tmp_path / "report/report.html").read_text(encoding="utf-8")
    assert "<script>" not in content
    assert "&lt;script&gt;" in content
    assert json.loads((tmp_path / "report/report.json").read_text())["findings"]
    store.close()


def test_dynamic_output_limit(tmp_path: Path) -> None:
    """Pipe draining completes even when output exceeds the retained prefix."""
    context = Context(
        str(tmp_path), 4096, (), (sys.executable, "-c", "print('x' * 100000)"), 100
    )
    result = asyncio.run(DynamicPlugin().run(context))
    assert result["returncode"] == 0
    output = result["stdout"]
    assert isinstance(output, dict)
    assert output["truncated"]
    assert len(output["text"]) == 100


def test_scheduler_failure_isolation(tmp_path: Path) -> None:
    """A broken plugin reaches its retry budget without blocking valid jobs."""
    store = Store(tmp_path / "db")
    context = asdict(Context(str(tmp_path), 1024, ()))
    store.enqueue("missing", context)
    store.enqueue("source", context)
    settings = Settings(str(tmp_path), attempts=2)
    asyncio.run(Scheduler(store, settings, {"source": SourcePlugin()}).run())
    jobs = store.jobs()
    assert jobs[0]["status"] == "failed"
    assert jobs[0]["attempts"] == 2
    assert jobs[1]["status"] == "done"
    store.close()


def test_timeout(tmp_path: Path) -> None:
    """Timed-out subprocesses are stopped and the task records failure."""
    store = Store(tmp_path / "db")
    context = Context(
        str(tmp_path), 1024, (), (sys.executable, "-c", "import time; time.sleep(30)")
    )
    store.enqueue("dynamic", asdict(context))
    asyncio.run(
        Scheduler(
            store,
            Settings(str(tmp_path), timeout=1, attempts=1),
            {"dynamic": DynamicPlugin()},
        ).run()
    )
    assert store.jobs()[0]["status"] == "failed"
    store.close()


def test_config_rejects_invalid_values(tmp_path: Path) -> None:
    """Reject coercible but invalid configuration types and unknown keys."""
    path = tmp_path / "config.yaml"
    for tail in (
        "workers: true",
        "workers: 0",
        "unknown: 1",
        "command: echo",
        "allow_dynamic: 'false'",
    ):
        path.write_text("root: .\n" + tail)
        with pytest.raises(ValueError):
            Settings.load(path)


def test_scheduler_lock(tmp_path: Path) -> None:
    """Reject a concurrent scheduler and release its lock after exit."""
    path = tmp_path / "lock"
    with scheduler_lock(path):
        with pytest.raises(OSError):
            with scheduler_lock(path):
                pass
    with scheduler_lock(path):
        pass


def test_dynamic_comparison_and_review_history(tmp_path: Path) -> None:
    """Compare only identical scopes and retain each human review event."""
    store = Store(tmp_path / "db")
    context = asdict(Context(str(tmp_path), 4096, (), ("test",)))
    for code in (0, 1):
        job = store.enqueue("dynamic", context)
        store.finish(
            job,
            {
                "returncode": code,
                "stdout": {"sha256": "same"},
                "stderr": {"sha256": "same"},
            },
        )
    report = aggregate(store)
    assert report["comparisons"][0]["changed"] == ["returncode"]
    assert report["comparisons"][0]["priority"] == 1
    store.review("example", "investigating", "first note")
    store.review("example", "dismissed", "reproduced expected behavior")
    assert len(aggregate(store)["review_history"]) == 2
    store.close()


def test_source_bounds(tmp_path: Path) -> None:
    """Skip large files and excluded subtrees without parsing their contents."""
    (tmp_path / "large.py").write_text("eval('1')" * 100)
    ignored = tmp_path / "ignored"
    ignored.mkdir()
    (ignored / "hidden.py").write_text("eval('1')")
    result = asyncio.run(SourcePlugin().run(Context(str(tmp_path), 20, ("ignored",))))
    assert result["findings"] == []
    assert len(result["files"]) == 1  # type: ignore[arg-type]


def test_future_schema_rejected(tmp_path: Path) -> None:
    """Do not overwrite a newer database schema version."""
    store = Store(tmp_path / "db")
    store.db.execute("PRAGMA user_version=99")
    store.close()
    with pytest.raises(ValueError, match="schema"):
        Store(tmp_path / "db")


@pytest.mark.skipif(os.name != "posix", reason="Linux symlink semantics")
def test_symlink_scope(tmp_path: Path) -> None:
    """Do not traverse linked files or directories outside the target."""
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "secret.py"
    outside.write_text("eval('1')")
    (root / "link.py").symlink_to(outside)
    result = asyncio.run(SourcePlugin().run(Context(str(root), 4096, ())))
    assert result["files"] == []
