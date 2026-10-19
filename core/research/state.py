"""Timeline, progress and checkpoints sharing the project's transactional store."""

import json
import sqlite3
import time
from typing import Any


class ResearchTimeline:
    """Append ordered events inside the calling component's transaction."""

    def __init__(self, db: sqlite3.Connection) -> None:
        """Bind the existing project connection."""
        self.db = db

    def record(
        self,
        run: str,
        event: str,
        task: str | None = None,
        details: dict[str, Any] | None = None,
        duration: float | None = None,
    ) -> None:
        """Save event time, outcome and duration without creating nested commits."""
        self.db.execute(
            "INSERT INTO ResearchEvents(run_id,task_id,created_at,event,details,duration) "
            "VALUES(?,?,?,?,?,?)",
            (run, task, time.time(), event, json.dumps(details or {}), duration),
        )

    def recent(
        self, run: str, limit: int = 100, before: int | None = None
    ) -> list[dict[str, Any]]:
        """Page backwards through run events by monotonic integer cursor."""
        if not 1 <= limit <= 1000:
            raise ValueError("Timeline limit must be between 1 and 1000")
        rows = self.db.execute(
            "SELECT * FROM ResearchEvents WHERE run_id=? AND (? IS NULL OR id<?) "
            "ORDER BY id DESC LIMIT ?",
            (run, before, before, limit),
        )
        return [{**dict(row), "details": json.loads(row["details"])} for row in rows]


class ProgressTracker:
    """Compute project-run progress from committed task state, not UI counters."""

    def __init__(self, db: sqlite3.Connection) -> None:
        """Bind a project-scoped database handle."""
        self.db = db

    def snapshot(self, run: str) -> dict[str, Any]:
        """Return task counts, active runtime, throughput and supervisor freshness."""
        row = self.db.execute(
            "SELECT * FROM ResearchRuns WHERE id=?", (run,)
        ).fetchone()
        if row is None:
            raise ValueError("Unknown research run")
        counts = dict.fromkeys(
            ("pending", "running", "completed", "failed", "cancelled", "blocked"), 0
        )
        for task in self.db.execute(
            "SELECT status,count(*) n FROM ResearchTasks WHERE run_id=? GROUP BY status",
            (run,),
        ):
            counts[task["status"]] = task["n"]
        elapsed = row["elapsed"]
        fresh = (
            row["status"] == "running"
            and row["heartbeat"] is not None
            and time.time() - row["heartbeat"] < 10
        )
        if fresh:
            elapsed += max(0, time.time() - row["heartbeat"])
        plugin_progress = [
            {
                "task": p["task_key"],
                "plugin": p["plugin"],
                "status": p["status"],
                **json.loads(p["progress"]),
            }
            for p in self.db.execute(
                "SELECT t.task_key,p.* FROM PluginProgress p JOIN ResearchTasks t ON t.id=p.namespace WHERE t.run_id=?",
                (run,),
            )
        ]
        return {
            "run_id": run,
            "name": row["name"],
            "status": row["status"],
            "workers": row["workers"],
            "active_workers": counts["running"],
            "total": sum(counts.values()),
            **counts,
            "errors": counts["failed"] + counts["blocked"],
            "elapsed_seconds": round(elapsed, 3),
            "tasks_per_minute": round(60 * counts["completed"] / elapsed, 3)
            if elapsed > 0
            else 0,
            "supervisor_alive": fresh,
            "stop_requested": row["stop_requested"],
            "error": row["error"],
            "plugins": plugin_progress,
            "processed_files": sum(p.get("processed", 0) for p in plugin_progress),
            "file_errors": sum(p.get("errors", 0) for p in plugin_progress),
        }


class CheckpointManager:
    """Persist consistent run/task snapshots while preserving newer durable commits."""

    def __init__(self, db: sqlite3.Connection) -> None:
        """Use the same transaction domain as the task queue and event history."""
        self.db = db

    def save(self, run: str, reason: str) -> int:
        """Commit one recovery marker and task snapshot atomically."""
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT * FROM ResearchRuns WHERE id=?", (run,)
            ).fetchone()
            if row is None:
                raise ValueError("Unknown research run")
            snapshot = {
                "run": dict(row),
                "tasks": [
                    dict(r)
                    for r in self.db.execute(
                        "SELECT * FROM ResearchTasks WHERE run_id=? ORDER BY task_key",
                        (run,),
                    )
                ],
            }
            cursor = self.db.execute(
                "INSERT INTO ResearchCheckpoints(run_id,created_at,reason,snapshot) VALUES(?,?,?,?)",
                (run, time.time(), reason, json.dumps(snapshot)),
            )
            ResearchTimeline(self.db).record(
                run, "checkpoint", details={"reason": reason}
            )
            assert cursor.lastrowid is not None
            return cursor.lastrowid

    def list(self, run: str, limit: int = 100) -> list[dict[str, Any]]:
        """List checkpoint metadata without loading full task snapshots."""
        if not 1 <= limit <= 1000:
            raise ValueError("Checkpoint limit must be between 1 and 1000")
        return [
            dict(r)
            for r in self.db.execute(
                "SELECT id,run_id,created_at,reason FROM ResearchCheckpoints "
                "WHERE run_id=? ORDER BY id DESC LIMIT ?",
                (run, limit),
            )
        ]
