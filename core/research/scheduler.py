"""Priority DAG scheduling, retry policy and crash recovery."""

import json
import sqlite3
import time
from typing import Any

from core.research.state import ResearchTimeline


class TaskScheduler:
    """Claim ready tasks atomically and propagate terminal dependency failures."""

    def __init__(self, db: sqlite3.Connection, run: str) -> None:
        """Scope all scheduling operations to one research run."""
        self.db, self.run = db, run
        self.timeline = ResearchTimeline(db)

    def propagate(self) -> None:
        """Mark descendants of failed/cancelled/blocked prerequisites as blocked."""
        while True:
            rows = self.db.execute(
                """
                SELECT t.id FROM ResearchTasks t WHERE t.run_id=? AND t.status='pending'
                AND EXISTS(SELECT 1 FROM ResearchDependencies d JOIN ResearchTasks p ON p.id=d.depends_on
                           WHERE d.task_id=t.id AND p.status IN ('failed','cancelled','blocked'))
            """,
                (self.run,),
            ).fetchall()
            if not rows:
                return
            for row in rows:
                self.db.execute(
                    "UPDATE ResearchTasks SET status='blocked',error='Dependency did not complete',finished_at=? WHERE id=?",
                    (time.time(), row[0]),
                )
                self.timeline.record(self.run, "task_blocked", row[0])

    def claim(self, worker: str) -> dict[str, Any] | None:
        """Choose the highest-priority dependency-ready task and debit its attempt."""
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            state = self.db.execute(
                "SELECT status,stop_requested FROM ResearchRuns WHERE id=?", (self.run,)
            ).fetchone()
            if state["status"] != "running" or state["stop_requested"]:
                return None
            self.propagate()
            row = self.db.execute(
                """
                SELECT t.* FROM ResearchTasks t WHERE t.run_id=? AND t.status='pending'
                AND t.available_at<=? AND t.cancel_requested=0
                AND NOT EXISTS(SELECT 1 FROM ResearchDependencies d JOIN ResearchTasks p ON p.id=d.depends_on
                               WHERE d.task_id=t.id AND p.status<>'completed')
                ORDER BY t.priority,t.task_key LIMIT 1
            """,
                (self.run, time.time()),
            ).fetchone()
            if row is None:
                return None
            now = time.time()
            self.db.execute(
                "UPDATE ResearchTasks SET status='running',attempts=attempts+1,worker=?,started_at=?,finished_at=NULL WHERE id=?",
                (worker, now, row["id"]),
            )
            self.timeline.record(
                self.run,
                "task_started",
                row["id"],
                {
                    "key": row["task_key"],
                    "stage": row["stage"],
                    "plugin": row["plugin"],
                    "attempt": row["attempts"] + 1,
                    "worker": worker,
                },
            )
            return {**dict(row), "attempts": row["attempts"] + 1, "started_at": now}

    def failure(self, task: str, error: str, duration: float) -> None:
        """Retry with bounded backoff or publish a final failure to the legacy result stream."""
        with self.db:
            row = self.db.execute(
                "SELECT * FROM ResearchTasks WHERE id=? AND run_id=?", (task, self.run)
            ).fetchone()
            retry = row["attempts"] < row["max_attempts"]
            status = "pending" if retry else "failed"
            job_id = row["job_id"]
            if not retry and job_id is None:
                cursor = self.db.execute(
                    "INSERT INTO jobs(plugin,context,status,attempts,error,created) VALUES(?,?,'failed',?,?,?)",
                    (
                        row["plugin"],
                        row["context"],
                        row["attempts"],
                        error,
                        row["started_at"] or time.time(),
                    ),
                )
                job_id = cursor.lastrowid
            self.db.execute(
                "UPDATE ResearchTasks SET status=?,error=?,duration=duration+?,finished_at=?,available_at=?,worker=NULL,job_id=? WHERE id=?",
                (
                    status,
                    error,
                    duration,
                    time.time(),
                    time.time() + min(30, 0.2 * 2 ** min(row["attempts"], 7)),
                    job_id,
                    task,
                ),
            )
            self.timeline.record(
                self.run,
                "task_retry" if retry else "task_failed",
                task,
                {"error": error},
                duration,
            )
            self.propagate()

    def interrupted(self, task: str, duration: float) -> None:
        """Return paused attempts to pending; honour explicit cancellation permanently."""
        with self.db:
            row = self.db.execute(
                "SELECT cancel_requested FROM ResearchTasks WHERE id=? AND run_id=?",
                (task, self.run),
            ).fetchone()
            cancel = bool(row[0])
            self.db.execute(
                "UPDATE ResearchTasks SET status=?,attempts=max(0,attempts-1),worker=NULL,duration=duration+? WHERE id=?",
                ("cancelled" if cancel else "pending", duration, task),
            )
            self.timeline.record(
                self.run,
                "task_cancelled" if cancel else "task_paused",
                task,
                duration=duration,
            )
            self.propagate()

    def recover(self, root: str) -> None:
        """Recover abandoned running attempts after acquiring the exclusive OS lock."""
        for row in self.db.execute(
            "SELECT * FROM ResearchTasks WHERE run_id=? AND status='running'",
            (self.run,),
        ).fetchall():
            if row["cancel_requested"]:
                self.interrupted(row["id"], 0)
                continue
            self.failure(row["id"], "Supervisor interrupted before task commit", 0)
        with self.db:
            for row in self.db.execute(
                "SELECT id,context FROM ResearchTasks WHERE run_id=? AND status='pending'",
                (self.run,),
            ):
                context = json.loads(row["context"])
                if context["root"] != root:
                    self.timeline.record(
                        self.run,
                        "target_rebound",
                        row["id"],
                        {"old": context["root"], "new": root},
                    )
                    context["root"] = root
                    self.db.execute(
                        "UPDATE ResearchTasks SET context=? WHERE id=?",
                        (json.dumps(context), row["id"]),
                    )
            self.propagate()
