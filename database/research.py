"""Additive durable orchestration schema, independent of the legacy jobs queue."""

import math
import sqlite3

ENGINE_TABLES = (
    "ResearchSchema",
    "ResearchRuns",
    "ResearchTasks",
    "ResearchDependencies",
    "ResearchEvents",
    "ResearchCheckpoints",
)


def initialize_research(db: sqlite3.Connection) -> None:
    """Install version-one engine tables without changing existing table contracts."""
    db.executescript("""
        CREATE TABLE IF NOT EXISTS ResearchSchema(version INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS ResearchRuns(
            id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES Projects(id),
            name TEXT NOT NULL, status TEXT NOT NULL, created_at REAL NOT NULL,
            started_at REAL, finished_at REAL, heartbeat REAL,
            elapsed REAL NOT NULL DEFAULT 0, workers INTEGER NOT NULL,
            checkpoint_seconds REAL NOT NULL, options TEXT NOT NULL,
            stop_requested TEXT NOT NULL DEFAULT '', error TEXT
        );
        CREATE TABLE IF NOT EXISTS ResearchTasks(
            id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES ResearchRuns(id),
            task_key TEXT NOT NULL, stage TEXT NOT NULL, plugin TEXT NOT NULL,
            priority INTEGER NOT NULL, context TEXT NOT NULL, status TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL,
            timeout REAL NOT NULL, available_at REAL NOT NULL DEFAULT 0,
            started_at REAL, finished_at REAL, duration REAL NOT NULL DEFAULT 0,
            worker TEXT, error TEXT, job_id INTEGER REFERENCES jobs(id),
            cancel_requested INTEGER NOT NULL DEFAULT 0,
            UNIQUE(run_id,task_key), UNIQUE(id,run_id)
        );
        CREATE INDEX IF NOT EXISTS research_task_queue
            ON ResearchTasks(run_id,status,priority,available_at);
        CREATE TABLE IF NOT EXISTS ResearchDependencies(
            run_id TEXT NOT NULL, task_id TEXT NOT NULL, depends_on TEXT NOT NULL,
            PRIMARY KEY(task_id,depends_on),
            FOREIGN KEY(task_id,run_id) REFERENCES ResearchTasks(id,run_id),
            FOREIGN KEY(depends_on,run_id) REFERENCES ResearchTasks(id,run_id)
        );
        CREATE TABLE IF NOT EXISTS ResearchEvents(
            id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES ResearchRuns(id),
            task_id TEXT REFERENCES ResearchTasks(id), created_at REAL NOT NULL,
            event TEXT NOT NULL, details TEXT NOT NULL, duration REAL
        );
        CREATE INDEX IF NOT EXISTS research_events_run ON ResearchEvents(run_id,id);
        CREATE TABLE IF NOT EXISTS ResearchCheckpoints(
            id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES ResearchRuns(id),
            created_at REAL NOT NULL, reason TEXT NOT NULL, snapshot TEXT NOT NULL
        );
    """)
    with db:
        versions = [r[0] for r in db.execute("SELECT version FROM ResearchSchema")]
        if not versions:
            db.execute("INSERT INTO ResearchSchema VALUES(1)")
        elif versions != [1]:
            raise ValueError("Unsupported research engine schema")


def validate_research(db: sqlite3.Connection) -> None:
    """Reject invalid imported run/task states, options and graph ownership."""
    if [r[0] for r in db.execute("SELECT version FROM ResearchSchema")] != [1]:
        raise ValueError("Unsupported research schema")
    if db.execute("PRAGMA foreign_key_check").fetchone():
        raise ValueError("Invalid research references")
    for row in db.execute("SELECT * FROM ResearchRuns"):
        if row["status"] not in {
            "ready",
            "running",
            "paused",
            "completed",
            "failed",
            "cancelled",
        }:
            raise ValueError("Invalid research state")
        if (
            not 1 <= row["workers"] <= 32
            or not math.isfinite(row["checkpoint_seconds"])
            or row["checkpoint_seconds"] <= 0
        ):
            raise ValueError("Invalid research limits")
    for row in db.execute("SELECT * FROM ResearchTasks"):
        if row["status"] not in {
            "pending",
            "running",
            "completed",
            "failed",
            "cancelled",
            "blocked",
        }:
            raise ValueError("Invalid task state")
        if (
            row["priority"] not in (1, 2, 3)
            or not math.isfinite(row["timeout"])
            or row["timeout"] <= 0
            or row["max_attempts"] < 1
        ):
            raise ValueError("Invalid task limits")
    if db.execute(
        "SELECT 1 FROM ResearchEvents e JOIN ResearchTasks t ON e.task_id=t.id WHERE e.run_id<>t.run_id LIMIT 1"
    ).fetchone():
        raise ValueError("Timeline task belongs to another run")
    for run in db.execute("SELECT id FROM ResearchRuns"):
        graph: dict[str, set[str]] = {
            r[0]: set()
            for r in db.execute(
                "SELECT id FROM ResearchTasks WHERE run_id=?", (run[0],)
            )
        }
        if not 1 <= len(graph) <= 10000:
            raise ValueError("Invalid research task count")
        for task, dependency in db.execute(
            "SELECT task_id,depends_on FROM ResearchDependencies WHERE run_id=?",
            (run[0],),
        ):
            graph[task].add(dependency)
        while graph:
            ready = {key for key, dependencies in graph.items() if not dependencies}
            if not ready:
                raise ValueError("Research dependency cycle")
            graph = {
                key: dependencies - ready
                for key, dependencies in graph.items()
                if key not in ready
            }
