"""Transactional local persistence with bounded retry recovery."""

import json
import sqlite3
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from database.plugin_state import initialize_plugins


class Store:
    """Own a SQLite connection used on a single event-loop thread."""

    def __init__(self, path: Path) -> None:
        """Open the database and initialize the version-one schema."""
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=30)
        if self.db.execute("PRAGMA user_version").fetchone()[0] > 1:
            self.db.close()
            raise ValueError("Unsupported database schema version")
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY, plugin TEXT NOT NULL, context TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued', attempts INTEGER DEFAULT 0,
                lease REAL DEFAULT 0, error TEXT, result TEXT, created REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status, id);
            CREATE TABLE IF NOT EXISTS reviews (
                fingerprint TEXT PRIMARY KEY, status TEXT NOT NULL,
                comment TEXT NOT NULL, updated REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS links (
                source TEXT NOT NULL, target TEXT NOT NULL, reason TEXT NOT NULL,
                PRIMARY KEY(source, target)
            );
            CREATE TABLE IF NOT EXISTS review_events (
                id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL,
                status TEXT NOT NULL, comment TEXT NOT NULL, created REAL NOT NULL
            );
            PRAGMA user_version=1;
        """)

        initialize_plugins(self.db)

    def enqueue(self, plugin: str, context: dict[str, Any]) -> int:
        """Persist a new task before acknowledging it."""
        with self.db:
            cur = self.db.execute(
                "INSERT INTO jobs(plugin,context,created) VALUES(?,?,?)",
                (plugin, json.dumps(context), time.time()),
            )
        assert cur.lastrowid is not None
        return cur.lastrowid

    def claim(self, limit: int, lease: float) -> dict[str, Any] | None:
        """Recover expired tasks and atomically claim the next eligible task."""
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute(
                "UPDATE jobs SET status=CASE WHEN attempts>=? THEN 'failed' "
                "ELSE 'queued' END, error='Worker lease expired' "
                "WHERE status='running' AND lease<?",
                (limit, time.time()),
            )
            row = self.db.execute(
                "SELECT * FROM jobs WHERE status='queued' ORDER BY id LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            self.db.execute(
                "UPDATE jobs SET status='running', attempts=attempts+1, lease=? "
                "WHERE id=?",
                (time.time() + lease, row["id"]),
            )
        return dict(row)

    def heartbeat(self, job: int, lease: float) -> None:
        """Extend the active job lease."""
        with self.db:
            self.db.execute(
                "UPDATE jobs SET lease=? WHERE id=? AND status='running'",
                (time.time() + lease, job),
            )

    def finish(self, job: int, result: dict[str, object]) -> None:
        """Atomically commit output and successful completion."""
        with self.db:
            self.db.execute(
                "UPDATE jobs SET status='done', result=?, error=NULL WHERE id=?",
                (json.dumps(result, ensure_ascii=False), job),
            )

    def fail(self, job: int, error: str, limit: int) -> None:
        """Retry failures until the configured attempt budget is exhausted."""
        with self.db:
            self.db.execute(
                "UPDATE jobs SET status=CASE WHEN attempts>=? THEN 'failed' "
                "ELSE 'queued' END, error=? WHERE id=?",
                (limit, error, job),
            )

    def jobs(self) -> list[dict[str, Any]]:
        """Return task metadata without potentially large result payloads."""
        return [
            dict(r)
            for r in self.db.execute(
                "SELECT id,plugin,status,attempts,error,created FROM jobs ORDER BY id"
            )
        ]

    def results(self) -> Iterator[dict[str, Any]]:
        """Return completed result records for report generation."""
        for row in self.db.execute(
            "SELECT id,plugin,context,result FROM jobs WHERE status='done' ORDER BY id"
        ):
            yield dict(row)

    def review(self, fingerprint: str, status: str, comment: str) -> None:
        """Persist the latest human review state and comment."""
        if status not in {"new", "confirmed", "dismissed", "investigating"}:
            raise ValueError("Invalid review status")
        with self.db:
            self.db.execute(
                "INSERT INTO review_events(fingerprint,status,comment,created) "
                "VALUES(?,?,?,?)",
                (fingerprint, status, comment, time.time()),
            )
            self.db.execute(
                "INSERT OR REPLACE INTO reviews VALUES(?,?,?,?)",
                (fingerprint, status, comment, time.time()),
            )

    def close(self) -> None:
        """Release the database handle."""
        self.db.close()
