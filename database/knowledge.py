"""Project-scoped knowledge schema with referentially valid graph endpoints."""

import sqlite3
from datetime import datetime, timezone
from typing import Any

STATES: dict[str, tuple[str, ...]] = {
    "Artifacts": ("unreviewed", "reviewed"),
    "Functions": ("unreviewed", "reviewed"),
    "Libraries": ("unreviewed", "reviewed"),
    "Modules": ("unreviewed", "reviewed"),
    "Findings": ("candidate", "confirmed", "dismissed"),
    "Hypotheses": ("open", "testing", "confirmed", "rejected"),
    "Experiments": ("planned", "running", "done", "failed"),
    "InterestingLocations": ("open", "reviewed"),
    "FalsePositives": ("documented",),
    "ResearchHistory": ("recorded",),
    "Notes": ("active", "archived"),
}


def utcnow() -> str:
    """Return a timezone-qualified UTC timestamp portable between machines."""
    return datetime.now(timezone.utc).isoformat()


def initialize(db: sqlite3.Connection, project: dict[str, Any]) -> None:
    """Add the knowledge schema alongside untouched version-one queue tables."""
    db.executescript("""
        CREATE TABLE IF NOT EXISTS KnowledgeSchema(version INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS Projects(
            id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL,
            product TEXT NOT NULL, product_version TEXT NOT NULL,
            created_at TEXT NOT NULL, last_researched_at TEXT,
            status TEXT NOT NULL CHECK(status IN ('active','paused','completed'))
        );
        CREATE TABLE IF NOT EXISTS KnowledgeEntities(
            id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES Projects(id),
            kind TEXT NOT NULL, name TEXT NOT NULL, status TEXT NOT NULL,
            priority INTEGER NOT NULL CHECK(priority BETWEEN 1 AND 3),
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            evidence TEXT NOT NULL, source_key TEXT,
            UNIQUE(project_id,kind,source_key), UNIQUE(id,project_id)
        );
        CREATE INDEX IF NOT EXISTS knowledge_kind_status
            ON KnowledgeEntities(kind,status,priority);
        CREATE TABLE IF NOT EXISTS Relationships(
            id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES Projects(id),
            source_id TEXT NOT NULL, target_id TEXT NOT NULL,
            relation TEXT NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL,
            FOREIGN KEY(source_id,project_id) REFERENCES KnowledgeEntities(id,project_id),
            FOREIGN KEY(target_id,project_id) REFERENCES KnowledgeEntities(id,project_id),
            UNIQUE(source_id,target_id,relation)
        );
        CREATE TABLE IF NOT EXISTS IngestedJobs(
            job_id INTEGER PRIMARY KEY REFERENCES jobs(id), status TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS relationships_target ON Relationships(target_id);
    """)
    for kind in STATES:
        # Identifiers come exclusively from the fixed schema allowlist.
        db.execute(
            f"CREATE TABLE IF NOT EXISTS {kind}("
            "id TEXT PRIMARY KEY REFERENCES KnowledgeEntities(id) ON DELETE CASCADE)"
        )
    with db:
        if db.execute("SELECT count(*) FROM KnowledgeSchema").fetchone()[0] == 0:
            db.execute("INSERT INTO KnowledgeSchema VALUES(1)")
        if not db.execute("SELECT 1 FROM Projects").fetchone():
            db.execute(
                "INSERT INTO Projects VALUES(?,?,?,?,?,?,?,?)",
                (
                    project["id"],
                    project["name"],
                    project["description"],
                    project["product"],
                    project["product_version"],
                    project["created_at"],
                    None,
                    "active",
                ),
            )


def validate(db: sqlite3.Connection) -> dict[str, Any]:
    """Check the supported schema and single-project ownership invariants."""
    versions = [r[0] for r in db.execute("SELECT version FROM KnowledgeSchema")]
    if versions != [1]:
        raise ValueError("Unsupported knowledge schema")
    rows = db.execute("SELECT * FROM Projects").fetchall()
    if len(rows) != 1:
        raise ValueError("A project database must contain exactly one project")
    project = dict(rows[0])
    if not project["name"].strip() or project["status"] not in {
        "active",
        "paused",
        "completed",
    }:
        raise ValueError("Invalid project metadata")
    if db.execute("PRAGMA foreign_key_check").fetchone():
        raise ValueError("Invalid graph or project references")
    for row in db.execute("SELECT * FROM KnowledgeEntities"):
        if row["project_id"] != project["id"] or row["kind"] not in STATES:
            raise ValueError("Invalid entity ownership or kind")
        if row["status"] not in STATES[row["kind"]] or row["priority"] not in (1, 2, 3):
            raise ValueError("Invalid entity state")
        if not db.execute(
            f"SELECT 1 FROM {row['kind']} WHERE id=?", (row["id"],)
        ).fetchone():
            raise ValueError("Missing entity membership")
    for kind in STATES:
        if db.execute(
            f"SELECT 1 FROM {kind} t JOIN KnowledgeEntities e ON e.id=t.id "
            "WHERE e.kind<>? LIMIT 1",
            (kind,),
        ).fetchone():
            raise ValueError("Entity membership kind mismatch")
    return project
