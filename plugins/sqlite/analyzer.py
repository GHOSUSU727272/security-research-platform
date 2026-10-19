"""Read-only SQLite schema introspection without executing target SQL objects."""

import sqlite3
from pathlib import Path
from typing import Any

from plugins.common import FileAnalyzer, positive


class SQLiteAnalyzer(FileAnalyzer):
    """Inventory schema, columns, indexes, triggers and views with query budgets."""

    name = "sqlite"

    def accepts(self, path: Path, options: dict[str, Any]) -> bool:
        """Recognize ordinary SQLite databases by file magic."""
        with path.open("rb") as stream:
            return stream.read(16) == b"SQLite format 3\x00"

    async def analyze(self, path: Path, options: dict[str, Any]) -> dict[str, Any]:
        """Inspect schema and pragma metadata, never SELECT from application views."""
        limit = positive(options, "max_records", 10000)
        budget = positive(options, "instruction_budget", 1000000)
        db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
        db.row_factory = sqlite3.Row
        ticks = 0

        def interrupt() -> int:
            """Abort unusually costly schema queries instead of hanging indefinitely."""
            nonlocal ticks
            ticks += 1000
            return int(ticks > budget)

        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            db.set_progress_handler(interrupt, 1000)
            objects = [
                dict(r)
                for r in db.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name LIMIT ?",
                    (limit + 1,),
                )
            ]
            truncated = len(objects) > limit
            objects = objects[:limit]
            for item in objects:
                quoted = '"' + item["name"].replace('"', '""') + '"'
                if item["type"] == "table" and not (
                    item["sql"] or ""
                ).upper().startswith("CREATE VIRTUAL TABLE"):
                    item["columns"] = [
                        dict(r) for r in db.execute(f"PRAGMA table_xinfo({quoted})")
                    ]
                    item["foreign_keys"] = [
                        dict(r)
                        for r in db.execute(f"PRAGMA foreign_key_list({quoted})")
                    ]
                if item["type"] == "index":
                    item["columns"] = [
                        dict(r) for r in db.execute(f"PRAGMA index_xinfo({quoted})")
                    ]
            return {
                "schema": objects,
                "user_version": db.execute("PRAGMA user_version").fetchone()[0],
                "application_id": db.execute("PRAGMA application_id").fetchone()[0],
                "page_count": db.execute("PRAGMA page_count").fetchone()[0],
                "truncated": truncated,
            }
        finally:
            db.close()
