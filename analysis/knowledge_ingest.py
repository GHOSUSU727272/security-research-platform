"""Idempotent projection of existing job results into project knowledge."""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from typing import Any

from analysis.plugin_ingest import ingest_records
from core.knowledge import GraphEngine, KnowledgeEngine
from database.knowledge import utcnow


def pending_ids(db: sqlite3.Connection) -> Iterator[int]:
    """Page only IDs and close each snapshot before the caller starts writing."""
    with closing(db.execute("SELECT coalesce(max(id),0) FROM jobs")) as cursor:
        upper = cursor.fetchone()[0]
    after = 0
    while after < upper:
        with closing(
            db.execute(
                "SELECT j.id FROM jobs j LEFT JOIN IngestedJobs i ON i.job_id=j.id "
                "WHERE j.id>? AND j.id<=? AND j.status IN ('done','failed') "
                "AND (i.status IS NULL OR i.status<>j.status) ORDER BY j.id LIMIT 64",
                (after, upper),
            )
        ) as cursor:
            identifiers = [int(row[0]) for row in cursor.fetchall()]
        if not identifiers:
            return
        for identifier in identifiers:
            yield identifier
        after = identifiers[-1]


def ingest(knowledge: KnowledgeEngine) -> int:
    """Import terminal job states once, preserving all existing human decisions."""
    count = 0
    db = knowledge.db
    for identifier in pending_ids(db):
        with db:
            db.execute("BEGIN IMMEDIATE")
            with closing(
                db.execute("SELECT * FROM jobs WHERE id=?", (identifier,))
            ) as cursor:
                row = cursor.fetchone()
            if row is None or row["status"] not in {"done", "failed"}:
                continue
            seen = db.execute(
                "SELECT status FROM IngestedJobs WHERE job_id=?", (row["id"],)
            ).fetchone()
            if seen is not None and seen[0] == row["status"]:
                continue
            result: dict[str, Any] = json.loads(row["result"]) if row["result"] else {}
            experiment = knowledge._insert(
                "Experiments",
                f"{row['plugin']} run #{row['id']}",
                status=row["status"],
                source_key=f"job:{row['id']}",
                evidence={
                    "job_id": row["id"],
                    "error": row["error"],
                    "context": json.loads(row["context"]),
                    "created": row["created"],
                },
            )
            graph = GraphEngine(knowledge)
            ingest_records(knowledge, experiment, result)
            modules: dict[str, str] = {}
            for item in result.get("files", []):
                artifact = knowledge._insert(
                    "Artifacts",
                    item["path"],
                    evidence=item,
                    source_key=f"file:{item['path']}:{item.get('sha256', '')}",
                )
                module = knowledge._insert(
                    "Modules",
                    item["path"],
                    evidence={"path": item["path"]},
                    source_key=item["path"],
                )
                modules[item["path"]] = module
                graph._connect(
                    module, artifact, "represented_by", "Indexed file snapshot"
                )
                graph._connect(experiment, artifact, "observed", "Source index")
            for item in result.get("functions", []):
                key = f"{item['path']}:{item['name']}"
                function = knowledge._insert(
                    "Functions", item["name"], evidence=item, source_key=key
                )
                graph._connect(
                    experiment, function, "observed", "AST function inventory"
                )
                if item["path"] in modules:
                    graph._connect(
                        function, modules[item["path"]], "belongs_to", "AST declaration"
                    )
            for path, imports in result.get("dependencies", {}).items():
                for name in imports:
                    library = knowledge._insert(
                        "Libraries",
                        name or "<relative import>",
                        evidence={
                            "provenance": "Python import; installed version unknown"
                        },
                        source_key=name,
                    )
                    if path in modules:
                        graph._connect(
                            modules[path],
                            library,
                            "imports",
                            "Syntactic import declaration",
                        )
            for item in result.get("findings", []):
                key = json.dumps(
                    [item["rule"], item["path"], item["line"], item["reason"]]
                )
                finding = knowledge._insert(
                    "Findings",
                    item["reason"],
                    priority=item["priority"],
                    evidence=item,
                    source_key=key,
                )
                location = knowledge._insert(
                    "InterestingLocations",
                    f"{item['path']}:{item['line']}",
                    priority=item["priority"],
                    evidence=item,
                    source_key=key,
                )
                graph._connect(
                    finding, location, "located_at", "Manual review candidate"
                )
                graph._connect(
                    experiment,
                    finding,
                    "observed",
                    "Static heuristic, not confirmation",
                )
                if item["path"] in modules:
                    graph._connect(
                        location,
                        modules[item["path"]],
                        "belongs_to",
                        "Indexed source path",
                    )
            if row["plugin"] == "dynamic" and result:
                with closing(
                    db.execute(
                        "SELECT id,context,result FROM jobs WHERE plugin='dynamic' "
                        "AND status='done' AND id<? ORDER BY id DESC",
                        (row["id"],),
                    )
                ) as prior:
                    context = json.loads(row["context"])
                    for old in prior:
                        old_context = json.loads(old["context"])
                        if any(
                            old_context.get(k) != context.get(k)
                            for k in ("root", "command")
                        ):
                            continue
                        before = json.loads(old["result"])
                        changes = [
                            key
                            for key in ("stdout", "stderr")
                            if before[key]["sha256"] != result[key]["sha256"]
                        ]
                        if before["returncode"] != result["returncode"]:
                            changes.append("returncode")
                        if changes:
                            finding = knowledge._insert(
                                "Findings",
                                "Dynamic behavior changed",
                                priority=1 if "returncode" in changes else 2,
                                evidence={
                                    "changes": changes,
                                    "before_job": old["id"],
                                    "after_job": row["id"],
                                    "reason": "Check nondeterminism manually",
                                },
                                source_key=f"dynamic:{old['id']}:{row['id']}",
                            )
                            graph._connect(
                                experiment,
                                finding,
                                "observed",
                                "Compared matching command runs",
                            )
                        break
            knowledge._event(
                "research_run",
                {
                    "job_id": row["id"],
                    "experiment": experiment,
                    "status": row["status"],
                },
            )
            db.execute(
                "INSERT OR REPLACE INTO IngestedJobs VALUES(?,?)",
                (row["id"], row["status"]),
            )
            db.execute(
                "UPDATE Projects SET last_researched_at=? WHERE id=?",
                (utcnow(), knowledge.project_id),
            )
        count += 1
    return count
