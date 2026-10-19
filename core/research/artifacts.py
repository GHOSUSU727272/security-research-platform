"""Content-addressed research output publication through the existing artifact schema."""

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from analysis.knowledge_ingest import ingest
from core.knowledge import KnowledgeEngine
from core.research.state import ResearchTimeline
from reports.plugin_graph import graph_html


class ArtifactManager:
    """Store immutable bytes first, then publish their project-owned metadata."""

    def __init__(self, knowledge: KnowledgeEngine, base: Path) -> None:
        """Reuse project memory and the portable v0.2 attachment layout."""
        self.knowledge, self.base = knowledge, base
        (base / "artifacts").mkdir(exist_ok=True)

    def publish(
        self,
        name: str,
        content: bytes,
        category: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Write atomically and deduplicate identical content/category metadata."""
        digest = hashlib.sha256(content).hexdigest()
        relative = f"artifacts/{digest}"
        destination = self.base / relative
        if not destination.exists():
            fd, temporary = tempfile.mkstemp(dir=destination.parent)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, destination)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        with self.knowledge.db:
            metadata_key = hashlib.sha256(
                json.dumps(metadata or {}, sort_keys=True).encode()
            ).hexdigest()
            return self.knowledge._insert(
                "Artifacts",
                name,
                evidence={
                    **(metadata or {}),
                    "blob": relative,
                    "sha256": digest,
                    "bytes": len(content),
                    "category": category,
                },
                source_key=f"engine:{category}:{digest}:{metadata_key}",
            )


class ResultAggregator:
    """Publish exactly one legacy job per completed task and project it into knowledge."""

    def __init__(self, knowledge: KnowledgeEngine, artifacts: ArtifactManager) -> None:
        """Bind the existing knowledge projection and artifact writer."""
        self.knowledge, self.artifacts = knowledge, artifacts

    def complete(
        self, task: dict[str, Any], result: dict[str, object], duration: float
    ) -> None:
        """Commit task success and a corresponding result atomically before ingest."""
        import time

        payload = json.dumps(result, ensure_ascii=False)
        if task["plugin"] in ("callgraph", "cfg", "ghidra"):
            records = result.get("records", [])
            if isinstance(records, list):
                for record in records:
                    detail = record["analysis"]
                    name = f"{task['plugin']}: {record['path']}"
                    for category, content in (
                        ("graph-json", json.dumps(detail, ensure_ascii=False).encode()),
                        ("graph-html", graph_html(name, detail)),
                    ):
                        self.artifacts.publish(
                            name,
                            content,
                            category,
                            {"task_id": task["id"], "path": record["path"]},
                        )
        artifact = self.artifacts.publish(
            f"{task['task_key']} result",
            payload.encode(),
            "analysis-result",
            {"task_id": task["id"], "plugin": task["plugin"]},
        )
        db = self.knowledge.db
        with db:
            current = db.execute(
                "SELECT status FROM ResearchTasks WHERE id=?", (task["id"],)
            ).fetchone()
            if current[0] == "completed":
                return
            cursor = db.execute(
                "INSERT INTO jobs(plugin,context,status,attempts,result,created) VALUES(?,?,'done',?,?,?)",
                (
                    task["plugin"],
                    task["context"],
                    task["attempts"],
                    payload,
                    task["started_at"],
                ),
            )
            db.execute(
                "UPDATE ResearchTasks SET status='completed',job_id=?,duration=duration+?,finished_at=?,error=NULL,worker=NULL WHERE id=?",
                (cursor.lastrowid, duration, time.time(), task["id"]),
            )
            ResearchTimeline(db).record(
                task["run_id"],
                "task_completed",
                task["id"],
                {
                    "key": task["task_key"],
                    "job_id": cursor.lastrowid,
                    "artifact_id": artifact,
                },
                duration,
            )

    def flush(self) -> int:
        """Idempotently deliver durable results and link published run artifacts."""
        count = ingest(self.knowledge)
        # Existing ingest's source keys and fingerprints deduplicate discoveries.
        return count

    def report(self, run: str, progress: dict[str, Any]) -> str:
        """Archive a complete snapshot of run metadata, outcomes, notes and timeline."""
        db = self.knowledge.db
        report = {
            "progress": progress,
            "knowledge": self.knowledge.summary(),
            "tasks": [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM ResearchTasks WHERE run_id=?", (run,)
                )
            ],
            "notes": [
                self.knowledge.get(r[0]) for r in db.execute("SELECT id FROM Notes")
            ],
            "timeline": [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM ResearchEvents WHERE run_id=? ORDER BY id", (run,)
                )
            ],
        }
        artifact = self.artifacts.publish(
            "Research Engine report",
            json.dumps(report, ensure_ascii=False, indent=2).encode(),
            "research-report",
            {"run_id": run},
        )
        with db:
            self.knowledge._event(
                "research_engine_report", {"run_id": run, "artifact": artifact}
            )
        return artifact
