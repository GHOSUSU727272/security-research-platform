"""Knowledge lifecycle and graph traversal for one isolated project database."""

import json
import uuid
from collections import Counter, deque
from typing import Any

from database.knowledge import STATES, utcnow, validate
from database.store import Store


class KnowledgeEngine:
    """Own project knowledge operations with transactional history and stable IDs."""

    def __init__(self, store: Store) -> None:
        """Attach to a database already initialized by ProjectManager."""
        self.store = store
        self.db = store.db
        self.project_id: str = validate(self.db)["id"]

    def project(self) -> dict[str, Any]:
        """Return current metadata for this project only."""
        return dict(
            self.db.execute(
                "SELECT * FROM Projects WHERE id=?", (self.project_id,)
            ).fetchone()
        )

    def _insert(
        self,
        kind: str,
        name: str,
        status: str | None = None,
        priority: int = 2,
        evidence: dict[str, Any] | None = None,
        source_key: str | None = None,
    ) -> str:
        """Insert one validated entity inside the caller's transaction."""
        if kind not in STATES or not name.strip():
            raise ValueError("Unknown kind or empty name")
        state = status or STATES[kind][0]
        if evidence is not None and not isinstance(evidence, dict):
            raise ValueError("Evidence must be a JSON object")
        if kind == "Notes":
            evidence = {"category": "general", "body": name, **(evidence or {})}
        if (
            state not in STATES[kind]
            or type(priority) is not int
            or priority not in (1, 2, 3)
        ):
            raise ValueError("Invalid status or priority")
        if source_key is not None:
            row = self.db.execute(
                "SELECT id FROM KnowledgeEntities WHERE kind=? AND source_key=?",
                (kind, source_key),
            ).fetchone()
            if row:
                return str(row[0])
        identifier, now = str(uuid.uuid4()), utcnow()
        self.db.execute(
            "INSERT INTO KnowledgeEntities VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                identifier,
                self.project_id,
                kind,
                name,
                state,
                priority,
                now,
                now,
                json.dumps(evidence or {}, ensure_ascii=False),
                source_key,
            ),
        )
        self.db.execute(f"INSERT INTO {kind}(id) VALUES(?)", (identifier,))
        return identifier

    def _event(self, action: str, evidence: dict[str, Any]) -> None:
        """Append immutable-by-API history without recursively generating events."""
        self._insert("ResearchHistory", action, evidence=evidence)

    def add(
        self,
        kind: str,
        name: str,
        *,
        status: str | None = None,
        priority: int = 2,
        evidence: dict[str, Any] | None = None,
    ) -> str:
        """Create a knowledge node and atomically document its creation."""
        with self.db:
            identifier = self._insert(kind, name, status, priority, evidence)
            self._event("created", {"entity": identifier, "kind": kind})
        return identifier

    def get(self, identifier: str) -> dict[str, Any]:
        """Resolve an entity strictly within the current database."""
        row = self.db.execute(
            "SELECT * FROM KnowledgeEntities WHERE id=? AND project_id=?",
            (identifier, self.project_id),
        ).fetchone()
        if row is None:
            raise ValueError(f"Unknown project entity: {identifier}")
        result = dict(row)
        result["evidence"] = json.loads(result["evidence"])
        return result

    def entities(
        self, kind: str, status: str | None = None, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Page through knowledge ordered by research priority and creation time."""
        if kind not in STATES or not 1 <= limit <= 1000 or offset < 0:
            raise ValueError("Invalid kind or pagination")
        if status is not None and status not in STATES[kind]:
            raise ValueError("Invalid status for kind")
        rows = self.db.execute(
            "SELECT id FROM KnowledgeEntities WHERE kind=? AND (? IS NULL OR status=?) "
            "ORDER BY priority,created_at,id LIMIT ? OFFSET ?",
            (kind, status, status, limit, offset),
        )
        return [self.get(r[0]) for r in rows]

    def transition(self, identifier: str, status: str, reason: str) -> None:
        """Record a human decision; dismissed findings gain a FalsePositives node."""
        item = self.get(identifier)
        if item["kind"] == "ResearchHistory" or status not in STATES[item["kind"]]:
            raise ValueError("Invalid transition")
        if not reason.strip():
            raise ValueError("A decision reason is required")
        with self.db:
            self.db.execute(
                "UPDATE KnowledgeEntities SET status=?,updated_at=? WHERE id=?",
                (status, utcnow(), identifier),
            )
            self._event(
                "status_changed",
                {
                    "entity": identifier,
                    "from": item["status"],
                    "to": status,
                    "reason": reason,
                },
            )
            if item["kind"] == "Findings" and status == "dismissed":
                fp = self._insert(
                    "FalsePositives",
                    item["name"],
                    evidence={"reason": reason},
                    source_key=identifier,
                )
                GraphEngine(self)._connect(fp, identifier, "dismisses", reason)

    def note(
        self,
        body: str,
        category: str,
        priority: int,
        functions: list[str],
        libraries: list[str],
    ) -> str:
        """Store a dated note and validate typed links before any write."""
        if not body.strip() or not category.strip():
            raise ValueError("Note body and category are required")
        for kind, identifiers in (("Functions", functions), ("Libraries", libraries)):
            if any(self.get(i)["kind"] != kind for i in identifiers):
                raise ValueError(f"Note reference must point to {kind}")
        with self.db:
            identifier = self._insert(
                "Notes",
                body[:100],
                priority=priority,
                evidence={"body": body, "category": category},
            )
            graph = GraphEngine(self)
            for target in functions + libraries:
                graph._connect(identifier, target, "refers_to", category)
            self._event("note_added", {"entity": identifier})
        return identifier

    def summary(self) -> dict[str, Any]:
        """Compute transparent progress against inventoried functions and libraries."""
        counts = dict.fromkeys(STATES, 0)
        states: dict[str, dict[str, int]] = {}
        for row in self.db.execute(
            "SELECT kind,status,count(*) n FROM KnowledgeEntities GROUP BY kind,status"
        ):
            counts[row["kind"]] += row["n"]
            states.setdefault(row["kind"], {})[row["status"]] = row["n"]
        total = counts["Functions"] + counts["Libraries"]
        reviewed = sum(
            states.get(k, {}).get("reviewed", 0) for k in ("Functions", "Libraries")
        )
        false_positives = self.db.execute("""
            SELECT count(*) FROM FalsePositives fp
            WHERE NOT EXISTS (SELECT 1 FROM Relationships r
                              WHERE r.source_id=fp.id AND r.relation='dismisses')
               OR EXISTS (SELECT 1 FROM Relationships r JOIN KnowledgeEntities e
                          ON e.id=r.target_id WHERE r.source_id=fp.id
                          AND r.relation='dismisses' AND e.status='dismissed')
        """).fetchone()[0]
        return {
            "project": self.project(),
            "counts": counts,
            "states": states,
            "progress": {
                "reviewed": reviewed,
                "total": total,
                "percent": round(100 * reviewed / total, 1) if total else None,
            },
            "confirmed": states.get("Findings", {}).get("confirmed", 0),
            "false_positives": false_positives,
            "jobs": dict(Counter(j["status"] for j in self.store.jobs())),
        }


class GraphEngine:
    """Persist directed typed relationships and traverse the local knowledge graph."""

    def __init__(self, knowledge: KnowledgeEngine) -> None:
        """Reuse the project's existing transaction and connection."""
        self.knowledge = knowledge

    def _connect(self, source: str, target: str, relation: str, reason: str) -> str:
        """Validate endpoints and insert an idempotent edge in the current transaction."""
        self.knowledge.get(source)
        self.knowledge.get(target)
        if not relation.strip() or not reason.strip():
            raise ValueError("Relation and reason are required")
        db = self.knowledge.db
        identifier = str(uuid.uuid4())
        db.execute(
            "INSERT OR IGNORE INTO Relationships VALUES(?,?,?,?,?,?,?)",
            (
                identifier,
                self.knowledge.project_id,
                source,
                target,
                relation,
                reason,
                utcnow(),
            ),
        )
        row = db.execute(
            "SELECT id FROM Relationships WHERE source_id=? AND target_id=? AND relation=?",
            (source, target, relation),
        ).fetchone()
        return str(row[0])

    def connect(self, source: str, target: str, relation: str, reason: str) -> str:
        """Create an edge and record who/what was linked in project history."""
        with self.knowledge.db:
            identifier = self._connect(source, target, relation, reason)
            self.knowledge._event("linked", {"edge": identifier})
        return identifier

    def neighborhood(self, identifier: str, depth: int = 1) -> dict[str, Any]:
        """Traverse both directions up to depth five and at most 1,000 nodes."""
        self.knowledge.get(identifier)
        if not 1 <= depth <= 5:
            raise ValueError("Depth must be between 1 and 5")
        visited = {identifier}
        queue = deque([(identifier, 0)])
        edges: dict[str, dict[str, Any]] = {}
        truncated = False
        while queue:
            current, distance = queue.popleft()
            if distance >= depth:
                continue
            for row in self.knowledge.db.execute(
                "SELECT * FROM Relationships WHERE source_id=? OR target_id=?",
                (current, current),
            ):
                other = (
                    row["target_id"]
                    if row["source_id"] == current
                    else row["source_id"]
                )
                if other not in visited:
                    if len(visited) >= 1000:
                        truncated = True
                        continue
                    visited.add(other)
                    queue.append((other, distance + 1))
                edges[row["id"]] = dict(row)
        return {
            "nodes": [self.knowledge.get(i) for i in sorted(visited)],
            "edges": list(edges.values()),
            "truncated": truncated,
        }
