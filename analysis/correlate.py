"""Stable review identities and explainable cross-run correlations."""

import hashlib
import json
from typing import Any

from database.store import Store


def aggregate(store: Store) -> dict[str, Any]:
    """Deduplicate source candidates and compare consecutive matching commands."""
    found: dict[str, dict[str, Any]] = {}
    previous: dict[str, tuple[int, dict[str, Any]]] = {}
    comparisons: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    for row in store.results():
        context = json.loads(row["context"])
        result = json.loads(row["result"])
        coverage.append(
            {
                "job": row["id"],
                "root": context["root"],
                "files": len(result.get("files", [])),
                "warnings": result.get("warnings", []),
                "truncated": result.get("truncated", False),
            }
        )
        for item in result.get("findings", []):
            identity = json.dumps(
                [
                    context["root"],
                    item["rule"],
                    item["path"],
                    item["line"],
                    item["reason"],
                ]
            )
            fingerprint = hashlib.sha256(identity.encode()).hexdigest()
            if fingerprint not in found:
                found[fingerprint] = {
                    **item,
                    "fingerprint": fingerprint,
                    "root": context["root"],
                    "jobs": [],
                }
            found[fingerprint]["jobs"].append(row["id"])
        if row["plugin"] == "dynamic":
            key = json.dumps([context["root"], context["command"]])
            if key in previous:
                old_id, old = previous[key]
                changed = [
                    name
                    for name in ("stdout", "stderr")
                    if old[name]["sha256"] != result[name]["sha256"]
                ]
                if old["returncode"] != result["returncode"]:
                    changed.append("returncode")
                if changed:
                    comparisons.append(
                        {
                            "source": old_id,
                            "target": row["id"],
                            "root": context["root"],
                            "command": context["command"],
                            "changed": changed,
                            "priority": 1 if "returncode" in changed else 2,
                            "reason": "Behavior changed; inspect nondeterminism "
                            "and environment before concluding a bug",
                        }
                    )
            previous[key] = row["id"], result
    reviews = {
        r["fingerprint"]: dict(r) for r in store.db.execute("SELECT * FROM reviews")
    }
    for fingerprint, item in found.items():
        item["review"] = reviews.get(fingerprint, {"status": "new", "comment": ""})
        item["manual_check"] = (
            "Inspect the call site, trace inputs, and reproduce in isolation."
        )
    return {
        "summary": {"candidates": len(found), "behavior_changes": len(comparisons)},
        "findings": sorted(
            found.values(), key=lambda f: (f["priority"], f["path"], f["line"])
        ),
        "comparisons": comparisons,
        "jobs": store.jobs(),
        "coverage": coverage,
        "review_history": [
            dict(r) for r in store.db.execute("SELECT * FROM review_events ORDER BY id")
        ],
        "links": [dict(r) for r in store.db.execute("SELECT * FROM links")],
    }
