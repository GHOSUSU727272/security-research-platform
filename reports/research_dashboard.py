"""Standalone offline dashboard for a research engine run."""

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.research.manager import ResearchManager
from plugins import registry


def research_dashboard(
    manager: ResearchManager, run: str | None, destination: Path
) -> None:
    """Render escaped progress and recent timeline without executing scripts."""
    progress: dict[str, Any] = (
        manager.progress.snapshot(run)
        if run
        else {
            "name": "No research started",
            "status": "idle",
            "workers": 0,
            "active_workers": 0,
            "completed": 0,
            "pending": 0,
            "errors": 0,
            "tasks_per_minute": 0,
            "elapsed_seconds": 0,
            "total": 0,
            "supervisor_alive": False,
        }
    )
    cards = {
        "Status": progress["status"],
        "Configured workers": progress["workers"],
        "Active workers": progress["active_workers"],
        "Completed": progress["completed"],
        "Waiting": progress["pending"],
        "Errors / blocked": progress["errors"],
        "Tasks / minute": progress["tasks_per_minute"],
        "Active seconds": progress["elapsed_seconds"],
    }
    tiles = "".join(
        f"<article><strong>{html.escape(str(value))}</strong><span>{name}</span></article>"
        for name, value in cards.items()
    )
    events = []
    plugin_rows = []
    scheduled: set[str] = set()
    for task in (
        manager.db.execute(
            "SELECT t.*,j.result FROM ResearchTasks t LEFT JOIN jobs j ON j.id=t.job_id WHERE t.run_id=? ORDER BY t.task_key",
            (run,),
        )
        if run
        else []
    ):
        state = manager.db.execute(
            "SELECT status,progress FROM PluginProgress WHERE namespace=? AND plugin=?",
            (task["id"], task["plugin"]),
        ).fetchone()
        scheduled.add(task["plugin"])
        result = json.loads(task["result"] or "{}")
        stats = json.loads(state["progress"]) if state else result.get("statistics", {})
        status = f"{task['status']} / {state['status']}" if state else task["status"]
        plugin_rows.append(
            "<tr>"
            + "".join(
                f"<td>{html.escape(str(v))}</td>"
                for v in (
                    task["task_key"],
                    task["plugin"],
                    status,
                    round(task["duration"] or stats.get("elapsed_seconds", 0), 2),
                    stats.get("processed", 0),
                    len(result.get("records", [])),
                    stats.get("errors", 0),
                )
            )
            + "<td><details><summary>Statistics and diagnostics</summary><pre>"
            + html.escape(
                json.dumps(
                    {
                        "statistics": stats,
                        "warnings": result.get("warnings", []),
                        "error": task["error"],
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            + "</pre></details></td></tr>"
        )
    for name in sorted(set(registry(False)) - scheduled - {"source"}):
        plugin_rows.append(
            f"<tr><td>—</td><td>{html.escape(name)}</td><td>Not scheduled / no selected input</td><td>0</td><td>0</td><td>0</td><td>0</td><td>Registered and available</td></tr>"
        )
    artifact_rows = []
    for row in manager.db.execute(
        "SELECT name,evidence FROM KnowledgeEntities WHERE kind='Artifacts' ORDER BY created_at DESC LIMIT 100"
    ):
        evidence = json.loads(row["evidence"])
        if "blob" in evidence:
            artifact_rows.append(
                "<tr>"
                + "".join(
                    f"<td>{html.escape(str(v))}</td>"
                    for v in (
                        row["name"],
                        evidence.get("category"),
                        evidence["blob"],
                        evidence.get("bytes"),
                    )
                )
                + "</tr>"
            )
    for event in manager.timeline.recent(run, 30) if run else []:
        timestamp = datetime.fromtimestamp(
            event["created_at"], timezone.utc
        ).isoformat()
        events.append(
            f"<tr><td>{timestamp}</td><td>{html.escape(event['event'])}</td>"
            f"<td>{html.escape(str(event['duration'] or ''))}</td><td><pre>"
            f"{html.escape(json.dumps(event['details'], ensure_ascii=False))}</pre></td></tr>"
        )
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Research Engine</title><style>body{{margin:0;background:#101827;color:#edf2f7;font:16px system-ui}}
main{{max-width:1200px;margin:auto;padding:36px}}p,span{{color:#acbfd4}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}}
article,section{{background:#1b2a40;border-radius:12px;padding:20px;margin:12px 0}}strong{{display:block;font-size:28px;color:#64dfbf}}
table{{width:100%;border-collapse:collapse}}td,th{{text-align:left;padding:12px;border-bottom:1px solid #33465f}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}section{{overflow:auto}}
</style></head><body><main><p>RESEARCH PLATFORM · V0.3</p><h1>Research Engine</h1>
<h2>{html.escape(manager.knowledge.project()["name"])} / {html.escape(progress["name"])}</h2>
<p>Run {html.escape(run or "—")} · Total tasks: {progress["total"]} · Supervisor alive: {progress["supervisor_alive"]}</p>
<div class="cards">{tiles}</div>
<section><h2>Plugins</h2><table><tr><th>Task</th><th>Plugin</th><th>Status</th><th>Seconds</th><th>Files / samples</th><th>Analysis artifacts</th><th>Errors</th><th>Details</th></tr>{"".join(plugin_rows)}</table></section>
<section><h2>Recent project artifacts and execution logs</h2><p>Paths are relative to this project's storage directory.</p><table><tr><th>Name</th><th>Category</th><th>Path</th><th>Bytes</th></tr>{"".join(artifact_rows)}</table></section>
<section><h2>Latest events</h2><table><thead><tr><th>UTC</th><th>Event</th><th>Seconds</th><th>Details</th></tr></thead>
<tbody>{"".join(events)}</tbody></table></section><p>Offline snapshot. Regenerate to refresh. Runtime excludes paused intervals.</p></main></body></html>"""
    # Publish the same immutable bytes through ArtifactManager before copying the view.
    artifact = manager.artifacts.publish(
        "Research Engine dashboard", page.encode("utf-8"), "dashboard", {"run_id": run}
    )
    blob = manager.knowledge.get(artifact)["evidence"]["blob"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    import os
    import tempfile

    descriptor, temporary = tempfile.mkstemp(dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write((manager.base / blob).read_bytes())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
