"""Offline project dashboard with escaped content and explicit progress semantics."""

import html
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from core.knowledge import KnowledgeEngine


def dashboard(knowledge: KnowledgeEngine, destination: Path) -> None:
    """Atomically render the project's metrics, research backlog and recent runs."""
    summary = knowledge.summary()
    project = summary["project"]
    escape = html.escape
    cards = {
        "Functions": summary["counts"]["Functions"],
        "Libraries": summary["counts"]["Libraries"],
        "Hypotheses": summary["counts"]["Hypotheses"],
        "Confirmed findings": summary["confirmed"],
        "False positives (current)": summary["false_positives"],
        "Interesting locations": summary["counts"]["InterestingLocations"],
        "Notes": summary["counts"]["Notes"],
    }
    tiles = "".join(
        f"<article><strong>{value}</strong><span>{label}</span></article>"
        for label, value in cards.items()
    )
    progress = summary["progress"]
    percent = progress["percent"]
    progress_text = "No inventory yet" if percent is None else f"{percent}% reviewed"
    rows = []
    for row in knowledge.db.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT 20"):
        created = datetime.fromtimestamp(row["created"], timezone.utc).isoformat()
        rows.append(
            "<tr><td>"
            + escape(created)
            + "</td>"
            + "".join(
                f"<td>{escape(str(row[key] or ''))}</td>"
                for key in ("id", "plugin", "status", "attempts", "error")
            )
            + "</tr>"
        )
    backlog = []
    for item in knowledge.entities("InterestingLocations", "open", limit=20):
        backlog.append(
            f"<li><b>P{item['priority']}</b> {escape(item['name'])}"
            f"<pre>{escape(json.dumps(item['evidence'], ensure_ascii=False, indent=2))}</pre></li>"
        )
    notes = [
        f"<li><b>{escape(n['evidence'].get('category', 'general'))}</b> · "
        f"{escape(n['created_at'])}<p>{escape(n['evidence'].get('body', n['name']))}</p></li>"
        for n in knowledge.entities("Notes", "active", limit=20)
    ]
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>{escape(project["name"])} Dashboard</title><style>
body{{background:#101827;color:#edf2f7;font:16px system-ui;margin:0}}main{{max-width:1200px;margin:auto;padding:36px}}
header p,.muted{{color:#a7b8cc}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px}}
article,section{{background:#1a273b;padding:20px;border-radius:12px;margin:18px 0}}article strong{{display:block;font-size:34px;color:#63dfbe}}
article span{{font-size:14px}}table{{border-collapse:collapse;width:100%}}td,th{{text-align:left;padding:12px;border-bottom:1px solid #34445b}}
pre,td{{overflow-wrap:anywhere;white-space:pre-wrap}}progress{{width:100%;accent-color:#63dfbe}}.scroll{{overflow:auto}}
</style></head><body><main><header><p>RESEARCH PLATFORM / PROJECT KNOWLEDGE</p>
<h1>{escape(project["name"])} Dashboard</h1>
<p>{escape(project["product"])} · {escape(project["product_version"])} · {escape(project["status"])}</p>
<p>{escape(project["description"])}</p><p>ID: {escape(project["id"])}</p></header>
<section><h2>{progress_text}</h2><progress max="100" value="{percent or 0}"></progress>
<p>{progress["reviewed"]} / {progress["total"]} inventoried functions and libraries reviewed.</p>
<p class="muted">This measures recorded review work, not security coverage of the product.</p></section>
<div class="cards">{tiles}</div><section><h2>Hypothesis states</h2>
<pre>{escape(json.dumps(summary["states"].get("Hypotheses", {}), indent=2))}</pre></section>
<section class="scroll"><h2>Recent runs</h2><table><thead><tr><th>Created (UTC)</th><th>ID</th><th>Plugin</th><th>Status</th><th>Attempts</th><th>Error</th></tr></thead>
<tbody>{"".join(rows) or '<tr><td colspan="6">No research runs yet.</td></tr>'}</tbody></table></section>
<section><h2>Manual review queue</h2><ul>{"".join(backlog) or "<li>No locations recorded.</li>"}</ul></section>
<section><h2>Notes</h2><ul>{"".join(notes) or "<li>No notes recorded.</li>"}</ul></section>
<footer class="muted">Last research: {escape(str(project["last_researched_at"] or "Not started"))}. Candidates require human validation.</footer>
</main></body></html>"""
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=destination.parent, suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(page)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
