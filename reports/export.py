"""Safe HTML rendering and atomic report writes."""

import html
import json
import os
import tempfile
from pathlib import Path
from typing import Any


def export(report: dict[str, Any], destination: Path) -> None:
    """Write JSON, Markdown and escaped standalone HTML from one report model."""
    destination.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(report, indent=2, ensure_ascii=False)
    lines = [
        "# Research report",
        "",
        "Candidates require human validation.",
        "",
        f"Candidates: {report['summary']['candidates']}",
        f"Behavior changes: {report['summary']['behavior_changes']}",
        "",
    ]
    for finding in report["findings"]:
        lines.extend(
            [
                f"## P{finding['priority']} — {html.escape(finding['rule'])}",
                "",
                f"Location: {html.escape(finding['path'])}:{finding['line']}",
                "",
                html.escape(finding["reason"]),
                "",
                f"Review: {html.escape(finding['review']['status'])}",
                "",
                html.escape(finding["manual_check"]),
                "",
                f"Fingerprint: {finding['fingerprint']}",
                "",
            ]
        )
    lines.extend(
        [
            "## Full evidence and task status",
            "",
            "<pre>",
            html.escape(serialized),
            "</pre>",
        ]
    )
    markdown = "\n".join(lines)
    page = (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width'>"
        "<title>Research report</title><style>body{max-width:1100px;margin:40px auto;"
        "padding:20px;font:16px system-ui;color:#172b4d;background:#f4f7fb}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:white;padding:24px}"
        "</style><h1>Research report</h1><p>Review candidates, not confirmed vulnerabilities.</p>"
        f"<pre>{html.escape(serialized)}</pre></html>"
    )
    for name, content in (
        ("report.json", serialized),
        ("report.md", markdown),
        ("report.html", page),
    ):
        descriptor, temporary = tempfile.mkstemp(dir=destination, suffix=".tmp")
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination / name)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
