"""Generate a static dashboard for all registered CTF challenges."""
from __future__ import annotations

import argparse
import html
from pathlib import Path

from ctf.challenges import load


def render(workspace: Path) -> Path:
    registry = load(workspace)["challenges"]
    rows = []
    for slug, item in sorted(registry.items()):
        report = workspace / "reports" / slug / "index.html"
        title = html.escape(slug)
        label = f'<a href="reports/{title}/index.html">{title}</a>' if report.exists() else title
        rows.append("<tr><td>" + label + "</td><td>" + html.escape(item["category"]) +
                    "</td><td>" + html.escape(item["status"]) + "</td><td>" +
                    str(item["candidate_count"]) + "</td><td>" +
                    str(item.get("solver_candidate_count", 0)) + "</td><td>" +
                    str(item.get("solarctf_candidate_count", 0)) + "</td></tr>")
    page = ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>CTF Workbench</title><style>body{font:16px system-ui;max-width:1100px;"
            "margin:40px auto;padding:0 16px}table{width:100%;border-collapse:collapse}"
            "td,th{padding:12px;border-bottom:1px solid #bbb;text-align:left}"
            "a{color:#1769aa}</style><h1>CTF Workbench</h1>"
            "<p>Offline challenge reports. No automatic flag submission.</p>"
            "<table><tr><th>Challenge</th><th>Category</th><th>Status</th>"
            "<th>Flag candidates</th><th>Auto-solvers</th><th>SOLARCTF format</th></tr>" + "".join(rows) + "</table></html>")
    workspace.mkdir(parents=True, exist_ok=True)
    dest = workspace / "index.html"
    dest.write_text(page, encoding="utf-8")
    return dest

def main() -> None:
    parser = argparse.ArgumentParser(description="Build static CTF challenge dashboard")
    parser.add_argument("--workspace", type=Path, default=Path("ctf-workspace"))
    args = parser.parse_args()
    print(render(args.workspace))

if __name__ == "__main__":
    main()
