"""Self-contained, escaped graph reports with complete edge tables."""

import html
import json
from typing import Any


def graph_html(name: str, graph: dict[str, Any]) -> bytes:
    """Render a bounded SVG overview and lossless JSON evidence without external assets."""
    edges = graph.get("calls") or graph.get("edges", [])
    pairs = [
        (
            str(e.get("caller", e.get("source", "?"))),
            str(e.get("callee", e.get("target", "unresolved"))),
        )
        for e in edges
    ]
    nodes = list(dict.fromkeys(n for pair in pairs for n in pair))[:200]
    positions = {
        node: (30 + i % 4 * 240, 40 + i // 4 * 80) for i, node in enumerate(nodes)
    }
    svg = []
    for source, target in pairs[:1000]:
        if source in positions and target in positions:
            x1, y1 = positions[source]
            x2, y2 = positions[target]
            svg.append(
                f'<path d="M{x1 + 90},{y1 + 10} L{x2 + 90},{y2 + 10}" stroke="#467ca6" marker-end="url(#a)"/>'
            )
    for node, (x, y) in positions.items():
        svg.append(
            f'<g><title>{html.escape(node)}</title><rect x="{x}" y="{y}" width="190" height="30" rx="5" fill="#dceefe"/><text x="{x + 5}" y="{y + 20}">{html.escape(node[:25])}</text></g>'
        )
    rows = "".join(
        f"<tr><td>{html.escape(source)}</td><td>{html.escape(target)}</td></tr>"
        for source, target in pairs
    )
    page = f'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>{html.escape(name)}</title><style>body{{font:15px system-ui;margin:2rem}}table{{border-collapse:collapse}}td{{border:1px solid #ccc;padding:.5rem}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}</style>
<h1>{html.escape(name)}</h1><p>Backend: {html.escape(str(graph.get("backend", "unknown")))}. Truncated analysis: {bool(graph.get("truncated"))}.</p>
<p>Overview limited to 200 nodes / 1000 edges. Complete collected evidence follows; unresolved targets remain explicit.</p>
<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="{max(120, (len(nodes) + 3) // 4 * 80 + 50)}"><defs><marker id="a" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto"><path d="M0,0 L9,3 L0,6" fill="#467ca6"/></marker></defs>{"".join(svg)}</svg>
<table><tr><th>Source</th><th>Target</th></tr>{rows}</table><details><summary>Complete evidence</summary><pre>{html.escape(json.dumps(graph, ensure_ascii=False, indent=2))}</pre></details></html>'''
    return page.encode()
