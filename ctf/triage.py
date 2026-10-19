"""Offline, read-only CTF triage. Never executes supplied challenge files."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FLAG_PATTERN = re.compile(rb"(?i)(?:flag|ctf|solarctf|solar)\{[ -~]{1,160}?\}")
EXTENSIONS = {
    "forensics": {".pcap", ".pcapng", ".evtx", ".mem", ".dmp", ".raw", ".png", ".jpg", ".jpeg", ".wav"},
    "reverse": {".elf", ".exe", ".dll", ".so", ".class", ".pyc", ".wasm"},
    "web": {".html", ".js", ".php", ".css", ".har"},
    "crypto": {".pem", ".pub", ".key", ".enc"},
    "misc": {".txt", ".json", ".zip", ".tar", ".gz", ".pdf"},
}
MAX_BYTES = 64 * 1024 * 1024

def classify(path: Path, header: bytes) -> str:
    if header.startswith((b"\x7fELF", b"MZ")):
        return "reverse"
    if header.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")):
        return "forensics"
    for category, extensions in EXTENSIONS.items():
        if path.suffix.lower() in extensions:
            return category
    return "unknown"

def scan_file(path: Path, root: Path) -> dict[str, Any]:
    stat = path.stat()
    digest = hashlib.sha256()
    matches: set[str] = set()
    head = b""
    scanned = 0
    tail = b""
    with path.open("rb") as source:
        while scanned < MAX_BYTES:
            chunk = source.read(min(1024 * 1024, MAX_BYTES - scanned))
            if not chunk:
                break
            if not head:
                head = chunk[:16]
            digest.update(chunk)
            scanned += len(chunk)
            sample = tail + chunk
            matches.update(m.group().decode("ascii", errors="replace") for m in FLAG_PATTERN.finditer(sample))
            tail = sample[-192:]
    return {
        "path": str(path.relative_to(root)),
        "size": stat.st_size,
        "scanned_bytes": scanned,
        "truncated": stat.st_size > scanned,
        "sha256_scanned": digest.hexdigest(),
        "category": classify(path, head),
        "candidate_flags": sorted(matches),
    }

def triage(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Input must be a directory")
    records = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            records.append(scan_file(path, root))
        except (OSError, ValueError) as exc:
            records.append({"path": str(path.relative_to(root)), "error": str(exc)})
    counts = Counter(r["category"] for r in records if "category" in r)
    return {
        "source": str(root),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "files": records,
        "categories": dict(counts),
        "candidate_count": sum(len(r.get("candidate_flags", [])) for r in records),
        "note": "Candidates are unverified; offline triage does not submit flags or execute files.",
    }

def write_report(report: dict[str, Any], destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    rows = []
    for entry in report["files"]:
        flags = ", ".join(entry.get("candidate_flags", []))
        decoded = entry.get("decoded_candidates", [])
        if decoded:
            flags += " | decoded: " + ", ".join(
                flag for item in decoded for flag in item["candidate_flags"]
            )
        archive = entry.get("archive")
        if archive:
            flags += " | ZIP: " + ", ".join(archive["warnings"])
        solved = entry.get("solver_findings", [])
        if solved:
            flags += " | auto-solvers: " + ", ".join(
                f'{finding["flag"]} [{finding["method"]}: {finding["evidence"]}]'
                for finding in solved
            )
        detail = entry.get("deep_inspection")
        detail_html = ""
        if detail:
            detail_html = (
                "<details><summary>" + html.escape(str(detail.get("type", "details")))
                + "</summary><pre>"
                + html.escape(json.dumps(
                    {k: v for k, v in detail.items() if k != "candidate_flags"},
                    ensure_ascii=False, indent=2,
                )) + "</pre></details>"
            )
        cols = (
            entry["path"], entry.get("category", "error"),
            entry.get("size", ""), flags, entry.get("error", ""),
        )
        rows.append("<tr>" + "".join(
            f"<td>{html.escape(str(value))}</td>" for value in cols
        ) + "<td>" + detail_html + "</td></tr>")
    event_flags = report.get("solarctf_candidates", [])
    event_html = "<h2>SOLARCTF format candidates (unverified)</h2><ul>" + "".join(
        f"<li><code>{html.escape(str(flag))}</code></li>" for flag in event_flags
    ) + "</ul>"
    page = ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<title>CTF offline triage</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto}"
            "table{border-collapse:collapse;width:100%}td,th{padding:9px;border:1px solid #ccc;overflow-wrap:anywhere}"
            "th{text-align:left;background:#eee}</style><h1>CTF offline triage</h1>"
            f"<p>Files: {len(report['files'])} ? Candidate flags: {report['candidate_count']}</p>"
            "<p>Candidates are unverified. No file execution or network traffic.</p>"
            + event_html +
            "<table><tr><th>File</th><th>Category</th><th>Bytes</th><th>Candidates</th><th>Error</th><th>Deep inspection</th></tr>"
            + "".join(rows) + "</table></html>")
    (destination / "index.html").write_text(page, encoding="utf-8")

def main() -> None:
    parser = argparse.ArgumentParser(description="Offline CTF artifact triage")
    parser.add_argument("input", type=Path, help="Directory with locally obtained challenge files")
    parser.add_argument("--output", type=Path, default=Path("ctf-output"))
    args = parser.parse_args()
    if args.output.resolve() == args.input.resolve() or args.output.resolve().is_relative_to(args.input.resolve()):
        parser.error("Output must be outside input directory")
    report = triage(args.input)
    write_report(report, args.output)
    print(f"Scanned {len(report['files'])} files; {report['candidate_count']} candidate flags")
    print(f"Reports: {args.output / 'report.json'} and {args.output / 'index.html'}")

if __name__ == "__main__":
    main()
