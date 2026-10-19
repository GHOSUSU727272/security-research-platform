"""Offline challenge registry; no network access or target interaction."""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ctf.archive import inspect_zip
from ctf.decoders import decode_candidates
from ctf.deep import inspect_file
from ctf.event import solarctf_candidates
from ctf.solvers import solve_file
from ctf.triage import triage, write_report

SLUG = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}$")
CATEGORIES = ("web", "crypto", "reverse", "forensics", "pwn", "misc", "osint", "unknown")

def registry_path(workspace: Path) -> Path:
    return workspace / "challenges.json"

def load(workspace: Path) -> dict[str, Any]:
    path = registry_path(workspace)
    if not path.exists():
        return {"schema": 1, "challenges": {}}
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or not isinstance(data.get("challenges"), dict):
        raise ValueError("Invalid challenge registry")
    return data

def save(workspace: Path, data: dict[str, Any]) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    path = registry_path(workspace)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)

def add(workspace: Path, slug: str, source: Path, category: str = "unknown") -> dict[str, Any]:
    if not SLUG.fullmatch(slug):
        raise ValueError("Challenge ID must use letters, digits, underscores or hyphens")
    if category not in CATEGORIES:
        raise ValueError("Unsupported category")
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise ValueError("Source must be a directory")
    data = load(workspace)
    if slug in data["challenges"]:
        raise ValueError("Challenge ID already exists")
    item = {"id": slug, "source": str(source), "category": category,
            "status": "new", "created_utc": datetime.now(timezone.utc).isoformat(),
            "notes": "", "candidate_count": 0}
    data["challenges"][slug] = item
    save(workspace, data)
    from ctf.dashboard import render
    render(workspace)
    return item

def analyze(workspace: Path, slug: str) -> dict[str, Any]:
    data = load(workspace)
    if slug not in data["challenges"]:
        raise ValueError("Unknown challenge")
    item = data["challenges"][slug]
    source = Path(item["source"])
    report_dir = workspace.resolve() / "reports" / slug
    if report_dir.is_relative_to(source.resolve()):
        raise ValueError("Workspace/reports must be outside the challenge input")
    report = triage(source)
    for entry in report["files"]:
        if "error" in entry:
            continue
        file_path = source / entry["path"]
        if file_path.suffix.lower() == ".zip":
            try:
                manifest = inspect_zip(file_path)
                entry["archive"] = {"entry_count": len(manifest["entries"]),
                                    "warnings": manifest["warnings"],
                                    "total_uncompressed": manifest["total_uncompressed"]}
            except (OSError, ValueError, __import__("zipfile").BadZipFile) as exc:
                entry["archive_error"] = str(exc)
        if file_path.suffix.lower() in {".txt", ".json", ".html", ".js", ".log", ".csv"}:
            try:
                with file_path.open("rb") as stream:
                    entry["decoded_candidates"] = decode_candidates(stream.read(2 * 1024 * 1024))
            except OSError as exc:
                entry["decode_error"] = str(exc)
    report["decoded_candidate_count"] = sum(
        len(e.get("decoded_candidates", [])) for e in report["files"]
    )
    for entry in report["files"]:
        if "error" in entry:
            continue
        try:
            entry["solver_findings"] = solve_file(source / entry["path"])
        except (OSError, ValueError, __import__("zipfile").BadZipFile) as exc:
            entry["solver_error"] = str(exc)
    for entry in report["files"]:
        if "error" in entry:
            continue
        try:
            deep = inspect_file(source / entry["path"])
            if deep:
                entry["deep_inspection"] = deep
                entry.setdefault("solver_findings", []).extend(
                    deep.get("candidate_flags", [])
                )
        except (OSError, ValueError) as exc:
            entry["deep_error"] = str(exc)
    solutions = {
        finding["flag"] for entry in report["files"]
        for finding in entry.get("solver_findings", [])
    }
    report["auto_solution_count"] = len(solutions)
    report["candidate_solutions"] = sorted(solutions)
    event_flags = solarctf_candidates(solutions)
    report["solarctf_candidates"] = event_flags
    report["solarctf_candidate_count"] = len(event_flags)
    write_report(report, report_dir)
    item["status"] = "analyzed"
    item["candidate_count"] = report["candidate_count"]
    item["solver_candidate_count"] = report["auto_solution_count"]
    item["solarctf_candidate_count"] = report["solarctf_candidate_count"]
    item["analyzed_utc"] = datetime.now(timezone.utc).isoformat()
    save(workspace, data)
    from ctf.dashboard import render
    render(workspace)
    return report

def main() -> None:
    parser = argparse.ArgumentParser(description="Offline CTF challenge registry")
    parser.add_argument("--workspace", type=Path, default=Path("ctf-workspace"))
    commands = parser.add_subparsers(dest="command", required=True)
    add_cmd = commands.add_parser("add")
    add_cmd.add_argument("id")
    add_cmd.add_argument("source", type=Path)
    add_cmd.add_argument("--category", choices=CATEGORIES, default="unknown")
    analyze_cmd = commands.add_parser("analyze")
    analyze_cmd.add_argument("id")
    commands.add_parser("list")
    args = parser.parse_args()
    try:
        if args.command == "add":
            print(json.dumps(add(args.workspace, args.id, args.source, args.category), indent=2))
        elif args.command == "analyze":
            report = analyze(args.workspace, args.id)
            print(f"Files: {len(report['files'])}; candidates: {report['candidate_count']}")
            print(f"Report: {args.workspace / 'reports' / args.id / 'index.html'}")
        else:
            print(json.dumps(load(args.workspace)["challenges"], indent=2, ensure_ascii=False))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

if __name__ == "__main__":
    main()
