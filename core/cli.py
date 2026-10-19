"""CLI entry points for queue, analysis, human memory and reports."""

import argparse
import asyncio
import json
import logging
import sqlite3
import zipfile
from dataclasses import asdict, replace
from logging.handlers import RotatingFileHandler
from pathlib import Path

from analysis.correlate import aggregate
from analysis.knowledge_ingest import ingest
from core.config import Settings
from core.knowledge import KnowledgeEngine
from core.locking import scheduler_lock
from core.models import Context
from core.project_cli import PROJECT_COMMANDS, add_commands, execute
from core.projects import ProjectManager
from core.research.cli import ENGINE_COMMANDS, add_engine_commands, execute_engine
from core.research.manager import ResearchManager
from core.scheduler import Scheduler
from database.store import Store
from plugins import registry
from reports.export import export


def main() -> None:
    """Parse an explicit operation and manage runtime resource lifetimes."""
    parser = argparse.ArgumentParser(description="Authorized local research platform")
    parser.add_argument("--config", type=Path, default=Path("config/example.yaml"))
    parser.add_argument("--workspace", type=Path, default=Path("state"))
    parser.add_argument(
        "--project", help="Project name or UUID; overrides active selection"
    )
    parser.add_argument(
        "--legacy", action="store_true", help="Use the v0.1 unscoped database"
    )
    sub = parser.add_subparsers(dest="action", required=True)
    for name in ("enqueue", "scan"):
        child = sub.add_parser(name)
        child.add_argument("--plugin", default="source")
    sub.add_parser("run")
    sub.add_parser("status")
    child = sub.add_parser("report")
    child.add_argument("--output", type=Path, required=True)
    child = sub.add_parser("review")
    child.add_argument("fingerprint")
    child.add_argument(
        "status", choices=["new", "confirmed", "dismissed", "investigating"]
    )
    child.add_argument("--comment", default="")
    child = sub.add_parser("link")
    child.add_argument("source")
    child.add_argument("target")
    child.add_argument("--reason", required=True)
    add_commands(sub)
    add_engine_commands(sub)
    ctf = sub.add_parser("ctf", help="Local offline CTF challenge workbench")
    ctf.add_argument("--ctf-workspace", type=Path, default=Path("ctf-workspace"))
    actions = ctf.add_subparsers(dest="ctf_action", required=True)
    child = actions.add_parser("add")
    child.add_argument("challenge_id")
    child.add_argument("source", type=Path)
    child.add_argument(
        "--category",
        choices=("web", "crypto", "reverse", "forensics", "pwn", "misc", "osint", "unknown"),
        default="unknown",
    )
    child = actions.add_parser("analyze")
    child.add_argument("challenge_id")
    actions.add_parser("list")
    actions.add_parser("dashboard")
    args = parser.parse_args()
    if args.action == "ctf":
        from ctf.challenges import add as ctf_add
        from ctf.challenges import analyze as ctf_analyze
        from ctf.challenges import load as ctf_load
        from ctf.dashboard import render as ctf_render

        try:
            workspace = args.ctf_workspace
            if args.ctf_action == "add":
                print(json.dumps(
                    ctf_add(workspace, args.challenge_id, args.source, args.category),
                    ensure_ascii=False, indent=2,
                ))
            elif args.ctf_action == "analyze":
                report = ctf_analyze(workspace, args.challenge_id)
                print(json.dumps({
                    "auto_solution_count": report["auto_solution_count"],
                    "solarctf_candidates": report["solarctf_candidates"],
                    "report": str(workspace / "reports" / args.challenge_id / "index.html"),
                }, ensure_ascii=False, indent=2))
            elif args.ctf_action == "dashboard":
                print(ctf_render(workspace))
            elif args.ctf_action == "list":
                print(json.dumps(
                    ctf_load(workspace)["challenges"], ensure_ascii=False, indent=2,
                ))
        except (ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        return
    if args.legacy and args.project:
        parser.error("--legacy and --project are mutually exclusive")
    manager = ProjectManager(args.workspace)
    try:
        if args.action in PROJECT_COMMANDS | ENGINE_COMMANDS:
            if args.legacy:
                parser.error("Project commands cannot be used with --legacy")
            if args.action in ENGINE_COMMANDS:
                execute_engine(args, manager)
            else:
                execute(args, manager)
            return
        selected = None if args.legacy else manager.resolve(args.project)
        project_state = manager.path(selected["id"]) if selected else None
        if selected:
            manager.audit(args.action, selected["id"])
    except (
        ValueError,
        OSError,
        sqlite3.Error,
        zipfile.BadZipFile,
        KeyError,
        TypeError,
    ) as exc:
        parser.error(str(exc))
    finally:
        manager.close()
    if selected and args.action == "status":
        assert project_state is not None
        store = Store(project_state / "research.sqlite3")
        try:
            summary = KnowledgeEngine(store).summary()
            engine = ResearchManager(store, project_state)
            latest = store.db.execute(
                "SELECT id FROM ResearchRuns ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            summary["research_engine"] = (
                engine.progress.snapshot(latest[0]) if latest else None
            )
            print(json.dumps(summary, ensure_ascii=False, indent=2))
        finally:
            store.close()
        return
    settings = Settings.load(args.config)
    if selected:
        assert project_state is not None
        if args.action in {"enqueue", "scan", "run"}:
            if not selected["root"] or not Path(selected["root"]).is_dir():
                parser.error(
                    "Bind a local target first: research open NAME --root PATH"
                )
        settings = replace(
            settings, state=str(project_state), root=selected["root"] or settings.root
        )
    state = Path(settings.state)
    state.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        state / "research.log", maxBytes=5_000_000, backupCount=5, encoding="utf-8"
    )
    logging.basicConfig(
        level=logging.INFO,
        handlers=[handler, logging.StreamHandler()],
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.info("operation=%s", args.action)
    store = Store(state / "research.sqlite3")
    try:
        if selected and args.action in {"enqueue", "scan", "run"}:
            if KnowledgeEngine(store).project()["status"] != "active":
                parser.error(
                    "Project is not active; use research project-status active"
                )
        if args.action in {"enqueue", "scan", "run"}:
            plugins = registry(settings.allow_dynamic)
            if args.action != "run":
                if args.plugin not in plugins:
                    parser.error("Unknown/disabled plugin")
                context = Context(
                    settings.root,
                    settings.max_file_bytes,
                    settings.excluded,
                    settings.command,
                    settings.max_log_bytes,
                    plugin_options=settings.plugin_options,
                    checkpoint_db=str(state / "research.sqlite3"),
                )
                print(store.enqueue(args.plugin, asdict(context)))
            if args.action != "enqueue":
                with scheduler_lock(state / "scheduler.lock"):
                    if selected:
                        with store.db:
                            for row in store.db.execute(
                                "SELECT id,context FROM jobs WHERE status IN ('queued','running')"
                            ):
                                context_data = json.loads(row["context"])
                                if context_data["root"] != settings.root:
                                    KnowledgeEngine(store)._event(
                                        "queued_target_rebound",
                                        {
                                            "job_id": row["id"],
                                            "old_root": context_data["root"],
                                            "new_root": settings.root,
                                        },
                                    )
                                context_data["root"] = settings.root
                                store.db.execute(
                                    "UPDATE jobs SET context=? WHERE id=?",
                                    (json.dumps(context_data), row["id"]),
                                )
                    asyncio.run(Scheduler(store, settings, plugins).run())
                if selected:
                    ingest(KnowledgeEngine(store))
        elif args.action == "status":
            print(json.dumps(store.jobs(), indent=2))
        elif args.action == "report":
            export(aggregate(store), args.output)
        elif args.action == "review":
            store.review(args.fingerprint, args.status, args.comment)
        elif args.action == "link":
            with store.db:
                store.db.execute(
                    "INSERT OR REPLACE INTO links VALUES(?,?,?)",
                    (args.source, args.target, args.reason),
                )
    finally:
        store.close()


if __name__ == "__main__":
    main()
