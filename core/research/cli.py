"""Research Engine CLI additions with unchanged legacy/project command semantics."""

import argparse
import asyncio
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from core.config import Settings
from core.models import Context
from core.projects import ProjectManager
from core.research.manager import ResearchManager
from core.research.plan import ResearchPlan, TaskSpec
from database.store import Store

ENGINE_COMMANDS = {"start", "stop", "resume", "progress", "timeline", "checkpoints"}


def add_engine_commands(sub: Any) -> None:
    """Add orchestration commands without reusing scan/run argument names."""
    start = sub.add_parser("start")
    start.add_argument("--plan", type=Path)
    start.add_argument("--workers", type=int)
    start.add_argument("--checkpoint-minutes", type=float)
    start.add_argument(
        "--prepare",
        action="store_true",
        help="Persist the plan without starting workers",
    )
    resume = sub.add_parser("resume")
    resume.add_argument("--run")
    resume.add_argument("--workers", type=int)
    stop = sub.add_parser("stop")
    stop.add_argument("--run")
    mode = stop.add_mutually_exclusive_group()
    mode.add_argument("--task", help="Cancel one task by key or UUID")
    mode.add_argument(
        "--cancel", action="store_true", help="Cancel the entire run permanently"
    )
    for command in ("progress", "timeline", "checkpoints"):
        child = sub.add_parser(command)
        child.add_argument("--run")
        if command != "progress":
            child.add_argument("--limit", type=int, default=100)
        if command == "timeline":
            child.add_argument("--before", type=int)


def execute_engine(args: argparse.Namespace, projects: ProjectManager) -> None:
    """Route one engine operation to the explicitly selected project only."""
    selected = projects.resolve(args.project)
    if selected is None:
        raise ValueError("Select a project with research open NAME")
    base = projects.path(selected["id"])
    projects.audit(args.action, selected["id"])
    store = Store(base / "research.sqlite3")
    try:
        manager = ResearchManager(store, base)
        result: Any
        if args.action in {"start", "resume"}:
            if not selected["root"] or not Path(selected["root"]).is_dir():
                raise ValueError("Bind a target first: research open NAME --root PATH")
            settings = Settings.load(args.config)
            if args.action == "start":
                plan = (
                    ResearchPlan.load(args.plan)
                    if args.plan
                    else ResearchPlan(
                        workers=settings.workers,
                        tasks=(
                            TaskSpec(
                                "source",
                                timeout=settings.timeout,
                                attempts=settings.attempts,
                            ),
                        ),
                    )
                )
                if args.workers is not None:
                    plan = replace(plan, workers=args.workers)
                if args.checkpoint_minutes is not None:
                    plan = replace(plan, checkpoint_minutes=args.checkpoint_minutes)
                context = Context(
                    selected["root"],
                    settings.max_file_bytes,
                    settings.excluded,
                    settings.command,
                    settings.max_log_bytes,
                    plugin_options=settings.plugin_options,
                )
                run = manager.create(plan, context, settings.allow_dynamic)
                if args.prepare:
                    print(json.dumps(manager.progress.snapshot(run), indent=2))
                    return
            else:
                run = manager.resolve(args.run)
            try:
                result = asyncio.run(
                    manager.execute(
                        run,
                        selected["root"],
                        allow_dynamic=settings.allow_dynamic,
                        workers=args.workers,
                    )
                )
            except KeyboardInterrupt:
                result = manager.progress.snapshot(run)
        else:
            run = manager.resolve(args.run)
            if args.action == "stop":
                manager.stop(run, args.task, args.cancel)
                result = manager.progress.snapshot(run)
            elif args.action == "progress":
                result = manager.progress.snapshot(run)
            elif args.action == "timeline":
                result = manager.timeline.recent(run, args.limit, args.before)
            else:
                result = manager.checkpoints.list(run, args.limit)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    finally:
        store.close()
