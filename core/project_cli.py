"""Additional project commands kept separate from the version-one CLI workflow."""

import argparse
import json
from pathlib import Path
from typing import Any

from analysis.knowledge_ingest import ingest
from core.knowledge import GraphEngine, KnowledgeEngine
from core.projects import ProjectManager
from core.research.manager import ResearchManager
from database.knowledge import STATES
from database.store import Store
from reports.dashboard import dashboard
from reports.research_dashboard import research_dashboard

PROJECT_COMMANDS = {
    "create",
    "open",
    "list",
    "export",
    "import",
    "knowledge",
    "note",
    "graph",
    "dashboard",
    "attach",
    "project-status",
    "sync",
}


def add_commands(sub: Any) -> None:
    """Register project operations without changing legacy command arguments."""
    child = sub.add_parser("create", help="Create an isolated research project")
    child.add_argument("name")
    child.add_argument("--description", default="")
    child.add_argument("--product", default="")
    child.add_argument("--version", default="")
    child.add_argument("--root", type=Path)
    child = sub.add_parser(
        "open", help="Select a project and optionally bind its target"
    )
    child.add_argument("name")
    child.add_argument("--root", type=Path)
    sub.add_parser("list")
    child = sub.add_parser("export")
    child.add_argument("--output", type=Path)
    child = sub.add_parser("import")
    child.add_argument("archive", type=Path)
    child = sub.add_parser("dashboard")
    child.add_argument("--output", type=Path)
    child.add_argument("--engine", action="store_true")
    child.add_argument("--run")
    child = sub.add_parser("project-status")
    child.add_argument("status", choices=["active", "paused", "completed"])
    child = sub.add_parser("attach")
    child.add_argument("file", type=Path)
    child.add_argument("--name")
    sub.add_parser("sync")
    child = sub.add_parser("knowledge")
    actions = child.add_subparsers(dest="knowledge_action", required=True)
    add = actions.add_parser("add")
    add.add_argument("kind", choices=list(STATES))
    add.add_argument("name")
    add.add_argument("--status")
    add.add_argument("--priority", type=int, choices=[1, 2, 3], default=2)
    add.add_argument("--evidence", default="{}", help="JSON object")
    listing = actions.add_parser("list")
    listing.add_argument("kind", choices=list(STATES))
    listing.add_argument("--status")
    listing.add_argument("--limit", type=int, default=100)
    listing.add_argument("--offset", type=int, default=0)
    update = actions.add_parser("set")
    update.add_argument("id")
    update.add_argument("status")
    update.add_argument("--reason", required=True)
    child = sub.add_parser("note")
    child.add_argument("body")
    child.add_argument("--category", required=True)
    child.add_argument("--priority", type=int, choices=[1, 2, 3], default=2)
    child.add_argument("--function", action="append", default=[])
    child.add_argument("--library", action="append", default=[])
    child = sub.add_parser("graph")
    actions = child.add_subparsers(dest="graph_action", required=True)
    add = actions.add_parser("link")
    add.add_argument("source")
    add.add_argument("target")
    add.add_argument("--relation", required=True)
    add.add_argument("--reason", required=True)
    view = actions.add_parser("show")
    view.add_argument("id")
    view.add_argument("--depth", type=int, default=1)


def execute(args: argparse.Namespace, manager: ProjectManager) -> None:
    """Execute a project operation with scoped database lifetime and JSON output."""
    result: Any = None
    if args.action in {"create", "open", "list", "import"}:
        manager.audit(args.action)
    if args.action == "create":
        result = manager.create(
            args.name, args.description, args.product, args.version, args.root
        )
    elif args.action == "open":
        result = manager.open(args.name, args.root)
    elif args.action == "list":
        result = manager.list()
    elif args.action == "import":
        result = manager.import_archive(args.archive)
    else:
        selected = manager.resolve(args.project)
        if selected is None:
            raise ValueError(
                "No project selected; use research open NAME or --project NAME"
            )
        base = manager.path(selected["id"])
        manager.audit(args.action, selected["id"])
        if args.action == "export":
            destination = args.output or base / "project.rpk.zip"
            manager.export(selected["id"], destination)
            result = {"archive": str(destination.resolve())}
        elif args.action == "attach":
            result = {"id": manager.attach(selected["id"], args.file, args.name)}
        else:
            store = Store(base / "research.sqlite3")
            try:
                knowledge = KnowledgeEngine(store)
                if args.action == "knowledge":
                    if args.knowledge_action == "add":
                        evidence = json.loads(args.evidence)
                        if not isinstance(evidence, dict):
                            raise ValueError("Evidence must be a JSON object")
                        result = {
                            "id": knowledge.add(
                                args.kind,
                                args.name,
                                status=args.status,
                                priority=args.priority,
                                evidence=evidence,
                            )
                        }
                    elif args.knowledge_action == "list":
                        result = knowledge.entities(
                            args.kind, args.status, args.limit, args.offset
                        )
                    else:
                        knowledge.transition(args.id, args.status, args.reason)
                        result = knowledge.get(args.id)
                elif args.action == "note":
                    result = {
                        "id": knowledge.note(
                            args.body,
                            args.category,
                            args.priority,
                            args.function,
                            args.library,
                        )
                    }
                elif args.action == "graph":
                    graph = GraphEngine(knowledge)
                    if args.graph_action == "link":
                        result = {
                            "id": graph.connect(
                                args.source, args.target, args.relation, args.reason
                            )
                        }
                    else:
                        result = graph.neighborhood(args.id, args.depth)
                elif args.action == "dashboard":
                    destination = args.output or base / (
                        "research-engine.html" if args.engine else "dashboard.html"
                    )
                    if args.engine:
                        engine = ResearchManager(store, base)
                        latest = store.db.execute(
                            "SELECT id FROM ResearchRuns ORDER BY created_at DESC LIMIT 1"
                        ).fetchone()
                        selected_run = (
                            engine.resolve(args.run)
                            if args.run
                            else (latest[0] if latest else None)
                        )
                        research_dashboard(engine, selected_run, destination)
                    else:
                        dashboard(knowledge, destination)
                    result = {"dashboard": str(destination.resolve())}
                elif args.action == "project-status":
                    with store.db:
                        store.db.execute(
                            "UPDATE Projects SET status=? WHERE id=?",
                            (args.status, selected["id"]),
                        )
                        knowledge._event(
                            "project_status_changed", {"status": args.status}
                        )
                    result = knowledge.project()
                elif args.action == "sync":
                    result = {"ingested": ingest(knowledge)}
            finally:
                store.close()
    print(json.dumps(result, ensure_ascii=False, indent=2))
