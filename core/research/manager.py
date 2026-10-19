"""Central orchestration of durable research runs, checkpoints and knowledge transfer."""

import asyncio
import json
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from core.knowledge import KnowledgeEngine
from core.locking import scheduler_lock
from core.models import Context
from core.research.artifacts import ArtifactManager, ResultAggregator
from core.research.plan import ResearchPlan
from core.research.pool import ProcessExecutor, WorkerPool
from core.research.scheduler import TaskScheduler
from core.research.state import CheckpointManager, ProgressTracker, ResearchTimeline
from database.checkpoints import CheckpointWriter
from database.research import initialize_research
from database.store import Store
from plugins import registry


class ResearchManager:
    """Coordinate one project's engine without replacing its legacy scheduler."""

    def __init__(self, store: Store, base: Path) -> None:
        """Attach component services to the existing project database and storage."""
        initialize_research(store.db)
        self.store, self.db, self.base = store, store.db, base.resolve()
        self.knowledge = KnowledgeEngine(store)
        self.timeline = ResearchTimeline(self.db)
        self.progress = ProgressTracker(self.db)
        self.checkpoints = CheckpointManager(self.db)
        self.artifacts = ArtifactManager(self.knowledge, self.base)
        self.aggregator = ResultAggregator(self.knowledge, self.artifacts)

    def resolve(self, run: str | None = None) -> str:
        """Resolve an explicit run ID or the most recently created research."""
        row = self.db.execute(
            "SELECT id FROM ResearchRuns WHERE (? IS NULL OR id=?) ORDER BY created_at DESC LIMIT 1",
            (run, run),
        ).fetchone()
        if row is None:
            raise ValueError("No research run found; use research start")
        return str(row[0])

    def create(
        self, plan: ResearchPlan, context: Context, allow_dynamic: bool = False
    ) -> str:
        """Validate the entire DAG before atomically publishing the new research."""
        plan.validate()
        if self.knowledge.project()["status"] != "active":
            raise ValueError("Project must be active")
        available = registry(allow_dynamic)
        if any(task.plugin not in available for task in plan.tasks):
            raise ValueError("Plan references an unknown or disabled plugin")
        if any(task.plugin == "dynamic" for task in plan.tasks) and not context.command:
            raise ValueError("Dynamic tasks require an explicit configured command")
        if not Path(context.root).is_dir():
            raise ValueError("Research root must be an existing directory")
        run = str(uuid.uuid4())
        ids = {task.key: str(uuid.uuid4()) for task in plan.tasks}
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if self.db.execute(
                "SELECT 1 FROM ResearchRuns WHERE status IN ('ready','running','paused')"
            ).fetchone():
                raise ValueError(
                    "An unfinished research exists; resume or cancel it first"
                )
            self.db.execute(
                "INSERT INTO ResearchRuns(id,project_id,name,status,created_at,workers,checkpoint_seconds,options) "
                "VALUES(?,?,?,'ready',?,?,?,?)",
                (
                    run,
                    self.knowledge.project_id,
                    plan.name,
                    time.time(),
                    plan.workers,
                    plan.checkpoint_minutes * 60,
                    json.dumps({"allow_dynamic": allow_dynamic}),
                ),
            )
            for task in plan.tasks:
                task_context = asdict(context)
                task_context["plugin_options"][task.plugin] = {
                    **context.plugin_options.get(task.plugin, {}),
                    **task.options,
                }
                self.db.execute(
                    "INSERT INTO ResearchTasks(id,run_id,task_key,stage,plugin,priority,context,status,max_attempts,timeout) "
                    "VALUES(?,?,?,?,?,?,?,'pending',?,?)",
                    (
                        ids[task.key],
                        run,
                        task.key,
                        task.stage,
                        task.plugin,
                        task.priority,
                        json.dumps(task_context),
                        task.attempts,
                        task.timeout,
                    ),
                )
            for task in plan.tasks:
                for dependency in set(task.depends_on):
                    self.db.execute(
                        "INSERT INTO ResearchDependencies VALUES(?,?,?)",
                        (run, ids[task.key], ids[dependency]),
                    )
            self.timeline.record(
                run,
                "research_created",
                details={"tasks": len(plan.tasks), "workers": plan.workers},
            )
        self.checkpoints.save(run, "created")
        return run

    def stop(self, run: str, task: str | None = None, cancel: bool = False) -> None:
        """Request cross-process pause or cancellation through durable control fields."""
        run = self.resolve(run)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT status FROM ResearchRuns WHERE id=?", (run,)
            ).fetchone()
            if row[0] in {"completed", "cancelled", "failed"}:
                raise ValueError("Research is already terminal")
            if task:
                item = self.db.execute(
                    "SELECT id,status FROM ResearchTasks WHERE run_id=? AND (id=? OR task_key=?)",
                    (run, task, task),
                ).fetchone()
                if item is None:
                    raise ValueError("Unknown task in selected run")
                if item["status"] not in {"pending", "running"}:
                    raise ValueError("Task is already terminal")
                self.db.execute(
                    "UPDATE ResearchTasks SET cancel_requested=1,status=CASE WHEN status='pending' THEN 'cancelled' ELSE status END WHERE id=?",
                    (item["id"],),
                )
                self.timeline.record(run, "task_cancel_requested", item["id"])
                TaskScheduler(self.db, run).propagate()
            else:
                request = "cancel" if cancel else "pause"
                self.db.execute(
                    "UPDATE ResearchRuns SET stop_requested=? WHERE id=?",
                    (request, run),
                )
                if cancel:
                    self.db.execute(
                        "UPDATE ResearchTasks SET cancel_requested=1,status=CASE WHEN status='pending' THEN 'cancelled' ELSE status END "
                        "WHERE run_id=? AND status IN ('pending','running')",
                        (run,),
                    )
                if row[0] != "running":
                    self.db.execute(
                        "UPDATE ResearchRuns SET status=? WHERE id=?",
                        ("cancelled" if cancel else "paused", run),
                    )
                self.timeline.record(run, "stop_requested", details={"mode": request})
        if row[0] != "running":
            self.checkpoints.save(run, "stop")

    async def execute(
        self,
        run: str,
        root: str,
        *,
        allow_dynamic: bool = False,
        workers: int | None = None,
    ) -> dict[str, Any]:
        """Hold the shared OS lock, recover work and supervise until pause or completion."""
        if not Path(root).is_dir():
            raise ValueError("Bind an existing project root before execution")
        if workers is not None and not 1 <= workers <= 32:
            raise ValueError("Workers must be between 1 and 32")
        if self.knowledge.project()["status"] != "active":
            raise ValueError("Project must be active")
        run = self.resolve(run)
        with scheduler_lock(self.base / "scheduler.lock"):
            row = self.db.execute(
                "SELECT * FROM ResearchRuns WHERE id=?", (run,)
            ).fetchone()
            if row["status"] in {"completed", "cancelled"}:
                raise ValueError("Research has already finished")
            plugins = registry(allow_dynamic)
            if any(
                r[0] not in plugins
                for r in self.db.execute(
                    "SELECT plugin FROM ResearchTasks WHERE run_id=? AND status IN ('pending','running')",
                    (run,),
                )
            ):
                raise ValueError(
                    "Pending tasks require unavailable or disabled plugins"
                )
            scheduler = TaskScheduler(self.db, run)
            scheduler.recover(root)
            if row["stop_requested"] == "cancel":
                with self.db:
                    self.db.execute(
                        "UPDATE ResearchTasks SET status='cancelled' WHERE run_id=? AND status='pending'",
                        (run,),
                    )
                    self.db.execute(
                        "UPDATE ResearchRuns SET status='cancelled',finished_at=? WHERE id=?",
                        (time.time(), run),
                    )
                    self.timeline.record(run, "research_cancelled")
                self.aggregator.flush()
                self.checkpoints.save(run, "cancelled")
                return self.progress.snapshot(run)
            with self.db:
                self.db.execute(
                    "UPDATE ResearchRuns SET status='running',started_at=coalesce(started_at,?),finished_at=NULL,"
                    "heartbeat=?,stop_requested='',error=NULL,workers=? WHERE id=?",
                    (time.time(), time.time(), workers or row["workers"], run),
                )
                self.timeline.record(
                    run,
                    "research_resumed",
                    details={"checkpoint": self.checkpoints.list(run, 1)},
                )
            async with CheckpointWriter(self.db) as writer:
                executor = ProcessExecutor(
                    self.base, self.artifacts, allow_dynamic, writer
                )
                pool = WorkerPool(
                    scheduler, executor, self.aggregator, workers or row["workers"]
                )
                tick = time.monotonic()
                next_checkpoint = tick + row["checkpoint_seconds"]
                next_flush = tick + 5
                terminal = "paused"
                try:
                    while True:
                        now = time.monotonic()
                        with self.db:
                            self.db.execute(
                                "UPDATE ResearchRuns SET elapsed=elapsed+?,heartbeat=? WHERE id=?",
                                (now - tick, time.time(), run),
                            )
                        tick = now
                        control = self.db.execute(
                            "SELECT stop_requested FROM ResearchRuns WHERE id=?", (run,)
                        ).fetchone()[0]
                        if control:
                            terminal = "cancelled" if control == "cancel" else "paused"
                            break
                        await pool.tick()
                        snapshot = self.progress.snapshot(run)
                        if snapshot["pending"] == 0 and snapshot["running"] == 0:
                            terminal = (
                                "failed"
                                if snapshot["errors"]
                                else (
                                    "cancelled"
                                    if snapshot["cancelled"]
                                    else "completed"
                                )
                            )
                            break
                        if now >= next_checkpoint:
                            self.checkpoints.save(run, "periodic")
                            next_checkpoint = now + row["checkpoint_seconds"]
                        if now >= next_flush:
                            self.aggregator.flush()
                            next_flush = now + 5
                        await asyncio.sleep(0.1)
                except asyncio.CancelledError:
                    terminal = "paused"
                    raise
                except Exception as exc:
                    terminal = "failed"
                    with self.db:
                        self.db.execute(
                            "UPDATE ResearchRuns SET error=? WHERE id=?",
                            (f"{type(exc).__name__}: {exc}", run),
                        )
                    raise
                finally:
                    await pool.shutdown()
                    with self.db:
                        self.db.execute(
                            "UPDATE ResearchRuns SET status=?,finished_at=?,elapsed=elapsed+?,heartbeat=? WHERE id=?",
                            (
                                terminal,
                                time.time(),
                                time.monotonic() - tick,
                                time.time(),
                                run,
                            ),
                        )
                        self.timeline.record(run, "research_" + terminal)
                    try:
                        self.aggregator.flush()
                        self.aggregator.report(run, self.progress.snapshot(run))
                    except Exception as exc:
                        terminal = "failed"
                        with self.db:
                            self.db.execute(
                                "UPDATE ResearchRuns SET status='failed',error=? WHERE id=?",
                                (f"Aggregation: {exc}", run),
                            )
                            self.timeline.record(
                                run, "aggregation_failed", details={"error": str(exc)}
                            )
                        raise
                    finally:
                        self.checkpoints.save(run, terminal)
                return self.progress.snapshot(run)
