"""Bounded process-per-task execution with hard timeout and cancellation cleanup."""

import asyncio
import json
import os
import signal
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from core.research.artifacts import ArtifactManager, ResultAggregator
from core.research.scheduler import TaskScheduler
from core.research.state import ResearchTimeline
from database.checkpoints import CheckpointWriter


class ProcessExecutor:
    """Launch independent Python workers and retain bounded diagnostic output."""

    def __init__(
        self,
        base: Path,
        artifacts: ArtifactManager,
        allow_dynamic: bool,
        writer: CheckpointWriter | None = None,
    ) -> None:
        """Configure per-attempt scratch space and explicit dynamic-analysis opt-in."""
        self.base, self.artifacts, self.allow_dynamic = base, artifacts, allow_dynamic
        self.writer = writer

    async def execute(self, task: dict[str, Any]) -> dict[str, object]:
        """Execute one process; cancellation terminates and reaps it before returning."""
        if self.writer is None:
            async with CheckpointWriter(self.artifacts.knowledge.db) as writer:
                executor = ProcessExecutor(
                    self.base, self.artifacts, self.allow_dynamic, writer
                )
                return await executor.execute(task)
        token = self.writer.grant(task["id"], task["plugin"])
        try:
            return await self._execute(task, token)
        finally:
            self.writer.revoke(token)

    async def _execute(self, task: dict[str, Any], token: str) -> dict[str, object]:
        """Keep the checkpoint capability valid until the child is fully reaped."""
        assert self.writer is not None
        scratch = self.base / "engine-work"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            folder = Path(temporary)
            request, output = folder / "input.json", folder / "output.json"
            plugin_context = json.loads(task["context"])
            plugin_context["checkpoint_db"] = str(self.base / "research.sqlite3")
            plugin_context["task_id"] = task["id"]
            plugin_context["checkpoint_endpoint"] = self.writer.endpoint
            plugin_context["checkpoint_token"] = token
            request.write_text(
                json.dumps(
                    {
                        "plugin": task["plugin"],
                        "context": plugin_context,
                        "allow_dynamic": self.allow_dynamic,
                        "parent_pid": os.getpid(),
                    }
                ),
                encoding="utf-8",
            )
            launch = asyncio.create_task(
                asyncio.create_subprocess_exec(
                    sys.executable,
                    "-m",
                    "core.research.worker",
                    str(request),
                    str(output),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    start_new_session=os.name == "posix",
                )
            )
            interrupted = False
            try:
                process = await asyncio.shield(launch)
            except asyncio.CancelledError:
                # Reap a child even when the deadline expires during process creation.
                process = await launch
                interrupted = True
            captured = bytearray()

            async def drain() -> None:
                """Drain all output while retaining only the first 64 KiB."""
                assert process.stdout is not None
                while block := await process.stdout.read(8192):
                    captured.extend(block[: max(0, 65536 - len(captured))])

            reader = asyncio.create_task(drain())
            try:
                if interrupted:
                    raise asyncio.CancelledError
                with self.artifacts.knowledge.db:
                    ResearchTimeline(self.artifacts.knowledge.db).record(
                        task["run_id"],
                        "worker_process",
                        task["id"],
                        {"pid": process.pid},
                    )
                code = await process.wait()
                await reader
                if code != 0:
                    raise RuntimeError(
                        f"Worker exited {code}: {captured.decode('utf-8', errors='replace')[-2000:]}"
                    )
                if not output.is_file() or output.stat().st_size > 128 * 1024 * 1024:
                    raise ValueError("Missing worker output or result exceeds 128 MiB")
                result: Any = json.loads(output.read_text(encoding="utf-8"))
                if not isinstance(result, dict):
                    raise ValueError("Invalid worker result")
                return result
            finally:
                if process.returncode is None:
                    try:
                        if sys.platform != "win32":
                            os.killpg(process.pid, signal.SIGTERM)
                        else:
                            process.terminate()
                    except ProcessLookupError:
                        pass
                    try:
                        await asyncio.wait_for(process.wait(), 2)
                    except TimeoutError:
                        if sys.platform != "win32":
                            os.killpg(process.pid, signal.SIGKILL)
                        else:
                            process.kill()
                        await process.wait()
                if sys.platform != "win32":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                reader.cancel()
                await asyncio.gather(reader, return_exceptions=True)
                artifact = self.artifacts.publish(
                    f"{task['task_key']} attempt {task['attempts']} log",
                    bytes(captured),
                    "worker-log",
                    {
                        "run_id": task["run_id"],
                        "task_id": task["id"],
                        "attempt": task["attempts"],
                    },
                )
                with self.artifacts.knowledge.db:
                    ResearchTimeline(self.artifacts.knowledge.db).record(
                        task["run_id"],
                        "worker_log",
                        task["id"],
                        {"artifact_id": artifact, "attempt": task["attempts"]},
                    )


class WorkerPool:
    """Maintain at most N active attempts, with one isolated worker per task."""

    def __init__(
        self,
        scheduler: TaskScheduler,
        executor: ProcessExecutor,
        aggregator: ResultAggregator,
        workers: int,
    ) -> None:
        """Inject scheduling, execution and result publication independently."""
        self.scheduler, self.executor, self.aggregator = scheduler, executor, aggregator
        self.workers = workers
        self.active: dict[str, asyncio.Task[None]] = {}

    async def attempt(self, task: dict[str, Any]) -> None:
        """Apply timeout, retries and cancellation to one complete worker lifetime."""
        started = time.monotonic()
        try:
            async with asyncio.timeout(task["timeout"]):
                result = await self.executor.execute(task)
            self.aggregator.complete(task, result, time.monotonic() - started)
        except asyncio.CancelledError:
            self.scheduler.interrupted(task["id"], time.monotonic() - started)
            with self.scheduler.db:
                self.scheduler.db.execute(
                    "UPDATE PluginProgress SET status='paused',updated=? WHERE namespace=?",
                    (time.time(), task["id"]),
                )
        except Exception as exc:
            self.scheduler.failure(
                task["id"], f"{type(exc).__name__}: {exc}", time.monotonic() - started
            )
            with self.scheduler.db:
                self.scheduler.db.execute(
                    "UPDATE PluginProgress SET status='failed',updated=? WHERE namespace=?",
                    (time.time(), task["id"]),
                )

    async def tick(self) -> None:
        """Reap finished attempts, observe task cancellation and fill free slots."""
        for identifier, task in list(self.active.items()):
            if task.done():
                await task
                del self.active[identifier]
            elif self.scheduler.db.execute(
                "SELECT cancel_requested FROM ResearchTasks WHERE id=?", (identifier,)
            ).fetchone()[0]:
                if not task.cancelling():
                    task.cancel()
        while len(self.active) < self.workers:
            task_row = self.scheduler.claim(f"worker-{uuid.uuid4().hex[:8]}")
            if task_row is None:
                break
            self.active[task_row["id"]] = asyncio.create_task(self.attempt(task_row))

    async def shutdown(self) -> None:
        """Cancel and reap all active processes before the manager releases its lock."""
        for task in self.active.values():
            if not task.cancelling():
                task.cancel()
        await asyncio.gather(*self.active.values(), return_exceptions=False)
        self.active.clear()
