"""Concurrent durable job execution with timeout and progress heartbeats."""

import asyncio
import json
import logging
from contextlib import suppress

from core.config import Settings
from core.models import Context, Plugin
from database.store import Store

LOG = logging.getLogger(__name__)


class Scheduler:
    """Dispatch registered plugins with bounded async concurrency."""

    def __init__(
        self, store: Store, settings: Settings, plugins: dict[str, Plugin]
    ) -> None:
        """Bind dependencies without importing concrete analysis plugins."""
        self.store, self.settings, self.plugins = store, settings, plugins

    async def run(self) -> None:
        """Drain the durable queue; cancellation leaves recoverable leases."""
        await asyncio.gather(*(self.worker() for _ in range(self.settings.workers)))

    async def pulse(self, job: int) -> None:
        """Record liveness periodically while the plugin yields control."""
        while True:
            await asyncio.sleep(5)
            self.store.heartbeat(job, 30)
            LOG.info("job=%s heartbeat", job)

    async def worker(self) -> None:
        """Isolate task errors so unrelated queued tasks continue."""
        while True:
            row = self.store.claim(self.settings.attempts, 30)
            if row is None:
                if any(j["status"] == "running" for j in self.store.jobs()):
                    await asyncio.sleep(1)
                    continue
                return
            job = row["id"]
            LOG.info("job=%s plugin=%s started", job, row["plugin"])
            pulse = asyncio.create_task(self.pulse(job))
            try:
                data = json.loads(row["context"])
                data["excluded"] = tuple(data["excluded"])
                data["command"] = tuple(data["command"])
                async with asyncio.timeout(self.settings.timeout):
                    result = await self.plugins[row["plugin"]].run(Context(**data))
                self.store.finish(job, result)
                LOG.info("job=%s completed", job)
            except Exception as exc:
                self.store.fail(
                    job, f"{type(exc).__name__}: {exc}", self.settings.attempts
                )
                LOG.exception("job=%s failed", job)
                await asyncio.sleep(0.1)
            finally:
                pulse.cancel()
                with suppress(asyncio.CancelledError):
                    await pulse
