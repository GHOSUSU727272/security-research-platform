"""Acknowledged checkpoint commands, serialized by the supervisor's SQLite owner."""

import asyncio
import json
import logging
import secrets
import sqlite3
import time
from contextlib import closing
from types import TracebackType
from typing import Any

from core.models import Context
from database.plugin_state import initialize_plugins

LOG = logging.getLogger(__name__)
# A 64 MiB cached JSON result can double when embedded as a JSON string.
MAX_MESSAGE = 128 * 1024 * 1024 + 65536


class PersistenceError(RuntimeError):
    """A checkpoint was not acknowledged; analysis must not silently continue."""


async def read_message(reader: asyncio.StreamReader) -> dict[str, Any]:
    """Read a length-prefixed JSON object within the transport memory budget."""
    size = int.from_bytes(await reader.readexactly(4), "big")
    if not 0 < size <= MAX_MESSAGE:
        raise ValueError("Checkpoint message exceeds transport budget")
    value: Any = json.loads(await reader.readexactly(size))
    if not isinstance(value, dict):
        raise ValueError("Checkpoint message must be an object")
    return value


async def write_message(writer: asyncio.StreamWriter, value: dict[str, Any]) -> None:
    """Send a bounded message, applying stream backpressure."""
    payload = json.dumps(value, ensure_ascii=False).encode()
    if len(payload) > MAX_MESSAGE:
        raise ValueError("Checkpoint message exceeds transport budget")
    writer.write(len(payload).to_bytes(4, "big"))
    writer.write(payload)
    await writer.drain()


def apply_command(
    db: sqlite3.Connection, namespace: str, plugin: str, command: dict[str, Any]
) -> str | None:
    """Execute one fixed command atomically; never yield or retain a read cursor."""
    operation = command["operation"]
    if operation == "get":
        with closing(
            db.execute(
                "SELECT result FROM PluginFileCache WHERE namespace=? AND plugin=? "
                "AND path=? AND digest=? AND signature=?",
                (
                    namespace,
                    plugin,
                    command["path"],
                    command["digest"],
                    command["signature"],
                ),
            )
        ) as cursor:
            row = cursor.fetchone()
            return str(row[0]) if row is not None else None
    if operation not in {"put", "progress", "sample"}:
        raise ValueError("Unknown checkpoint operation")
    if db.in_transaction:
        raise RuntimeError("Checkpoint command cannot join another transaction")
    with db:
        db.execute("BEGIN IMMEDIATE")
        now = time.time()
        if operation in {"progress", "sample"}:
            db.execute(
                "INSERT OR REPLACE INTO PluginProgress VALUES(?,?,?,?,?)",
                (namespace, plugin, command["status"], now, command["progress"]),
            )
        if operation in {"put", "sample"}:
            db.execute(
                "INSERT OR REPLACE INTO PluginFileCache VALUES(?,?,?,?,?,?,?)",
                (
                    namespace,
                    plugin,
                    command["path"],
                    command["digest"],
                    command["signature"],
                    command["result"],
                    now,
                ),
            )
    return None


class CheckpointWriter:
    """Bounded IPC queue consumed on the supervisor's existing SQLite-owning thread.

    SQLite calls are synchronous and contain no awaits, so they cannot overlap
    scheduler, aggregation or timeline transactions on the same event loop.
    The lifecycle must enclose the complete worker pool, including shutdown.
    """

    def __init__(self, db: sqlite3.Connection) -> None:
        """Attach to an initialized Store; do not open another database connection."""
        self.db = db
        self.endpoint = ""
        self.grants: dict[str, tuple[str, str]] = {}
        self.queue: asyncio.Queue[
            tuple[str, str, dict[str, Any], asyncio.Future[str | None]]
        ] = asyncio.Queue(maxsize=4)
        self.gate = asyncio.Semaphore(4)
        self.handlers: set[asyncio.Task[None]] = set()
        self.server: asyncio.Server | None = None
        self.consumer: asyncio.Task[None] | None = None

    async def __aenter__(self) -> "CheckpointWriter":
        """Start a loopback-only command endpoint and its single consumer."""
        self.server = await asyncio.start_server(self._accept, "127.0.0.1", 0)
        self.endpoint = str(self.server.sockets[0].getsockname()[1])
        self.consumer = asyncio.create_task(self._consume())
        LOG.info("Checkpoint writer started on supervisor thread")
        return self

    def grant(self, namespace: str, plugin: str) -> str:
        """Issue an ephemeral capability for exactly one task and plugin."""
        token = secrets.token_hex(32)
        self.grants[token] = (namespace, plugin)
        return token

    def revoke(self, token: str) -> None:
        """Retire a capability when its worker attempt has been reaped."""
        self.grants.pop(token, None)

    def _accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Track handlers so shutdown cannot leave a dangling connection or write."""
        task = asyncio.create_task(self._handle(reader, writer))
        self.handlers.add(task)

        def finished(completed: asyncio.Task[None]) -> None:
            """Close even a handler cancelled before its coroutine first ran."""
            self.handlers.discard(completed)
            writer.close()
            if not completed.cancelled():
                completed.exception()

        task.add_done_callback(finished)

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Authorize a command and reply only after the consumer committed it."""
        try:
            async with self.gate:
                # This bounds incomplete senders, not time spent awaiting a DB commit.
                async with asyncio.timeout(30):
                    request = await read_message(reader)
                scope = self.grants.get(request.get("token", ""))
                if (
                    scope != (request.get("namespace"), request.get("plugin"))
                    or scope is None
                ):
                    raise PermissionError("Invalid checkpoint capability")
                future: asyncio.Future[str | None] = (
                    asyncio.get_running_loop().create_future()
                )
                # A disconnected/cancelled handler may no longer observe a failure.
                # The consumer logs it, and this callback retrieves the exception.
                future.add_done_callback(lambda done: done.exception())
                await self.queue.put((*scope, request, future))
                result = await asyncio.shield(future)
                await write_message(writer, {"ok": True, "result": result})
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:
            try:
                await write_message(
                    writer, {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                )
            except (ConnectionError, ValueError):
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def _consume(self) -> None:
        """Serialize accepted operations with all other supervisor database work."""
        while True:
            namespace, plugin, command, future = await self.queue.get()
            try:
                result = apply_command(self.db, namespace, plugin, command)
            except Exception as exc:
                LOG.exception(
                    "Checkpoint commit failed task=%s plugin=%s", namespace, plugin
                )
                future.set_exception(exc)
            else:
                future.set_result(result)
            finally:
                self.queue.task_done()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Drain accepted writes, close incomplete senders and release the endpoint."""
        assert self.server is not None and self.consumer is not None
        self.server.close()
        for task in list(self.handlers):
            task.cancel()
        await asyncio.gather(*self.handlers, return_exceptions=True)
        # A handler may have queued a request just before it was cancelled.
        await self.queue.join()
        self.consumer.cancel()
        await asyncio.gather(self.consumer, return_exceptions=True)
        await self.server.wait_closed()
        self.grants.clear()
        LOG.info("Checkpoint writer stopped after draining accepted writes")


class CheckpointClient:
    """Use supervisor IPC in workers and a compatible local backend in standalone runs."""

    def __init__(self, context: Context, namespace: str, plugin: str) -> None:
        """Bind a namespace; IPC workers never open or initialize the project SQLite file."""
        self.context, self.namespace, self.plugin = context, namespace, plugin
        self.db: sqlite3.Connection | None = None
        if not context.checkpoint_endpoint and context.checkpoint_db:
            self.db = sqlite3.connect(context.checkpoint_db, timeout=30)
            try:
                initialize_plugins(self.db)
            except BaseException:
                self.db.close()
                raise

    async def request(self, operation: str, **values: Any) -> str | None:
        """Return only acknowledged data; transport/storage errors fail the task."""
        command = {"operation": operation, **values}
        try:
            if self.context.checkpoint_endpoint:
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", int(self.context.checkpoint_endpoint)
                )
                try:
                    await write_message(
                        writer,
                        {
                            **command,
                            "namespace": self.namespace,
                            "plugin": self.plugin,
                            "token": self.context.checkpoint_token,
                        },
                    )
                    response = await read_message(reader)
                    if response.get("ok") is not True:
                        raise PersistenceError(
                            str(response.get("error", "No commit acknowledgement"))
                        )
                    result = response.get("result")
                    if result is not None and not isinstance(result, str):
                        raise PersistenceError("Invalid checkpoint response")
                    return result
                finally:
                    writer.close()
                    await writer.wait_closed()
            if self.db is not None:
                return apply_command(self.db, self.namespace, self.plugin, command)
            return None
        except Exception as exc:
            raise PersistenceError(f"Checkpoint {operation} failed: {exc}") from exc

    def close(self) -> None:
        """Release the standalone backend; IPC connections are scoped to each request."""
        if self.db is not None:
            self.db.close()
