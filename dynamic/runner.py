"""Bounded subprocess observation; Linux process-group cleanup on cancellation."""

import asyncio
import hashlib
import os
import signal
import sys
import time

from core.models import Context


class DynamicPlugin:
    """Run an authorized argument vector without shell interpolation."""

    async def run(self, context: Context) -> dict[str, object]:
        """Capture bounded output while draining pipes to prevent deadlocks."""
        if not context.command:
            raise ValueError("Explicit dynamic command required")
        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *context.command,
            cwd=context.root,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=os.name == "posix",
        )

        async def capture(stream: asyncio.StreamReader | None) -> dict[str, object]:
            """Retain a prefix and hash the complete stream using constant memory."""
            assert stream is not None
            saved = bytearray()
            digest = hashlib.sha256()
            total = 0
            while block := await stream.read(8192):
                total += len(block)
                digest.update(block)
                saved.extend(block[: max(0, context.max_log_bytes - len(saved))])
            return {
                "text": saved.decode("utf-8", errors="replace"),
                "sha256": digest.hexdigest(),
                "bytes": total,
                "truncated": total > len(saved),
            }

        readers = [
            asyncio.create_task(capture(process.stdout)),
            asyncio.create_task(capture(process.stderr)),
        ]
        try:
            code = await process.wait()
            stdout, stderr = await asyncio.gather(*readers)
        finally:
            if sys.platform != "win32":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            elif process.returncode is None:
                process.kill()
            await process.wait()
            for reader in readers:
                reader.cancel()
            await asyncio.gather(*readers, return_exceptions=True)
        return {
            "returncode": code,
            "stdout": stdout,
            "stderr": stderr,
            "duration": time.monotonic() - started,
            "findings": [],
        }
