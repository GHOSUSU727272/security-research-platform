"""Bounded subprocess capture for explicit journal/Ghidra backend commands."""

import asyncio
import os
import signal
import sys
from contextlib import suppress


async def run_command(
    argv: list[str], timeout: int, limit: int, env: dict[str, str] | None = None
) -> tuple[bytes, bytes]:
    """Execute argv without shell and clean up process groups on cancellation."""
    own_group = (
        sys.platform != "win32" and os.environ.get("RESEARCH_PLATFORM_WORKER") != "1"
    )
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=own_group,
        env=env,
    )

    async def capture(stream: asyncio.StreamReader | None) -> bytes:
        """Fail explicitly when backend output exceeds the configured bound."""
        assert stream is not None
        output = bytearray()
        while chunk := await stream.read(65536):
            output.extend(chunk)
            if len(output) > limit:
                raise ValueError("Backend output limit exceeded")
        return bytes(output)

    readers = [
        asyncio.create_task(capture(process.stdout)),
        asyncio.create_task(capture(process.stderr)),
    ]
    try:
        async with asyncio.timeout(timeout):
            stdout, stderr = await asyncio.gather(*readers)
            code = await process.wait()
        if code:
            raise RuntimeError(
                f"Backend exit {code}: {stderr[-2000:].decode(errors='replace')}"
            )
        return stdout, stderr
    finally:
        if process.returncode is None or own_group:
            with suppress(ProcessLookupError):
                if sys.platform != "win32" and own_group:
                    os.killpg(process.pid, signal.SIGTERM)
                else:
                    process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 2)
            except TimeoutError:
                with suppress(ProcessLookupError):
                    if sys.platform != "win32" and own_group:
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                await process.wait()
            if sys.platform != "win32" and own_group:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
        for task in readers:
            task.cancel()
        await asyncio.gather(*readers, return_exceptions=True)
