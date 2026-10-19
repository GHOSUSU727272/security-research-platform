"""Isolated worker entry point; accepts only supervisor-created JSON task files."""

import asyncio
import json
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

from core.models import Context
from plugins import registry


async def execute(input_path: Path, output_path: Path) -> None:
    """Run one trusted installed plugin and atomically write its JSON result."""
    request = json.loads(input_path.read_text(encoding="utf-8"))
    os.environ["RESEARCH_PLATFORM_WORKER"] = "1"
    if sys.platform != "win32":
        parent = request["parent_pid"]

        def monitor_parent() -> None:
            """Cancel an orphan worker; force exit if trusted plugin cleanup hangs."""
            while os.getppid() == parent:
                time.sleep(0.5)
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(2.5)
            os._exit(1)

        threading.Thread(target=monitor_parent, daemon=True).start()
    data = request["context"]
    data["excluded"] = tuple(data["excluded"])
    data["command"] = tuple(data["command"])
    plugin = registry(request["allow_dynamic"])[request["plugin"]]
    task = asyncio.create_task(plugin.run(Context(**data)))
    if sys.platform != "win32":
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGTERM, task.cancel)
        loop.add_signal_handler(signal.SIGINT, task.cancel)
    result = await task
    if not isinstance(result, dict):
        raise ValueError("Plugin output must be a JSON mapping")
    temporary = output_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, output_path)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    asyncio.run(execute(Path(sys.argv[1]), Path(sys.argv[2])))
