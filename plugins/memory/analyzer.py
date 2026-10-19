"""Explicit-PID Linux process memory diagnostics, without reading address-space contents."""

import asyncio
import hashlib
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from core.models import Context
from database.checkpoints import CheckpointClient
from plugins.common import positive


def process_identity(proc: Path) -> str:
    """Read Linux starttime to detect PID reuse between diagnostic reads."""
    text = (proc / "stat").read_text()
    return text[text.rfind(")") + 2 :].split()[19]


class MemoryAnalyzer:
    """Capture permitted maps/status/statm/smaps_rollup for explicitly selected PIDs."""

    name = "memory"

    async def run(self, context: Context) -> dict[str, object]:
        """Record final and cancelled status while persisting each completed sample."""
        started = time.monotonic()
        try:
            result = await self._sample(context)
            status = "partial" if result["warnings"] else "completed"
            await self._save(
                context,
                status,
                {
                    **dict(result["statistics"]),
                    "elapsed_seconds": time.monotonic() - started,
                },
            )
            return result
        except asyncio.CancelledError:
            await self._save(
                context, "paused", {"elapsed_seconds": time.monotonic() - started}
            )
            raise
        except Exception:
            await self._save(
                context, "failed", {"elapsed_seconds": time.monotonic() - started}
            )
            raise

    async def _save(
        self,
        context: Context,
        status: str,
        progress: dict[str, Any],
        record: dict[str, Any] | None = None,
    ) -> None:
        """Commit one diagnostic snapshot and progress without retaining connections."""
        client = CheckpointClient(context, context.task_id or "memory", "memory")
        try:
            command: dict[str, Any] = {
                "status": status,
                "progress": json.dumps(progress),
            }
            if record:
                payload = json.dumps(record["analysis"])
                command.update(
                    path=record["path"],
                    digest=hashlib.sha256(payload.encode()).hexdigest(),
                    signature="fresh-process-diagnostics",
                    result=payload,
                )
            await client.request("sample" if record else "progress", **command)
        finally:
            client.close()

    async def _sample(self, context: Context) -> dict[str, Any]:
        """Take fresh diagnostics; never reuse stale live-process observations as cache."""
        options = context.plugin_options.get("memory", {})
        if options.get("authorized") is not True:
            raise ValueError(
                "Memory diagnostics require authorized: true and explicit pids"
            )
        pids = options.get("pids")
        if (
            not isinstance(pids, list)
            or not pids
            or not all(type(pid) is int and pid > 0 for pid in pids)
        ):
            raise ValueError("pids must contain explicit positive process IDs")
        if options.get("snapshots"):
            snapshots = options["snapshots"]
            if not isinstance(snapshots, list) or not all(
                isinstance(p, str) for p in snapshots
            ):
                raise ValueError("snapshots must be a list of paths within root")
            records = []
            snapshot_warnings: list[str] = []
            root = Path(context.root).resolve()
            for name in snapshots:
                await asyncio.sleep(0)
                path = (root / name).resolve()
                if not path.is_relative_to(root):
                    raise ValueError("Snapshot outside configured target")
                if path.stat().st_size > positive(
                    options, "max_file_bytes", 16 * 1024 * 1024
                ):
                    raise ValueError("Diagnostic snapshot exceeds byte budget")
                data = json.loads(path.read_text(encoding="utf-8"))
                if data.get("plugin") != "memory":
                    raise ValueError("Expected a memory diagnostic export")
                snapshot_warnings.extend(str(w) for w in data.get("warnings", []))
                for record in data["records"]:
                    if record["analysis"]["pid"] not in pids:
                        continue
                    record["analysis"]["provenance"] = (
                        "Previously captured diagnostic snapshot; not live memory"
                    )
                    records.append(record)
                    await self._save(
                        context, "running", {"processed": len(records)}, record
                    )
            observed = {r["analysis"]["pid"] for r in records}
            snapshot_warnings.extend(
                f"PID {pid}: not present in diagnostic snapshots"
                for pid in pids
                if pid not in observed
            )
            return {
                "plugin": "memory",
                "records": records,
                "files": [],
                "findings": [],
                "warnings": snapshot_warnings,
                "statistics": {
                    "processed": len(records),
                    "errors": len(snapshot_warnings),
                },
                "truncated": False,
            }
        if sys.platform == "win32" or not Path("/proc/self/stat").is_file():
            raise RuntimeError("Memory diagnostics require Linux procfs")
        limit = positive(options, "max_file_bytes", 16 * 1024 * 1024)
        records, warnings = [], []
        for pid in pids:
            await asyncio.sleep(0)
            proc = Path("/proc") / str(pid)
            logging.getLogger(__name__).info(
                "memory pid=%s inspecting diagnostic metadata", pid
            )
            try:
                identity = process_identity(proc)
                diagnostics: dict[str, Any] = {
                    "pid": pid,
                    "starttime": identity,
                    "captured_at": time.time(),
                }
                for name in ("maps", "status", "statm", "smaps_rollup"):
                    try:
                        with (proc / name).open("rb") as stream:
                            data = stream.read(limit + 1)
                        if len(data) > limit:
                            raise ValueError(f"{name} exceeds diagnostic limit")
                        text = data.decode("utf-8", errors="replace")
                        if name == "maps":
                            maps = []
                            for line in text.splitlines():
                                fields = line.split(None, 5)
                                maps.append(
                                    dict(
                                        zip(
                                            (
                                                "address_range",
                                                "permissions",
                                                "offset",
                                                "device",
                                                "inode",
                                                "path",
                                            ),
                                            fields,
                                        )
                                    )
                                )
                            diagnostics[name] = maps
                        elif name in ("status", "smaps_rollup"):
                            diagnostics[name] = {
                                k: v.strip()
                                for k, v in (
                                    line.split(":", 1)
                                    for line in text.splitlines()
                                    if ":" in line
                                )
                            }
                        else:
                            diagnostics[name] = {
                                "pages": [int(x) for x in text.split()],
                                "page_size": os.sysconf("SC_PAGE_SIZE")
                                if sys.platform != "win32"
                                else 0,
                            }
                    except PermissionError:
                        diagnostics[name] = {"unavailable": "permission denied"}
                        warnings.append(f"PID {pid}: no permission to read {name}")
                    except FileNotFoundError:
                        diagnostics[name] = {
                            "unavailable": "not available or process exited"
                        }
                if process_identity(proc) != identity:
                    raise RuntimeError("PID was reused during observation")
                records.append(
                    {"path": f"proc/{pid}@{identity}", "analysis": diagnostics}
                )
            except (OSError, ValueError, RuntimeError) as exc:
                warnings.append(f"PID {pid}: {exc}")
            await self._save(
                context,
                "running",
                {"processed": len(records), "errors": len(warnings)},
                records[-1] if records else None,
            )
        return {
            "plugin": "memory",
            "records": records,
            "files": [],
            "findings": [],
            "warnings": warnings,
            "statistics": {"processed": len(records), "errors": len(warnings)},
            "truncated": False,
            "checkpoint_semantics": "Diagnostics are fresh snapshots; after restart selected PIDs are revalidated and resampled",
        }
