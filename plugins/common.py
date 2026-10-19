"""Shared file traversal, durable checkpoints and result contracts for analyzers."""

import asyncio
import fnmatch
import hashlib
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

from core.models import Context
from database.checkpoints import CheckpointClient, PersistenceError

LOG = logging.getLogger(__name__)


def positive(options: dict[str, Any], name: str, default: int) -> int:
    """Validate a positive integer option rather than silently coercing YAML types."""
    value = options.get(name, default)
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def json_value(value: Any) -> Any:
    """Convert parser containers and byte payloads to portable evidence values."""
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    if isinstance(value, Mapping):
        return {
            str(k): json_value(v)
            for k, v in value.items()
            if not str(k).startswith("_")
        }
    if isinstance(value, (list, tuple)):
        return [json_value(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


class FileAnalyzer(ABC):
    """Independent plugin base with per-file content-validated restart checkpoints."""

    name: str
    version = "1"

    def accepts(self, path: Path, options: dict[str, Any]) -> bool:
        """Allow all regular files unless a concrete analyzer limits its formats."""
        return True

    @abstractmethod
    async def analyze(self, path: Path, options: dict[str, Any]) -> dict[str, Any]:
        """Read one file without modifying it and return structured evidence."""
        raise NotImplementedError

    async def run(self, context: Context) -> dict[str, object]:
        """Analyze eligible files, reuse valid checkpoints and persist live progress."""
        root = Path(context.root).resolve()
        if not root.is_dir():
            raise ValueError("Analyzer root must be a directory")
        options = context.plugin_options.get(self.name, {})
        max_files = positive(options, "max_files", 10000)
        max_size = positive(options, "max_file_bytes", context.max_file_bytes)
        max_output = positive(options, "max_result_bytes", 64 * 1024 * 1024)
        include, exclude = options.get("include", ["*"]), options.get("exclude", [])
        if not all(
            isinstance(v, list) and all(isinstance(p, str) for p in v)
            for v in (include, exclude)
        ):
            raise ValueError("include/exclude must be lists of glob patterns")
        signature = hashlib.sha256(
            json.dumps([self.version, options, max_size], sort_keys=True).encode()
        ).hexdigest()
        namespace = context.task_id or hashlib.sha256(str(root).encode()).hexdigest()
        client = CheckpointClient(context, namespace, self.name)
        records: list[dict[str, Any]] = []
        files: list[dict[str, Any]] = []
        warnings: list[str] = []
        stats: dict[str, Any] = {
            "processed": 0,
            "cached": 0,
            "skipped": 0,
            "errors": 0,
            "bytes": 0,
        }
        started = time.monotonic()
        truncated = False
        output_bytes = 0

        async def progress(status: str, current: str = "") -> None:
            """Acknowledge durable counters before advancing the worker."""
            stats["elapsed_seconds"] = round(time.monotonic() - started, 3)
            await client.request(
                "progress",
                status=status,
                progress=json.dumps({**stats, "current_file": current}),
            )

        LOG.info("plugin=%s started root=%s", self.name, root)

        def walk_error(error: OSError) -> None:
            """Surface inaccessible directories instead of reporting empty success."""
            stats["errors"] += 1
            warnings.append(f"Traversal: {error}")
            LOG.warning("plugin=%s traversal error=%s", self.name, error)

        def candidates() -> Iterator[tuple[str, list[str], list[str]]]:
            """Allow efficient exact-file tasks while enforcing the same target scope."""
            selected = options.get("files")
            if selected is None:
                yield from os.walk(root, followlinks=False, onerror=walk_error)
                return
            if not isinstance(selected, list) or not all(
                isinstance(p, str) for p in selected
            ):
                raise ValueError("files must be a list of relative target paths")
            for name in dict.fromkeys(selected):
                path = root / name
                if Path(name).is_absolute() or not path.resolve().is_relative_to(root):
                    raise ValueError("Explicit file outside target root")
                if any(part in context.excluded for part in Path(name).parts[:-1]):
                    continue
                if not path.is_file():
                    walk_error(FileNotFoundError(str(path)))
                    continue
                yield str(path.parent), [], [path.name]

        try:
            await progress("running")
            stop = False
            for directory, dirs, names in candidates():
                dirs[:] = sorted(
                    d
                    for d in dirs
                    if d not in context.excluded
                    and not (Path(directory) / d).is_symlink()
                )
                for name in sorted(names):
                    await asyncio.sleep(0)
                    path = Path(directory) / name
                    relative = path.relative_to(root).as_posix()
                    if path.is_symlink() or not path.is_file():
                        continue
                    if context.checkpoint_db and path.resolve() in {
                        Path(context.checkpoint_db).resolve(),
                        Path(context.checkpoint_db + "-wal").resolve(),
                        Path(context.checkpoint_db + "-shm").resolve(),
                    }:
                        continue
                    if not any(
                        fnmatch.fnmatchcase(relative, p) for p in include
                    ) or any(fnmatch.fnmatchcase(relative, p) for p in exclude):
                        continue
                    try:
                        if not self.accepts(path, options):
                            continue
                        if stats["processed"] + stats["errors"] >= max_files:
                            truncated, stop = True, True
                            break
                        before = path.stat()
                        if before.st_size > max_size:
                            truncated = True
                            stats["skipped"] += 1
                            warnings.append(f"{relative}: exceeds max_file_bytes")
                            continue
                        digest = hashlib.sha256()
                        read = 0
                        with path.open("rb") as stream:
                            while chunk := stream.read(1024 * 1024):
                                read += len(chunk)
                                if read > max_size:
                                    raise ValueError("File grew beyond size limit")
                                digest.update(chunk)
                                await asyncio.sleep(0)
                        sha = digest.hexdigest()
                        cached = await client.request(
                            "get",
                            path=relative,
                            digest=sha,
                            signature=signature,
                        )
                        detail = (
                            json.loads(cached)
                            if cached is not None
                            else await self.analyze(path, options)
                        )
                        after = path.stat()
                        if (before.st_size, before.st_mtime_ns) != (
                            after.st_size,
                            after.st_mtime_ns,
                        ):
                            raise ValueError(
                                "File changed while analyzing; retry against a stable copy"
                            )
                        serialized = json.dumps(detail, ensure_ascii=False)
                        if output_bytes + len(serialized.encode()) > max_output:
                            truncated, stop = True, True
                            warnings.append(
                                "Result budget reached; remaining files were not processed"
                            )
                            break
                        output_bytes += len(serialized.encode())
                        if cached is None:
                            await client.request(
                                "put",
                                path=relative,
                                digest=sha,
                                signature=signature,
                                result=serialized,
                            )
                        item = {"path": relative, "sha256": sha, "size": read}
                        files.append(item)
                        records.append({**item, "analysis": detail})
                        stats["processed"] += 1
                        stats["cached"] += int(cached is not None)
                        stats["bytes"] += read
                        truncated = truncated or bool(detail.get("truncated", False))
                        LOG.info(
                            "plugin=%s file=%s completed cached=%s",
                            self.name,
                            relative,
                            bool(cached),
                        )
                    except PersistenceError:
                        raise
                    except Exception as exc:
                        stats["errors"] += 1
                        warnings.append(f"{relative}: {type(exc).__name__}: {exc}")
                        LOG.warning(
                            "plugin=%s file=%s error=%s", self.name, relative, exc
                        )
                    await progress("running", relative)
                if stop:
                    break
            await progress("partial" if stats["errors"] or truncated else "completed")
            return {
                "plugin": self.name,
                "records": records,
                "files": files,
                "findings": [],
                "statistics": stats,
                "warnings": warnings,
                "truncated": truncated,
            }
        except asyncio.CancelledError:
            await progress("paused")
            LOG.info(
                "plugin=%s cancelled after=%s files", self.name, stats["processed"]
            )
            raise
        finally:
            client.close()
