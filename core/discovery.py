"""Linux package-owned installation discovery and offline research snapshots."""

import argparse
import asyncio
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from core.models import Context


def command(arguments: list[str]) -> tuple[str, str, int]:
    """Run a standard local Linux inventory command without shell expansion."""
    result = subprocess.run(
        arguments, capture_output=True, text=True, errors="replace", timeout=120
    )
    return result.stdout, result.stderr, result.returncode


def discover(package: str) -> dict[str, Any]:
    """Derive paths from dpkg ownership, then inspect processes and Unix sockets."""
    if sys.platform != "linux":
        raise RuntimeError("Package discovery requires Linux")
    listing, error, code = command(["dpkg-query", "-L", package])
    if code:
        raise ValueError(error)
    version, _, _ = command(["dpkg-query", "-W", "-f=${Version}", package])
    roots: set[Path] = set()
    for name in listing.splitlines():
        path = Path(name)
        for i, part in enumerate(path.parts):
            if part == package or part.startswith(package + "-"):
                root = Path(*path.parts[: i + 1])
                if root.is_dir():
                    roots.add(root)
                break
    roots = {r for r in roots if not any(p in roots for p in r.parents)}
    found: set[Path] = set()
    warnings = []
    for root in sorted(roots):
        output, error, code = command(
            ["find", "-P", str(root), "-type", "f", "-o", "-type", "l"]
        )
        if code:
            warnings.append(error.strip())
        found.update(Path(p).resolve() for p in output.splitlines())
    # Explicit package file names remain usable even when directory listing is denied.
    found.update(Path(p).resolve() for p in listing.splitlines() if Path(p).is_file())
    records = []
    for path in sorted(found):
        try:
            if not path.is_file() or not any(
                path.is_relative_to(r.resolve()) for r in roots
            ):
                continue
            with path.open("rb") as stream:
                magic = stream.read(16)
            category = "file"
            if magic.startswith(b"\x7fELF"):
                category = "library" if ".so" in path.name else "binary"
            elif magic == b"SQLite format 3\x00":
                category = "sqlite"
            elif path.suffix.lower() in {
                ".yaml",
                ".yml",
                ".json",
                ".xml",
                ".ini",
                ".toml",
                ".conf",
                ".cfg",
            }:
                category = "config"
            elif path.suffix in {".log", ".journal", ".jsonl"} or "log" in path.parts:
                category = "log"
            records.append(
                {"path": str(path), "category": category, "bytes": path.stat().st_size}
            )
        except OSError as exc:
            warnings.append(f"{path}: {exc}")
    processes, _, _ = command(["ps", "-eo", "pid=,ppid=,user=,comm=,args="])
    selected: list[dict[str, Any]] = []
    for line in processes.splitlines():
        fields = line.strip().split(None, 4)
        if len(fields) != 5 or not any(str(root) + "/" in fields[4] for root in roots):
            continue
        pid = int(fields[0])
        executable, exe_error, _ = command(["readlink", "-f", f"/proc/{pid}/exe"])
        selected.append(
            {
                "pid": pid,
                "ppid": int(fields[1]),
                "user": fields[2],
                "comm": fields[3],
                "arguments": fields[4],
                "executable": executable.strip(),
                "access_error": exe_error,
            }
        )
    sockets, socket_error, _ = command(["ss", "-xlnp"])
    names = {p["comm"] for p in selected}
    sockets = "\n".join(
        line
        for line in sockets.splitlines()
        if any(n in line for n in names) or package in line
    )
    if socket_error:
        warnings.append(socket_error)
    return {
        "package": package,
        "version": version.strip(),
        "captured_at": time.time(),
        "uid": os.getuid(),
        "roots": [str(r) for r in sorted(roots)],
        "files": records,
        "processes": selected,
        "sockets": sockets,
        "warnings": warnings,
    }


def snapshot(manifest: dict[str, Any], output: Path, max_bytes: int) -> None:
    """Copy a bounded, package-scoped corpus; take consistent SQLite backups."""
    from plugins.memory.analyzer import MemoryAnalyzer

    target = output / "target"
    target.mkdir(parents=True, exist_ok=True)
    total = 0
    copied = []
    for record in manifest["files"]:
        source = Path(record["path"])
        if total + record["bytes"] > max_bytes:
            manifest["warnings"].append(f"Snapshot budget exceeded: {source}")
            continue
        destination = target / source.relative_to("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            if record["category"] == "sqlite":
                src = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
                dst = sqlite3.connect(destination)
                start = time.monotonic()

                def budget(status: int, remaining: int, total_pages: int) -> None:
                    """Interrupt a busy live database backup after thirty seconds."""
                    if time.monotonic() - start > 30:
                        raise TimeoutError("SQLite snapshot timed out")

                try:
                    src.backup(dst, pages=256, progress=budget)
                finally:
                    src.close()
                    dst.close()
            else:
                before = source.stat()
                shutil.copyfile(source, destination)
                after = source.stat()
                if (before.st_size, before.st_mtime_ns) != (
                    after.st_size,
                    after.st_mtime_ns,
                ):
                    manifest["warnings"].append(
                        f"Changed while copying: {source}; inspect as non-atomic snapshot"
                    )
            with destination.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            total += destination.stat().st_size
            copied.append(
                {
                    **record,
                    "relative": destination.relative_to(target).as_posix(),
                    "sha256": digest,
                }
            )
        except (OSError, sqlite3.Error, TimeoutError) as exc:
            manifest["warnings"].append(f"Snapshot {source}: {exc}")
            destination.unlink(missing_ok=True)
    pids = [p["pid"] for p in manifest["processes"]]
    if pids:
        context = Context(
            str(target),
            16777216,
            (),
            plugin_options={"memory": {"authorized": True, "pids": pids}},
        )
        result = asyncio.run(MemoryAnalyzer().run(context))
        (target / "process-diagnostics.json").write_text(
            json.dumps(result, ensure_ascii=False), encoding="utf-8"
        )
    manifest["snapshot"] = copied
    manifest["snapshot_bytes"] = total


def main() -> None:
    """Discover an installed package and optionally collect a researcher-owned snapshot."""
    if sys.platform != "linux":
        raise RuntimeError("Package discovery requires Linux")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--snapshot", action="store_true")
    parser.add_argument("--max-bytes", type=int, default=4 * 1024**3)
    args = parser.parse_args()
    if not args.package or args.package.startswith("-") or args.max_bytes <= 0:
        parser.error("Explicit package and positive byte budget required")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    manifest = discover(args.package)
    if args.snapshot:
        snapshot(manifest, output, args.max_bytes)
    (output / "discovery.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    # sudo supplies the original caller; only the freshly created output is handed back.
    if os.getuid() == 0 and "SUDO_UID" in os.environ:
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
        for path in [output, *output.rglob("*")]:
            os.chown(path, uid, gid)
    print(
        json.dumps(
            {
                "output": str(output),
                "files": len(manifest["files"]),
                "pids": [p["pid"] for p in manifest["processes"]],
                "warnings": len(manifest["warnings"]),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
