"""Watch a local challenge inbox and analyze new folders without networking."""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from ctf.challenges import add, analyze, load, save


def fingerprint(source: Path) -> str:
    """Fingerprint paths, sizes and modification times, without reading contents."""
    digest = hashlib.sha256()
    for idx, path in enumerate(sorted(source.rglob("*"))):
        if idx >= 10000:
            digest.update(b"scan-limit")
            break
        if path.is_symlink() or not path.is_file():
            continue
        stat = path.stat()
        digest.update(str(path.relative_to(source)).encode("utf-8"))
        digest.update(f":{stat.st_size}:{stat.st_mtime_ns};".encode("ascii"))
    return digest.hexdigest()


def run_once(inbox: Path, workspace: Path) -> dict[str, Any]:
    inbox = inbox.resolve(strict=True)
    if not inbox.is_dir():
        raise ValueError("Inbox must be a directory")
    if workspace.resolve().is_relative_to(inbox):
        raise ValueError("Workspace must be outside inbox")
    result: dict[str, Any] = {"added": [], "analyzed": [], "errors": []}
    known = load(workspace)["challenges"]
    for source in sorted(inbox.iterdir()):
        if source.is_symlink() or not source.is_dir() or source.name.startswith("."):
            continue
        slug = source.name
        if slug not in known:
            try:
                add(workspace, slug, source)
                result["added"].append(slug)
            except (ValueError, OSError) as exc:
                result["errors"].append({"id": slug, "error": str(exc)})
                continue
        item = load(workspace)["challenges"].get(slug)
        if item:
            try:
                signature = fingerprint(source)
                if item["status"] != "new" and item.get("input_signature") == signature:
                    continue
                analyze(workspace, slug)
                data = load(workspace)
                data["challenges"][slug]["input_signature"] = signature
                save(workspace, data)
                result["analyzed"].append(slug)
            except (ValueError, OSError) as exc:
                result["errors"].append({"id": slug, "error": str(exc)})
    return result

def main() -> None:
    parser = argparse.ArgumentParser(description="Offline CTF inbox watcher")
    parser.add_argument("inbox", type=Path)
    parser.add_argument("--workspace", type=Path, default=Path("ctf-workspace"))
    parser.add_argument("--interval", type=float, default=10.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.interval <= 3600:
        parser.error("Interval must be between 1 and 3600 seconds")
    try:
        while True:
            print(json.dumps(run_once(args.inbox, args.workspace)), flush=True)
            if args.once:
                break
            time.sleep(args.interval)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        return

if __name__ == "__main__":
    main()
