"""Automatic offline CTF solution attempts on challenge files and ZIP members."""
from __future__ import annotations

import argparse
import json
import re
import stat
import zipfile
from pathlib import Path
from typing import Any

from ctf.solve import MAX_INPUT, solve_bytes
from ctf.triage import FLAG_PATTERN

MAX_FILES = 100
MAX_BYTES_TOTAL = 32 * 1024 * 1024
MAX_ZIP_ENTRIES = 50
MAX_ZIP_TOTAL = 8 * 1024 * 1024
MAX_ZIP_RATIO = 100


def solve_directory(
    source: Path, category: str = "unknown", flag_pattern: re.Pattern[bytes] = FLAG_PATTERN,
) -> dict[str, Any]:
    """Never execute challenge binaries or unpack ZIP members onto the disk."""
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise ValueError("Challenge source must be a directory")
    results: list[dict[str, Any]] = []
    warnings: list[str] = []
    processed = 0
    remaining = MAX_BYTES_TOTAL

    def solve_one(data: bytes, label: str) -> None:
        nonlocal processed
        if processed >= MAX_FILES:
            return
        processed += 1
        result = solve_bytes(data, category=category, flag_pattern=flag_pattern)
        for candidate in result["candidates"]:
            results.append({"source": label, **candidate})

    for path in sorted(source.rglob("*")):
        if processed >= MAX_FILES or remaining <= 0:
            warnings.append("scan limits reached")
            break
        if path.is_symlink() or not path.is_file():
            continue
        label = str(path.relative_to(source))
        try:
            with path.open("rb") as stream:
                sample = stream.read(min(MAX_INPUT + 1, remaining))
            remaining -= len(sample)
            # Do not scan raw ZIP bytes: unsafe entries may be stored without
            # compression and would bypass the member path safety checks.
            if path.suffix.lower() != ".zip":
                solve_one(sample, label)
                continue
            with zipfile.ZipFile(path) as archive:
                entries = archive.infolist()
                if len(entries) > MAX_ZIP_ENTRIES:
                    warnings.append(f"{label}: ZIP entry limit reached")
                zip_remaining = MAX_ZIP_TOTAL
                for entry in entries[:MAX_ZIP_ENTRIES]:
                    if processed >= MAX_FILES or zip_remaining <= 0 or remaining <= 0:
                        break
                    name = entry.filename
                    parts = name.replace("\\", "/").split("/")
                    unsafe = name.startswith(("/", "\\")) or ".." in parts or ":" in parts[0]
                    symlink = stat.S_ISLNK((entry.external_attr >> 16) & 0xFFFF)
                    ratio = entry.file_size / max(1, entry.compress_size)
                    if (unsafe or symlink or entry.is_dir() or bool(entry.flag_bits & 1)
                            or ratio > MAX_ZIP_RATIO or entry.file_size > MAX_INPUT):
                        warnings.append(f"{label}: skipped unsafe or oversized ZIP entry {name[:120]}")
                        continue
                    limit = min(entry.file_size, zip_remaining, remaining, MAX_INPUT)
                    with archive.open(entry) as zip_stream:
                        data = zip_stream.read(limit + 1)
                    if len(data) > limit:
                        warnings.append(f"{label}: ZIP entry exceeded declared budget")
                        continue
                    zip_remaining -= len(data)
                    remaining -= len(data)
                    solve_one(data, f"{label}!{name}")
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
            warnings.append(f"{label}: {exc}")
    return {"mode": "offline-no-execution", "files_processed": processed,
            "candidates": results, "candidate_count": len(results),
            "warnings": warnings, "verified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline automatic CTF solver")
    parser.add_argument("source", type=Path)
    parser.add_argument("--category", default="unknown")
    parser.add_argument("--flag-regex", help="Event-specific ASCII regular expression")
    args = parser.parse_args()
    try:
        regex = re.compile(args.flag_regex.encode("ascii")) if args.flag_regex else FLAG_PATTERN
        print(json.dumps(solve_directory(args.source, args.category, regex),
                         indent=2, ensure_ascii=False))
    except (OSError, ValueError, re.error) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
