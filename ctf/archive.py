"""Read-only ZIP manifest with zip-bomb and traversal indicators."""
from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path
from typing import Any

MAX_ENTRIES = 10000
MAX_UNCOMPRESSED = 512 * 1024 * 1024
MAX_RATIO = 1000

def inspect_zip(path: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    total = 0
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            name = info.filename
            parts = name.replace("\\", "/").split("/")
            traversal = name.startswith(("/", "\\")) or ".." in parts or ":" in parts[0]
            total += info.file_size
            ratio = info.file_size / max(info.compress_size, 1)
            entries.append({"name": name, "size": info.file_size,
                            "compressed": info.compress_size, "ratio": round(ratio, 1),
                            "unsafe_path": traversal, "encrypted": bool(info.flag_bits & 1)})
            if len(entries) > MAX_ENTRIES:
                raise ValueError("Archive exceeds maximum entry count")
    warnings = []
    if total > MAX_UNCOMPRESSED:
        warnings.append("uncompressed size exceeds safe inspection threshold")
    if any(entry["ratio"] > MAX_RATIO for entry in entries):
        warnings.append("extreme compression ratio")
    if any(entry["unsafe_path"] for entry in entries):
        warnings.append("unsafe archive paths")
    if any(entry["encrypted"] for entry in entries):
        warnings.append("encrypted entries")
    return {"archive": str(path), "entries": entries, "total_uncompressed": total,
            "warnings": warnings, "extracted": False}

def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect ZIP without extraction")
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(inspect_zip(args.archive), indent=2, ensure_ascii=False))
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))

if __name__ == "__main__":
    main()
