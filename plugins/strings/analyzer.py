"""Offset-preserving ASCII, UTF-8 and UTF-16 extraction with evidence categories."""

import asyncio
import codecs
import ipaddress
import re
from pathlib import Path
from typing import Any

from plugins.common import FileAnalyzer, positive


def classify(text: str) -> list[str]:
    """Assign nonexclusive semantic labels without resolving URLs or hostnames."""
    labels = []
    patterns = {
        "url": r"\b[a-zA-Z][a-zA-Z0-9+.-]*://\S+",
        "path": r"(?:^|\s)(?:/|[A-Za-z]:[\\/])\S+",
        "unix_socket": r"(?:unix:|\.sock\b|/run/|/var/run/)",
        "filename": r"(?:^|[/\\\s])[\w.-]+\.[A-Za-z0-9]{1,10}(?:$|\s)",
        "environment": r"(?:\$\{?[A-Z_][A-Z0-9_]*\}?|\b[A-Z_][A-Z0-9_]*=)",
        "log_message": r"\b(?:error|warning|fatal|debug|failed|denied|exception|info)\b",
        "library": r"\b(?:lib[^\s/]+\.so(?:\.[0-9]+)*|[\w.-]+\.(?:dll|dylib))\b",
    }
    for label, pattern in patterns.items():
        if re.search(pattern, text, re.I if label == "log_message" else 0):
            labels.append(label)
    for candidate in re.findall(r"[0-9a-fA-F:.]{3,}", text):
        try:
            ipaddress.ip_address(candidate)
            labels.append("ip")
            break
        except ValueError:
            continue
    return labels


class StringsAnalyzer(FileAnalyzer):
    """Extract printable Unicode runs, exact byte offsets and multiple categories."""

    name = "strings"
    version = "2"

    async def analyze(self, path: Path, options: dict[str, Any]) -> dict[str, Any]:
        """Scan configured encodings, preserving invalid-byte boundaries and offsets."""
        minimum = positive(options, "min_length", 4)
        maximum = positive(options, "max_length", 4096)
        limit = positive(options, "max_records", 10000)
        encodings = options.get(
            "encodings", ["ascii", "utf-8", "utf-16-le", "utf-16-be"]
        )
        if (
            not isinstance(encodings, list)
            or not encodings
            or not all(
                e in {"ascii", "utf-8", "utf-16-le", "utf-16-be"} for e in encodings
            )
        ):
            raise ValueError("Unsupported string encoding")
        if maximum < minimum:
            raise ValueError("max_length must be at least min_length")
        records: list[dict[str, Any]] = []
        truncated = False
        modes = [
            (encoding, alignment)
            for encoding in dict.fromkeys(encodings)
            for alignment in ((0, 1) if encoding.startswith("utf-16") else (0,))
        ]
        for mode_index, (encoding, alignment) in enumerate(modes):
            quota = limit // len(modes) + int(mode_index < limit % len(modes))
            if not quota:
                truncated = True
                continue
            end_count = len(records) + quota
            errors = (
                "surrogatepass" if encoding.startswith("utf-16") else "surrogateescape"
            )
            decoder = codecs.getincrementaldecoder(encoding)(errors=errors)
            offset = start = alignment
            chars: list[str] = []

            def flush() -> None:
                """Emit one printable run, preserving offsets across chunk boundaries."""
                if len(chars) >= minimum and len(records) < end_count:
                    value = "".join(chars)
                    records.append(
                        {
                            "offset": start,
                            "encoding": encoding,
                            "text": value,
                            "categories": classify(value),
                        }
                    )
                chars.clear()

            remaining = max(0, path.stat().st_size - alignment)
            if encoding.startswith("utf-16"):
                remaining -= remaining % 2
            with path.open("rb") as stream:
                stream.seek(alignment)
                while remaining > 0:
                    await asyncio.sleep(0)
                    chunk = stream.read(min(65536, remaining))
                    if not chunk:
                        raise ValueError("File shrank during string extraction")
                    remaining -= len(chunk)
                    text = decoder.decode(chunk, final=remaining == 0)
                    for char in text:
                        if char.isprintable():
                            if not chars:
                                start = offset
                            chars.append(char)
                            if len(chars) >= maximum:
                                flush()
                        else:
                            flush()
                        offset += len(char.encode(encoding, errors=errors))
                        if len(records) >= end_count:
                            truncated = True
                            break
                    if len(records) >= end_count:
                        break
                flush()
        return {
            "strings": records[:limit],
            "count": min(len(records), limit),
            "truncated": truncated,
            "budget_semantics": "Record budget is shared fairly across configured encoding/alignment passes",
            "semantics": "Printable runs are candidates; UTF-16 without BOM may include binary false positives",
        }
