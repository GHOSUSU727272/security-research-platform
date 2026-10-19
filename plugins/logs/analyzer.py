"""Syslog, journal JSON/export and text-log event extraction."""

import asyncio
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from plugins.common import FileAnalyzer, positive

SYSLOG = re.compile(
    r"^(?:<(?P<priority>\d+)>)?(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<program>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
RFC5424 = re.compile(
    r"^<(?P<priority>\d+)>(?P<version>\d+) (?P<timestamp>\S+) (?P<host>\S+) (?P<program>\S+) (?P<pid>\S+) (?P<msgid>\S+) (?P<message>.*)$"
)


class LogsAnalyzer(FileAnalyzer):
    """Normalize supplied log files and journal exports while retaining source evidence."""

    name = "logs"

    def accepts(self, path: Path, options: dict[str, Any]) -> bool:
        """Select common logs or allow explicit include patterns for extensionless files."""
        return (
            path.suffix.lower() in {".log", ".jsonl", ".journal", ".txt", ".export"}
            or path.name in {"syslog", "messages"}
            or bool(options.get("include"))
        )

    async def analyze(self, path: Path, options: dict[str, Any]) -> dict[str, Any]:
        """Parse bounded event streams; journal binary files use journalctl export."""
        limit = positive(options, "max_records", 10000)
        data = path.read_bytes()
        if data[:8] == b"LPKSHHRH":
            from plugins.process import run_command

            stdout, _ = await run_command(
                ["journalctl", "--file", str(path), "--output=json", "--no-pager"],
                positive(options, "timeout", 120),
                positive(options, "max_output_bytes", 32 * 1024 * 1024),
            )
            text = stdout.decode("utf-8", errors="replace")
        else:
            text = data.decode(str(options.get("encoding", "utf-8")), errors="replace")
        events: list[dict[str, Any]] = []
        journal: dict[str, str] = {}
        journal_start = 1
        lines = text.splitlines()
        journal_export = str(
            options.get("format", "")
        ) == "journal-export" or text.startswith("__CURSOR=")
        for number, line in enumerate(lines + ([""] if journal_export else []), 1):
            if number % 1000 == 0:
                await asyncio.sleep(0)
            if len(events) >= limit:
                break
            if journal_export:
                if line:
                    if "=" not in line:
                        raise ValueError(
                            "Binary journal export fields are unsupported; use journalctl --output=json"
                        )
                    key, value = line.split("=", 1)
                    if not journal:
                        journal_start = number
                    journal[key] = value
                    continue
                if not journal:
                    continue
                record: dict[str, Any] = {
                    "line": journal_start,
                    "format": "journal",
                    "fields": journal,
                    "message": journal.get("MESSAGE", ""),
                    "timestamp": journal.get("__REALTIME_TIMESTAMP"),
                    "program": journal.get("SYSLOG_IDENTIFIER", journal.get("_COMM")),
                    "pid": journal.get("_PID"),
                }
                if "PRIORITY" in journal:
                    record["severity"] = journal["PRIORITY"]
                journal = {}
            elif line.startswith("{"):
                try:
                    fields = json.loads(line)
                except json.JSONDecodeError:
                    fields = {
                        "MESSAGE": line,
                        "parse_warning": "Malformed JSON; retained as text",
                    }
                if not isinstance(fields, dict):
                    fields = {"MESSAGE": line}
                record = {
                    "line": number,
                    "format": "journal-json",
                    "fields": fields,
                    "message": fields.get("MESSAGE", fields.get("message", line)),
                    "timestamp": fields.get(
                        "__REALTIME_TIMESTAMP", fields.get("timestamp")
                    ),
                    "severity": fields.get("PRIORITY", fields.get("level", "unknown")),
                }
            else:
                match = RFC5424.match(line) or SYSLOG.match(line)
                record = {
                    "line": number,
                    "format": "syslog" if match else "text",
                    **(match.groupdict() if match else {"message": line}),
                }
                if record.get("priority"):
                    record["severity"] = int(record["priority"]) % 8
            if "severity" not in record:
                severity = re.search(
                    r"\b(error|warn(?:ing)?|fatal|debug|info|critical)\b",
                    str(record.get("message", "")),
                    re.I,
                )
                record["severity"] = (
                    severity.group(1).lower() if severity else "unknown"
                )
            severity_value = str(record["severity"]).lower()
            names = (
                "emerg",
                "alert",
                "crit",
                "error",
                "warning",
                "notice",
                "info",
                "debug",
            )
            record["severity"] = (
                names[int(severity_value)]
                if severity_value in tuple(str(i) for i in range(8))
                else severity_value
            )
            events.append(record)
        return {
            "events": events,
            "severity_counts": dict(Counter(str(e["severity"]) for e in events)),
            "truncated": len(events) >= limit and len(lines) > limit,
        }
