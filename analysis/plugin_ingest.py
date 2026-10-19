"""Cross-plugin knowledge projection preserving evidence and human review states."""

import hashlib
import json
from pathlib import PurePosixPath
from typing import Any

from core.knowledge import GraphEngine, KnowledgeEngine


def ingest_records(
    knowledge: KnowledgeEngine, experiment: str, result: dict[str, Any]
) -> None:
    """Deduplicate content evidence and correlate file, library and function identities."""
    graph = GraphEngine(knowledge)
    plugin = str(result.get("plugin", "unknown"))
    for record in result.get("records", []):
        path, detail = str(record["path"]), record["analysis"]
        digest = hashlib.sha256(json.dumps(detail, sort_keys=True).encode()).hexdigest()
        evidence = knowledge._insert(
            "Artifacts",
            f"{plugin}: {path}",
            evidence={"plugin": plugin, **record},
            source_key=f"analysis:{plugin}:{path}:{digest}",
        )
        graph._connect(experiment, evidence, "produced", "Plugin analysis output")
        module = knowledge._insert(
            "Modules", path, source_key=path, evidence={"path": path}
        )
        graph._connect(
            evidence, module, "analyzes", "File/process diagnostic provenance"
        )
        if record.get("sha256"):
            artifact = knowledge._insert(
                "Artifacts",
                path,
                evidence={k: v for k, v in record.items() if k != "analysis"},
                source_key=f"file:{path}:{record['sha256']}",
            )
            graph._connect(
                evidence, artifact, "derived_from", "Content-addressed input"
            )
            content = knowledge._insert(
                "Artifacts",
                f"SHA-256 {record['sha256']}",
                source_key=f"content:{record['sha256']}",
                evidence={
                    "content_sha256": record["sha256"],
                    "category": "content-identity",
                },
            )
            graph._connect(
                artifact,
                content,
                "same_content",
                "SHA-256 correlation across input paths and plugins",
            )
        functions = list(detail.get("functions", []))
        functions.extend(
            s
            for s in detail.get("symbols", [])
            if s.get("st_info", {}).get("type") == "STT_FUNC"
            and s.get("st_shndx") != "SHN_UNDEF"
        )
        functions.extend(
            s
            for s in detail.get("exports", [])
            if s.get("st_info", {}).get("type") == "STT_FUNC"
        )
        identities: dict[str, str] = {}
        for function in functions:
            name = str(function.get("name", ""))
            if not name:
                continue
            node = knowledge._insert(
                "Functions",
                name,
                evidence={"path": path, **function},
                source_key=f"{path}:{name}",
            )
            identities[name] = node
            graph._connect(node, module, "belongs_to", "Analyzed function inventory")
            graph._connect(
                evidence, node, "describes", "Plugin evidence; review state unchanged"
            )
        for library in detail.get("libraries", detail.get("needed", [])):
            name = str(library)
            node = knowledge._insert(
                "Libraries",
                name,
                evidence={
                    "provenance": "Declared dependency; installed version unknown"
                },
                source_key=name,
            )
            graph._connect(module, node, "imports", "Declared binary dependency")
            graph._connect(evidence, node, "describes", "Plugin dependency evidence")
        for call in detail.get("calls", []):
            caller, callee = call.get("caller"), call.get("callee")
            if caller in identities and callee in identities:
                graph._connect(
                    identities[caller],
                    identities[callee],
                    "calls",
                    f"{plugin} call reference",
                )
        if plugin == "memory" and isinstance(detail.get("maps"), list):
            for mapping in detail["maps"]:
                mapped_path = str(mapping.get("path", ""))
                if not mapped_path.startswith("/"):
                    continue
                mapped = knowledge._insert(
                    "Modules",
                    mapped_path.lstrip("/"),
                    source_key=mapped_path.lstrip("/"),
                    evidence={"path": mapped_path},
                )
                graph._connect(
                    module,
                    mapped,
                    "maps",
                    "Observed process memory map; not memory contents",
                )
                if ".so" in PurePosixPath(mapped_path).name:
                    name = PurePosixPath(mapped_path).name
                    library = knowledge._insert(
                        "Libraries",
                        name,
                        source_key=name,
                        evidence={"provenance": "Mapped process library"},
                    )
                    graph._connect(module, library, "loads", "Observed mapped library")
        # Events remain losslessly stored in the analysis artifact. Only high severity
        # events get review candidates, never automatically confirmed findings.
        for event in detail.get("events", []):
            if event.get("severity") not in (
                "emerg",
                "alert",
                "crit",
                "error",
                "err",
                "critical",
            ):
                continue
            event_key = hashlib.sha256(
                json.dumps(event, sort_keys=True).encode()
            ).hexdigest()
            node = knowledge._insert(
                "InterestingLocations",
                f"Log event: {path}",
                evidence={
                    "path": path,
                    "event": event,
                    "reason": "High severity log event; verify context manually",
                },
                source_key=f"log:{path}:{event_key}",
            )
            graph._connect(
                node,
                evidence,
                "derived_from",
                "Log severity is not vulnerability confirmation",
            )
