"""Generate an explicit per-file research plan from a verified local KESL snapshot."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

from core.research.plan import ResearchPlan


def prepare(
    snapshot: Path, destination: Path, headless: Path | None = None
) -> dict[str, int]:
    """Configure analyzers from observed files; never assume installation locations."""
    snapshot = snapshot.resolve()
    manifest = json.loads((snapshot / "discovery.json").read_text(encoding="utf-8"))
    target = snapshot / "target"
    if manifest["package"] != "kesl" or not target.is_dir():
        raise ValueError("Expected a KESL discovery with an offline target snapshot")
    options: dict[str, dict[str, Any]] = {
        "elf_analyzer": {"max_records": 200000},
        "imports": {"max_records": 200000},
        "strings": {"max_records": 50000},
        "config": {"redact_secrets": True, "xml_fragments": True},
        "logs": {"max_records": 100000},
        "yaml": {"redact_secrets": True},
        "sqlite": {"instruction_budget": 5000000},
        "cfg": {"max_instructions": 200000},
        "callgraph": {"max_instructions": 200000},
    }
    if headless:
        if not headless.is_file():
            raise ValueError("Ghidra headless executable not found")
        options["ghidra"] = {
            "headless_path": str(headless.resolve()),
            "backend_timeout": 1800,
            "max_records": 200000,
        }
    tasks: list[dict[str, Any]] = []
    counts: dict[str, int] = dict.fromkeys(options, 0)
    for item in manifest.get("snapshot", []):
        relative = item["relative"]
        path = (target / relative).resolve()
        if not path.is_relative_to(target) or not path.is_file():
            raise ValueError(
                "Snapshot manifest refers outside target or to missing file"
            )
        plugins = ["strings"]
        category = item["category"]
        if category in ("binary", "library"):
            plugins += ["elf_analyzer", "imports", "cfg", "callgraph"]
            if headless:
                plugins.append("ghidra")
        elif category == "config":
            plugins.append("config")
            if path.suffix.lower() in (".yaml", ".yml"):
                plugins.append("yaml")
        elif category == "log":
            plugins.append("logs")
        elif category == "sqlite":
            plugins.append("sqlite")
        for plugin in plugins:
            counts[plugin] += 1
            key = plugin + "-" + hashlib.sha256(relative.encode()).hexdigest()[:20]
            tasks.append(
                {
                    "key": key,
                    "plugin": plugin,
                    "stage": "inventory"
                    if plugin
                    in ("elf_analyzer", "strings", "imports", "config", "logs")
                    else "deep-analysis",
                    "priority": 3 if plugin in ("ghidra", "cfg", "callgraph") else 1,
                    "timeout": 1900 if plugin == "ghidra" else 600,
                    "attempts": 2,
                    "options": {"include": [relative], "files": [relative]},
                }
            )
    if (target / "process-diagnostics.json").is_file():
        sample = json.loads((target / "process-diagnostics.json").read_text())
        pids = [r["analysis"]["pid"] for r in sample["records"]]
        if pids:
            options["memory"] = {
                "authorized": True,
                "pids": pids,
                "snapshots": ["process-diagnostics.json"],
            }
            tasks.append(
                {
                    "key": "memory-snapshot",
                    "plugin": "memory",
                    "stage": "diagnostics",
                    "priority": 2,
                    "timeout": 120,
                }
            )
            counts["memory"] = 1
    destination.mkdir(parents=True, exist_ok=True)
    config = {
        "root": str(target),
        "state": str(destination.parent / "state"),
        "workers": 2,
        "max_file_bytes": 512 * 1024 * 1024,
        "plugin_options": options,
    }
    (destination / "kesl.yaml").write_text(
        yaml.safe_dump(config, sort_keys=False), encoding="utf-8"
    )
    plan_path = destination / "kesl-plan.yaml"
    plan_path.write_text(
        yaml.safe_dump(
            {
                "name": f"KESL {manifest['version']} discovered installation",
                "workers": 2,
                "checkpoint_minutes": 5,
                "tasks": tasks,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    ResearchPlan.load(plan_path).validate()
    return counts


def main() -> None:
    """Write YAML inputs for the existing research start --prepare command."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--output", type=Path, default=Path("config/discovered"))
    parser.add_argument("--headless", type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.snapshot, args.output, args.headless), indent=2))


if __name__ == "__main__":
    main()
