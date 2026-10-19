"""Strict, fail-fast YAML configuration."""

from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Settings:
    """Validated runtime limits and target scope."""

    root: str
    state: str = "state"
    workers: int = 2
    timeout: int = 120
    attempts: int = 3
    max_file_bytes: int = 1048576
    max_log_bytes: int = 65536
    excluded: tuple[str, ...] = (".git", ".venv", "node_modules", "state")
    allow_dynamic: bool = False
    command: tuple[str, ...] = ()
    plugin_options: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "Settings":
        """Load YAML, reject unknown fields, and resolve paths relative to YAML."""
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or "root" not in raw:
            raise ValueError("Configuration requires a root mapping field")
        if set(raw) - {f.name for f in fields(cls)}:
            raise ValueError("Unknown configuration fields")
        for key in ("root", "state"):
            value = raw.get(key, "state")
            if not isinstance(value, str):
                raise ValueError(f"{key} must be a string")
            raw[key] = str((path.resolve().parent / value).resolve())
        for key in (
            "workers",
            "timeout",
            "attempts",
            "max_file_bytes",
            "max_log_bytes",
        ):
            if key in raw and (type(raw[key]) is not int or raw[key] <= 0):
                raise ValueError(f"{key} must be a positive integer")
        for key in ("excluded", "command"):
            if key in raw:
                if not isinstance(raw[key], list) or not all(
                    isinstance(v, str) and v for v in raw[key]
                ):
                    raise ValueError(f"{key} must be a string list")
                raw[key] = tuple(raw[key])
        if "allow_dynamic" in raw and type(raw["allow_dynamic"]) is not bool:
            raise ValueError("allow_dynamic must be boolean")
        result = cls(**raw)
        if not isinstance(result.plugin_options, dict) or not all(
            isinstance(key, str) and isinstance(value, dict)
            for key, value in result.plugin_options.items()
        ):
            raise ValueError("plugin_options must map plugin names to option mappings")
        if not Path(result.root).is_dir():
            raise ValueError("root must be an existing directory")
        if Path(result.state) == Path(result.root):
            raise ValueError("state must differ from target root")
        if result.workers > 32:
            raise ValueError("workers cannot exceed 32")
        return result
