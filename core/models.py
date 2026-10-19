"""Serializable contracts shared by independently registered plugins."""

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class Finding:
    """A review candidate, including evidence and a suggested priority."""

    rule: str
    path: str
    line: int
    reason: str
    priority: int = 2


@dataclass(frozen=True)
class Context:
    """Immutable task input constrained by configuration."""

    root: str
    max_file_bytes: int
    excluded: tuple[str, ...]
    command: tuple[str, ...] = ()
    max_log_bytes: int = 65536
    plugin_options: dict[str, dict[str, Any]] = field(default_factory=dict)
    checkpoint_db: str = ""
    task_id: str = ""
    checkpoint_endpoint: str = ""
    checkpoint_token: str = ""


class Plugin(Protocol):
    """Async extension contract; returned values must be JSON serializable."""

    async def run(self, context: Context) -> dict[str, object]:
        """Analyze input without modifying the target project."""
        ...
