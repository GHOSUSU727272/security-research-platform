"""Typed research plans and preflight validation of task dependency graphs."""

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class TaskSpec:
    """One plugin invocation with a stage, priority and dependency keys."""

    key: str
    plugin: str = "source"
    stage: str = "analysis"
    priority: int = 2
    depends_on: tuple[str, ...] = ()
    timeout: float = 120
    attempts: int = 3
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ResearchPlan:
    """A bounded DAG and supervisor limits saved with the research run."""

    name: str = "Project research"
    workers: int = 2
    checkpoint_minutes: float = 5
    tasks: tuple[TaskSpec, ...] = field(default_factory=lambda: (TaskSpec("source"),))

    def validate(self) -> None:
        """Reject malformed limits, missing dependencies, duplicate keys and cycles."""
        if (
            not self.name.strip()
            or type(self.workers) is not int
            or not 1 <= self.workers <= 32
        ):
            raise ValueError("Name required; workers must be an integer from 1 to 32")
        if (
            type(self.checkpoint_minutes) not in (int, float)
            or not math.isfinite(self.checkpoint_minutes)
            or not 0 < self.checkpoint_minutes <= 1440
            or not 1 <= len(self.tasks) <= 10000
        ):
            raise ValueError("Invalid checkpoint interval or task count")
        keys = {task.key for task in self.tasks}
        if len(keys) != len(self.tasks):
            raise ValueError("Duplicate task keys")
        dependencies: dict[str, set[str]] = {}
        for task in self.tasks:
            if not isinstance(task.options, dict) or not all(
                isinstance(k, str) for k in task.options
            ):
                raise ValueError("Task options must be a string-keyed mapping")
            if (
                not task.key.strip()
                or not task.stage.strip()
                or not task.plugin.strip()
            ):
                raise ValueError("Task key, stage and plugin are required")
            if type(task.priority) is not int or task.priority not in (1, 2, 3):
                raise ValueError("Priority must be 1, 2 or 3")
            if type(task.attempts) is not int or not 1 <= task.attempts <= 100:
                raise ValueError("Attempts must be between 1 and 100")
            if (
                type(task.timeout) not in (int, float)
                or not math.isfinite(task.timeout)
                or not 0 < task.timeout <= 604800
            ):
                raise ValueError("Timeout must be between 0 and 604800 seconds")
            if set(task.depends_on) - keys or task.key in task.depends_on:
                raise ValueError("Missing or self-referencing dependency")
            dependencies[task.key] = set(task.depends_on)
        while dependencies:
            ready = {key for key, values in dependencies.items() if not values}
            if not ready:
                raise ValueError("Dependency cycle")
            dependencies = {
                key: values - ready
                for key, values in dependencies.items()
                if key not in ready
            }

    @classmethod
    def load(cls, path: Path) -> "ResearchPlan":
        """Parse a strict YAML plan without executing embedded code."""
        data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or set(data) - {
            "name",
            "workers",
            "checkpoint_minutes",
            "tasks",
        }:
            raise ValueError("Invalid research plan mapping")
        if not isinstance(data.get("tasks"), list):
            raise ValueError("Plan requires a tasks list")
        tasks = []
        for raw in data.pop("tasks"):
            if not isinstance(raw, dict) or set(raw) - {
                "key",
                "plugin",
                "stage",
                "priority",
                "depends_on",
                "timeout",
                "attempts",
                "options",
            }:
                raise ValueError("Invalid task fields")
            dependencies = raw.get("depends_on", [])
            if not isinstance(dependencies, list) or not all(
                isinstance(v, str) for v in dependencies
            ):
                raise ValueError("depends_on must be a string list")
            raw["depends_on"] = tuple(dependencies)
            try:
                tasks.append(TaskSpec(**raw))
            except TypeError as exc:
                raise ValueError("Invalid task definition") from exc
        try:
            plan = cls(tasks=tuple(tasks), **data)
            plan.validate()
        except (TypeError, AttributeError) as exc:
            raise ValueError("Invalid plan field types") from exc
        return plan
