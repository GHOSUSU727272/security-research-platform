"""Built-in registration and installed entry-point discovery."""

from importlib.metadata import entry_points
from typing import cast

from analysis.source import SourcePlugin
from core.models import Plugin
from dynamic.runner import DynamicPlugin
from plugins.callgraph.analyzer import CallGraphAnalyzer
from plugins.cfg.analyzer import CFGAnalyzer
from plugins.config.analyzer import ConfigAnalyzer
from plugins.elf_analyzer.analyzer import ELFAnalyzer
from plugins.ghidra.analyzer import GhidraAnalyzer
from plugins.imports.analyzer import ImportsAnalyzer
from plugins.logs.analyzer import LogsAnalyzer
from plugins.memory.analyzer import MemoryAnalyzer
from plugins.sqlite.analyzer import SQLiteAnalyzer
from plugins.strings.analyzer import StringsAnalyzer
from plugins.yaml.analyzer import YAMLAnalyzer


def registry(allow_dynamic: bool) -> dict[str, Plugin]:
    """Load trusted installed plugins; reject names shadowing built-ins."""
    result: dict[str, Plugin] = {"source": SourcePlugin()}
    for analyzer in (
        ELFAnalyzer(),
        StringsAnalyzer(),
        ImportsAnalyzer(),
        CallGraphAnalyzer(),
        CFGAnalyzer(),
        LogsAnalyzer(),
        ConfigAnalyzer(),
        YAMLAnalyzer(),
        SQLiteAnalyzer(),
        MemoryAnalyzer(),
        GhidraAnalyzer(),
    ):
        result[analyzer.name] = analyzer
    if allow_dynamic:
        result["dynamic"] = DynamicPlugin()
    for entry in entry_points(group="research_platform.plugins"):
        if entry.name in {"source", "dynamic"} or entry.name in result:
            raise ValueError(f"Duplicate/reserved plugin: {entry.name}")
        result[entry.name] = cast(Plugin, entry.load()())
    return result
