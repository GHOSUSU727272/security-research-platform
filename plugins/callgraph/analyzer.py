"""Independent Python/ELF call graph construction with unresolved edges preserved."""

import ast
from pathlib import Path
from typing import Any

from analysis.source import Calls
from plugins.binary_graph import binary_graph
from plugins.common import FileAnalyzer, positive
from plugins.elf_analyzer.analyzer import is_elf


class CallGraphAnalyzer(FileAnalyzer):
    """Build syntactic Python calls or Capstone-backed ELF call sites."""

    name = "callgraph"

    def accepts(self, path: Path, options: dict[str, Any]) -> bool:
        """Support Python source and ELF without requiring prior plugin results."""
        return path.suffix == ".py" or is_elf(path)

    async def analyze(self, path: Path, options: dict[str, Any]) -> dict[str, Any]:
        """Return a common functions/calls graph and explicit backend limitations."""
        if path.suffix == ".py":
            visitor = Calls(path.name)
            visitor.visit(ast.parse(path.read_bytes(), filename=str(path)))
            limit = positive(options, "max_records", 100000)
            return {
                "backend": "python-ast",
                "functions": visitor.functions[:limit],
                "calls": [
                    {
                        **edge,
                        "caller": str(edge["caller"]).removeprefix("<module>."),
                        "resolved": False,
                    }
                    for edge in visitor.edges[:limit]
                ],
                "truncated": len(visitor.edges) > limit
                or len(visitor.functions) > limit,
                "limitations": [
                    "Syntactic calls; dynamic dispatch and aliases are not resolved"
                ],
            }
        graph = binary_graph(path, positive(options, "max_instructions", 100000))
        return {
            key: graph[key]
            for key in (
                "backend",
                "machine",
                "functions",
                "calls",
                "truncated",
                "limitations",
            )
        }
