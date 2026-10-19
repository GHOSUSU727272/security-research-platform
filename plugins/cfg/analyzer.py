"""ELF control-flow graph plugin backed by Capstone."""

from pathlib import Path
from typing import Any

from plugins.binary_graph import binary_graph
from plugins.common import FileAnalyzer, positive
from plugins.elf_analyzer.analyzer import is_elf


class CFGAnalyzer(FileAnalyzer):
    """Build basic blocks, branch/fallthrough edges and unresolved transfer evidence."""

    name = "cfg"

    def accepts(self, path: Path, options: dict[str, Any]) -> bool:
        """Select ELF binaries by magic."""
        return is_elf(path)

    async def analyze(self, path: Path, options: dict[str, Any]) -> dict[str, Any]:
        """Build the graph using the configured instruction budget."""
        return binary_graph(path, positive(options, "max_instructions", 100000))
