"""ELF dynamic dependency, symbol export and GNU symbol-version inventory."""

from pathlib import Path
from typing import Any

from plugins.common import FileAnalyzer, positive
from plugins.elf_analyzer.analyzer import inspect_elf, is_elf


class ImportsAnalyzer(FileAnalyzer):
    """Analyze dynamic linkage without ldd or execution of the target loader."""

    name = "imports"

    def accepts(self, path: Path, options: dict[str, Any]) -> bool:
        """Recognize ELF inputs independently of prior analysis tasks."""
        return is_elf(path)

    async def analyze(self, path: Path, options: dict[str, Any]) -> dict[str, Any]:
        """Inventory imports, exports, SONAME/search paths and required ABI versions."""
        elf = inspect_elf(path, positive(options, "max_records", 100000))
        dynamic = [s for s in elf["symbols"] if s["table"] == ".dynsym" and s["name"]]
        return {
            "libraries": elf["needed"],
            "imports": [s for s in dynamic if s["st_shndx"] == "SHN_UNDEF"],
            "exports": [
                s
                for s in dynamic
                if s["st_shndx"] != "SHN_UNDEF"
                and s["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK")
            ],
            "version_requirements": elf["version_requirements"],
            "version_definitions": elf["version_definitions"],
            "search_paths": [
                t
                for t in elf["dynamic"]
                if any(k in t for k in ("soname", "rpath", "runpath"))
            ],
            "truncated": elf["truncated"],
            "version_semantics": "Required symbol ABI versions, not installed package versions",
        }
