"""pyelftools-based ELF metadata, symbols, notes and relocation analysis."""

from pathlib import Path
from typing import Any

from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.gnuversions import (
    GNUVerDefSection,
    GNUVerNeedSection,
    GNUVerSymSection,
)
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import NoteSection, SymbolTableSection
from elftools.elf.segments import NoteSegment

from plugins.common import FileAnalyzer, json_value, positive


def is_elf(path: Path) -> bool:
    """Recognize ELF by magic bytes instead of executable permission or extension."""
    with path.open("rb") as stream:
        return stream.read(4) == b"\x7fELF"


def inspect_elf(path: Path, limit: int = 100000) -> dict[str, Any]:
    """Read ELF structures without executing the file or invoking its loader."""
    result: dict[str, Any] = {
        k: []
        for k in (
            "segments",
            "sections",
            "symbols",
            "dynamic",
            "relocations",
            "notes",
            "needed",
            "version_requirements",
            "version_definitions",
        )
    }
    result["truncated"] = False

    def append(key: str, value: dict[str, Any]) -> None:
        """Bound each structure collection and expose truncation explicitly."""
        if len(result[key]) < limit:
            result[key].append(value)
        else:
            result["truncated"] = True

    with path.open("rb") as stream:
        elf = ELFFile(stream)
        result.update(
            header=json_value(dict(elf.header)),
            bits=elf.elfclass,
            little_endian=elf.little_endian,
            machine=elf.get_machine_arch(),
        )
        for i, segment in enumerate(elf.iter_segments()):
            append("segments", {"index": i, **json_value(dict(segment.header))})
            if isinstance(segment, NoteSegment):
                for note in segment.iter_notes():
                    append(
                        "notes", {"source": f"segment:{i}", **json_value(dict(note))}
                    )
        for section in elf.iter_sections():
            append(
                "sections", {"name": section.name, **json_value(dict(section.header))}
            )
            if isinstance(section, SymbolTableSection):
                for index, symbol in enumerate(section.iter_symbols()):
                    append(
                        "symbols",
                        {
                            "name": symbol.name,
                            "index": index,
                            "table": section.name,
                            **json_value(dict(symbol.entry)),
                        },
                    )
            if isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    item = json_value(dict(tag.entry))
                    for field in ("needed", "soname", "rpath", "runpath"):
                        if hasattr(tag, field):
                            item[field] = str(getattr(tag, field))
                    append("dynamic", item)
                    if hasattr(tag, "needed"):
                        result["needed"].append(str(tag.needed))
            if isinstance(section, RelocationSection):
                symbols = elf.get_section(section["sh_link"])
                for relocation in section.iter_relocations():
                    symbol_index = relocation["r_info_sym"]
                    symbol_name = (
                        symbols.get_symbol(symbol_index).name
                        if symbol_index and isinstance(symbols, SymbolTableSection)
                        else ""
                    )
                    append(
                        "relocations",
                        {
                            "section": section.name,
                            "symbol": symbol_name,
                            **json_value(dict(relocation.entry)),
                        },
                    )
            if isinstance(section, NoteSection):
                for note in section.iter_notes():
                    append("notes", {"source": section.name, **json_value(dict(note))})
            if isinstance(section, GNUVerNeedSection):
                for version, auxiliaries in section.iter_versions():
                    append(
                        "version_requirements",
                        {
                            "library": version.name,
                            "versions": [
                                {"name": aux.name, **json_value(dict(aux.entry))}
                                for aux in auxiliaries
                            ],
                        },
                    )
            if isinstance(section, GNUVerDefSection):
                for version, auxiliaries in section.iter_versions():
                    append(
                        "version_definitions",
                        {
                            **json_value(dict(version.entry)),
                            "names": [aux.name for aux in auxiliaries],
                        },
                    )
        result["build_ids"] = sorted(
            {
                str(n["n_desc"])
                for n in result["notes"]
                if n.get("n_type") == "NT_GNU_BUILD_ID"
            }
        )
        versions = elf.get_section_by_name(".gnu.version")
        if isinstance(versions, GNUVerSymSection):
            for symbol in result["symbols"]:
                if symbol["table"] == ".dynsym":
                    symbol["version_index"] = json_value(
                        dict(versions.get_symbol(symbol["index"]).entry)
                    )
    return result


class ELFAnalyzer(FileAnalyzer):
    """Analyze every eligible ELF file and persist complete structured evidence."""

    name = "elf_analyzer"

    def accepts(self, path: Path, options: dict[str, Any]) -> bool:
        """Select binaries and shared objects by ELF magic."""
        return is_elf(path)

    async def analyze(self, path: Path, options: dict[str, Any]) -> dict[str, Any]:
        """Extract ELF structures under an explicit per-collection record budget."""
        return inspect_elf(path, positive(options, "max_records", 100000))
