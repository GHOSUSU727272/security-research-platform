"""Official Ghidra headless integration with bounded, cancellable subprocesses."""

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from core.models import Context
from plugins.common import FileAnalyzer, positive
from plugins.elf_analyzer.analyzer import is_elf
from plugins.process import run_command


class GhidraAnalyzer(FileAnalyzer):
    """Import ELF binaries into disposable Ghidra projects and export real analysis."""

    name = "ghidra"

    async def run(self, context: Context) -> dict[str, object]:
        """Require an explicitly configured official headless installation."""
        options = context.plugin_options.get(self.name, {})
        executable = Path(str(options.get("headless_path", "")))
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError(
                "Configure ghidra.headless_path to executable support/analyzeHeadless"
            )
        return await super().run(context)

    def accepts(self, path: Path, options: dict[str, Any]) -> bool:
        """Default to ELF; allow explicit suffixes for other Ghidra loaders."""
        return is_elf(path) or path.suffix.lower() in options.get("extensions", [])

    async def analyze(self, path: Path, options: dict[str, Any]) -> dict[str, Any]:
        """Run auto-analysis and a shipped Java post-script without launching a GUI."""
        timeout = positive(options, "backend_timeout", 600)
        limit = positive(options, "max_records", 100000)
        capture = positive(options, "max_log_bytes", 4 * 1024 * 1024)
        with tempfile.TemporaryDirectory(prefix="research-ghidra-") as directory:
            output = Path(directory) / "result.json"
            stdout, stderr = await run_command(
                [
                    str(Path(options["headless_path"]).resolve()),
                    directory,
                    "Research",
                    "-import",
                    str(path.resolve()),
                    "-scriptPath",
                    str(Path(__file__).parent),
                    "-postScript",
                    "ResearchExport.java",
                    str(output),
                    str(limit),
                    "-analysisTimeoutPerFile",
                    str(timeout),
                    "-max-cpu",
                    "1",
                    "-deleteProject",
                ],
                timeout + 60,
                capture,
                env={
                    **os.environ,
                    "GHIDRA_HEADLESS_MAXMEM": f"{positive(options, 'max_heap_mb', 768)}M",
                },
            )
            if not output.is_file():
                raise RuntimeError(
                    "Ghidra did not produce post-script output: "
                    + stderr[-2000:].decode(errors="replace")
                )
            if output.stat().st_size > positive(
                options, "max_result_bytes", 64 * 1024 * 1024
            ):
                raise ValueError("Ghidra export exceeds result budget")
            result: dict[str, Any] = json.loads(output.read_text(encoding="utf-8"))
            if result.get("backend") != "ghidra" or not isinstance(
                result.get("functions"), list
            ):
                raise ValueError("Invalid Ghidra export contract")
            result["backend_log"] = {
                "stdout": stdout.decode(errors="replace"),
                "stderr": stderr.decode(errors="replace"),
            }
            return result
