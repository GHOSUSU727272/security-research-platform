"""Index files and extract conservative syntactic Python evidence."""

import ast
import asyncio
import hashlib
import os
from dataclasses import asdict
from pathlib import Path

from core.models import Context, Finding

SENSITIVE = {
    "eval",
    "exec",
    "pickle.loads",
    "yaml.load",
    "os.system",
    "subprocess.run",
    "subprocess.Popen",
}
MANIFESTS = {
    "pyproject.toml",
    "requirements.txt",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "Gemfile",
    "Dockerfile",
}


class Calls(ast.NodeVisitor):
    """Collect syntactic caller/callee edges and review candidates."""

    def __init__(self, path: str) -> None:
        """Initialize module-level scope for one source file."""
        self.path = path
        self.scope = ["<module>"]
        self.edges: list[dict[str, object]] = []
        self.findings: list[dict[str, object]] = []
        self.imports: list[str] = []
        self.functions: list[dict[str, object]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Track nested function scopes during traversal."""
        self.scope.append(node.name)
        self.functions.append(
            {"name": ".".join(self.scope[1:]), "path": self.path, "line": node.lineno}
        )
        self.generic_visit(node)
        self.scope.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Include class names to distinguish methods."""
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_Import(self, node: ast.Import) -> None:
        """Inventory imported modules without importing target code."""
        self.imports.extend(alias.name for alias in node.names)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Record relative and absolute dependency declarations."""
        self.imports.append("." * node.level + (node.module or ""))

    def visit_Call(self, node: ast.Call) -> None:
        """Record call sites; sensitive names are heuristics, not vulnerabilities."""
        name = ast.unparse(node.func)[:200]
        self.edges.append(
            {
                "caller": ".".join(self.scope),
                "callee": name,
                "path": self.path,
                "line": node.lineno,
            }
        )
        if name in SENSITIVE:
            high_interest = name in {"eval", "exec", "pickle.loads", "os.system"}
            reason = (
                "code execution or object deserialization"
                if high_interest
                else "process creation or configurable deserialization"
            )
            self.findings.append(
                asdict(
                    Finding(
                        "sensitive-api",
                        self.path,
                        node.lineno,
                        f"{name}: {reason}; manually trace input provenance and validation",
                        1 if high_interest else 2,
                    )
                )
            )
        self.generic_visit(node)


class SourcePlugin:
    """Read at most 10,000 regular files, excluding symlinks and large files."""

    async def run(self, context: Context) -> dict[str, object]:
        """Build a bounded index, import graph, call graph and review candidates."""
        root = Path(context.root)
        files: list[dict[str, object]] = []
        findings: list[dict[str, object]] = []
        edges: list[dict[str, object]] = []
        dependencies: dict[str, list[str]] = {}
        functions: list[dict[str, object]] = []
        warnings: list[str] = []
        technologies: set[str] = set()
        truncated = False
        bytes_read = 0
        for directory, dirs, names in os.walk(root, followlinks=False):
            dirs[:] = sorted(
                d
                for d in dirs
                if d not in context.excluded and not (Path(directory) / d).is_symlink()
            )
            for name in sorted(names):
                await asyncio.sleep(0)
                path = Path(directory) / name
                relative = path.relative_to(root).as_posix()
                if (
                    len(files) >= 10000
                    or len(edges) >= 100000
                    or bytes_read >= 64 * 1024 * 1024
                ):
                    truncated = True
                    break
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                    size = path.stat().st_size
                    item: dict[str, object] = {
                        "path": relative,
                        "size": size,
                        "component": name in MANIFESTS,
                    }
                    files.append(item)
                    if size > context.max_file_bytes:
                        item["skipped"] = "file size limit"
                        continue
                    with path.open("rb") as stream:
                        data = stream.read(context.max_file_bytes + 1)
                    bytes_read += len(data)
                    if len(data) > context.max_file_bytes:
                        item["skipped"] = "file grew beyond limit"
                        continue
                    item["sha256"] = hashlib.sha256(data).hexdigest()
                    if path.suffix == ".py":
                        technologies.add("Python")
                        visitor = Calls(relative)
                        visitor.visit(ast.parse(data, filename=relative))
                        edges.extend(visitor.edges)
                        findings.extend(visitor.findings)
                        dependencies[relative] = visitor.imports
                        functions.extend(visitor.functions)
                    if name in MANIFESTS:
                        technologies.add(name)
                        item["manifest"] = data.decode("utf-8", errors="replace")
                except (OSError, SyntaxError, ValueError, RecursionError) as exc:
                    warnings.append(f"{relative}: {exc}")
            if truncated:
                break
        return {
            "functions": functions,
            "files": files,
            "call_graph": edges,
            "dependencies": dependencies,
            "technologies": sorted(technologies),
            "findings": findings,
            "warnings": warnings,
            "truncated": truncated,
        }
