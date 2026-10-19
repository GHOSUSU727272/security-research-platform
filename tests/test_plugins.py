"""Real parser, checkpoint, isolation and multi-plugin integration coverage."""

import asyncio
import hashlib
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from core.models import Context
from core.prepare_kesl import prepare
from core.projects import ProjectManager
from core.research.manager import ResearchManager
from core.research.plan import ResearchPlan, TaskSpec
from database.plugin_state import PLUGIN_TABLES
from database.store import Store
from plugins import registry
from plugins.binary_graph import binary_graph
from plugins.common import FileAnalyzer
from plugins.config.analyzer import ConfigAnalyzer
from plugins.elf_analyzer.analyzer import inspect_elf
from plugins.ghidra.analyzer import GhidraAnalyzer
from plugins.imports.analyzer import ImportsAnalyzer
from plugins.logs.analyzer import LogsAnalyzer
from plugins.memory.analyzer import MemoryAnalyzer
from plugins.process import run_command
from plugins.sqlite.analyzer import SQLiteAnalyzer
from plugins.strings.analyzer import StringsAnalyzer, classify
from plugins.yaml.analyzer import YAMLAnalyzer
from reports.research_dashboard import research_dashboard


def tiny_elf(path: Path) -> Path:
    """Construct an inert ELF64 fixture with code, symbols, a note and a segment."""
    names = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00.note.gnu.build-id\x00"
    strings = b"\x00main\x00helper\x00"
    code = b"\xe8\x01\x00\x00\x00\xc3\xc3"
    symbols = (
        bytes(24)
        + struct.pack("<IBBHQQ", 1, 18, 0, 1, 0x400100, 6)
        + struct.pack("<IBBHQQ", 6, 18, 0, 1, 0x400106, 1)
    )
    note = struct.pack("<III", 4, 4, 3) + b"GNU\x00" + b"\x12\x34\x56\x78"
    parts = [
        (".text", 1, 6, 0x400100, code, 0, 0, 1, 0),
        (".symtab", 2, 0, 0, symbols, 3, 1, 8, 24),
        (".strtab", 3, 0, 0, strings, 0, 0, 1, 0),
        (".shstrtab", 3, 0, 0, names, 0, 0, 1, 0),
        (".note.gnu.build-id", 7, 0, 0, note, 0, 0, 4, 0),
    ]
    content = bytearray(256)
    headers = [bytes(64)]
    for name, kind, flags, address, data, link, info, align, entry in parts:
        offset = len(content)
        content.extend(data)
        headers.append(
            struct.pack(
                "<IIQQQQIIQQ",
                names.index(name.encode()),
                kind,
                flags,
                address,
                offset,
                len(data),
                link,
                info,
                align,
                entry,
            )
        )
    section_offset = len(content)
    content.extend(b"".join(headers))
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    content[:64] = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        2,
        62,
        1,
        0x400100,
        64,
        section_offset,
        0,
        64,
        56,
        1,
        64,
        6,
        4,
    )
    content[64:120] = struct.pack(
        "<IIQQQQQQ", 1, 5, 256, 0x400100, 0x400100, len(code), len(code), 1
    )
    path.write_bytes(content)
    return path


def test_registry_and_elf(tmp_path: Path) -> None:
    """All analyzers register and ELF headers/symbols/build IDs are actually parsed."""
    assert {
        "elf_analyzer",
        "strings",
        "imports",
        "callgraph",
        "cfg",
        "logs",
        "config",
        "yaml",
        "sqlite",
        "memory",
        "ghidra",
    } <= registry(False).keys()
    path = tiny_elf(tmp_path / "sample")
    elf = inspect_elf(path)
    assert elf["bits"] == 64 and elf["header"]["e_machine"] == "EM_X86_64"
    assert len(elf["segments"]) == 1 and len(elf["sections"]) == 6
    assert {s["name"] for s in elf["symbols"]} == {"", "main", "helper"}
    assert elf["build_ids"] == ["12345678"]
    assert inspect_elf(path, 1)["truncated"]
    assert asyncio.run(ImportsAnalyzer().analyze(path, {}))["libraries"] == []


def test_binary_graph(tmp_path: Path) -> None:
    """Resolve a real direct x86 call and preserve return-separated basic blocks."""
    graph = binary_graph(tiny_elf(tmp_path / "sample"), 100)
    assert graph["calls"][0]["caller"] == "main"
    assert graph["calls"][0]["callee"] == "helper"
    assert len(graph["blocks"]) == 2
    assert graph["edges"] == []
    assert binary_graph(tmp_path / "sample", 1)["truncated"]


@pytest.mark.parametrize(
    "extension,text,expected",
    [
        ("yaml", "a: [1, 2]\nsecret: hidden", "/0/a/0"),
        ("json", '{"a": {"v": 3}, "password": "hidden"}', "/a/v"),
        ("toml", '[a]\nv = 3\npassword = "hidden"', "/a/v"),
        ("ini", "[a]\nv = 3\npassword = hidden", "/a/v"),
        ("xml", "<a><v>3</v><password>hidden</password></a>", "/children/0/text"),
    ],
)
def test_config_formats(
    tmp_path: Path, extension: str, text: str, expected: str
) -> None:
    """All five configuration formats preserve structure and redact secrets."""
    path = tmp_path / f"data.{extension}"
    path.write_text(text, encoding="utf-8")
    result = asyncio.run(ConfigAnalyzer().analyze(path, {}))
    assert expected in {p["path"] for p in result["parameters"]}
    assert "hidden" not in json.dumps(result)


def test_yaml_cycles_and_xml_entities(tmp_path: Path) -> None:
    """YAML recursion terminates, and XML external entities cannot read local files."""
    path = tmp_path / "data.yaml"
    path.write_text("a: &a [*a]\n")
    assert "cycle" in json.dumps(asyncio.run(YAMLAnalyzer().analyze(path, {})))
    path = tmp_path / "data.xml"
    path.write_text('<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>')
    with pytest.raises(Exception, match="EntitiesForbidden"):
        asyncio.run(ConfigAnalyzer().analyze(path, {}))


def test_explicit_xml_fragments(tmp_path: Path) -> None:
    """KESL multi-root XML is parsed only with explicit fragment support."""
    path = tmp_path / "settings.xml"
    path.write_text(
        '<?xml version="1.0"?><TraceLevel>None</TraceLevel><CoreDumps>false</CoreDumps>'
    )
    with pytest.raises(Exception, match="junk after document element"):
        asyncio.run(ConfigAnalyzer().analyze(path, {}))
    result = asyncio.run(ConfigAnalyzer().analyze(path, {"xml_fragments": True}))
    assert "CoreDumps" in json.dumps(result) and "TraceLevel" in json.dumps(result)


def test_strings_encodings_and_categories(tmp_path: Path) -> None:
    """Extract real byte offsets across Unicode encodings and classify common evidence."""
    path = tmp_path / "strings.bin"
    data = (
        b"/tmp/service.sock\x00https://example.test/a\x00"
        + "Привет мир".encode()
        + b"\x00\xff"
        + "wide text".encode("utf-16-le")
        + b"\x00\x00"
    )
    path.write_bytes(data)
    result = asyncio.run(StringsAnalyzer().analyze(path, {}))
    assert any(
        s["text"] == "Привет мир" and s["encoding"] == "utf-8"
        for s in result["strings"]
    )
    assert any(
        s["text"] == "wide text" and s["encoding"] == "utf-16-le"
        for s in result["strings"]
    )
    for item in result["strings"]:
        assert data[
            item["offset"] : item["offset"] + len(item["text"].encode(item["encoding"]))
        ] == item["text"].encode(item["encoding"])
    for value, category in [
        ("/tmp/a.sock", "unix_socket"),
        ("libc.so.6", "library"),
        ("HOME=/tmp", "environment"),
        ("192.0.2.1", "ip"),
        ("error: failed", "log_message"),
        ("file.txt", "filename"),
    ]:
        assert category in classify(value)


def test_logs_formats(tmp_path: Path) -> None:
    """Retain syslog, journal JSON, journal export and unstructured events."""
    path = tmp_path / "syslog"
    path.write_text(
        '<11>Sep 28 12:34:56 host service[12]: error occurred\n{"MESSAGE":"journal", "PRIORITY":"3"}\nwarning text\n'
    )
    result = asyncio.run(LogsAnalyzer().analyze(path, {}))
    assert len(result["events"]) == 3
    assert result["events"][0]["program"] == "service"
    assert result["events"][1]["message"] == "journal"
    path.write_text("__CURSOR=abc\nMESSAGE=journal export\nPRIORITY=4\n\n")
    assert (
        asyncio.run(LogsAnalyzer().analyze(path, {}))["events"][0]["message"]
        == "journal export"
    )


def test_sqlite_schema_read_only(tmp_path: Path) -> None:
    """Inventory tables, indexes, triggers and views without querying or firing them."""
    path = tmp_path / "db.sqlite"
    db = sqlite3.connect(path)
    db.executescript(
        "CREATE TABLE data(id INTEGER PRIMARY KEY, value TEXT); CREATE INDEX idx ON data(value); CREATE VIEW v AS SELECT * FROM data; CREATE TRIGGER t AFTER INSERT ON data BEGIN UPDATE data SET value='changed'; END;"
    )
    db.close()
    before = path.read_bytes()
    result = asyncio.run(SQLiteAnalyzer().analyze(path, {}))
    assert {o["type"] for o in result["schema"]} == {
        "table",
        "view",
        "index",
        "trigger",
    }
    assert path.read_bytes() == before


def test_checkpoint_resume_invalidation_and_errors(tmp_path: Path) -> None:
    """Completed files survive restart, changed content is reanalyzed, malformed input isolated."""
    root = tmp_path / "target"
    root.mkdir()
    (root / "a.json").write_text('{"x":1}')
    (root / "b.json").write_text('{"broken":')
    context = Context(
        str(root), 10000, (), checkpoint_db=str(tmp_path / "state.db"), task_id="test"
    )
    analyzer = ConfigAnalyzer()
    first: Any = asyncio.run(analyzer.run(context))
    assert first["statistics"]["processed"] == 1 and first["statistics"]["errors"] == 1
    second: Any = asyncio.run(analyzer.run(context))
    assert second["statistics"]["cached"] == 1
    (root / "a.json").write_text('{"x":2}')
    third: Any = asyncio.run(analyzer.run(context))
    assert third["statistics"]["cached"] == 0
    limited: Any = asyncio.run(analyzer.run(replace(context, max_file_bytes=1)))
    assert limited["truncated"]


def test_cancellation_after_file_checkpoint(tmp_path: Path) -> None:
    """Cancellation leaves the first file reusable and the plugin explicitly paused."""

    class BlockingAnalyzer(FileAnalyzer):
        """Test-only analyzer that blocks after its first durable file."""

        name = "blocking"

        async def analyze(self, path: Path, options: dict[str, Any]) -> dict[str, Any]:
            """Block only the second file to expose a deterministic cancellation point."""
            if path.name == "b":
                await asyncio.sleep(60)
            return {"value": path.read_text()}

    root = tmp_path / "target"
    root.mkdir()
    for name in ("a", "b"):
        (root / name).write_text(name)
    database = tmp_path / "cache.db"
    context = Context(str(root), 100, (), checkpoint_db=str(database), task_id="task")

    async def cancel() -> None:
        """Wait for the actual durable checkpoint before cancelling."""
        task = asyncio.create_task(BlockingAnalyzer().run(context))
        for _ in range(100):
            await asyncio.sleep(0.01)
            if database.exists():
                with sqlite3.connect(database) as db:
                    if db.execute("SELECT COUNT(*) FROM PluginFileCache").fetchone()[0]:
                        break
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel())
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT COUNT(*) FROM PluginFileCache").fetchone()[0] == 1
        assert db.execute("SELECT status FROM PluginProgress").fetchone()[0] == "paused"


def test_memory_authorization(tmp_path: Path) -> None:
    """Live-process diagnostics require explicit selection and authorization."""
    with pytest.raises(ValueError, match="authorized"):
        asyncio.run(MemoryAnalyzer().run(Context(str(tmp_path), 100, ())))


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux procfs")
def test_memory_real_procfs(tmp_path: Path) -> None:
    """Read the test process's actual mappings/statistics and persist a fresh sample."""
    context = Context(
        str(tmp_path),
        10000,
        (),
        plugin_options={"memory": {"authorized": True, "pids": [os.getpid()]}},
        checkpoint_db=str(tmp_path / "memory.db"),
    )
    result: Any = asyncio.run(MemoryAnalyzer().run(context))
    assert result["records"][0]["analysis"]["maps"]
    assert result["records"][0]["analysis"]["statm"]["pages"][0] > 0
    with sqlite3.connect(context.checkpoint_db) as db:
        assert (
            db.execute("SELECT status FROM PluginProgress").fetchone()[0] == "completed"
        )


def test_backend_timeout_and_output_budget() -> None:
    """Timeouts and oversized backend output fail without leaving a running worker."""
    with pytest.raises(TimeoutError):
        asyncio.run(
            run_command([sys.executable, "-c", "import time; time.sleep(10)"], 1, 1000)
        )
    with pytest.raises(ValueError, match="output limit"):
        asyncio.run(run_command([sys.executable, "-c", "print('x'*2000)"], 10, 100))


def test_ghidra_missing_backend(tmp_path: Path) -> None:
    """Missing Ghidra fails explicitly rather than returning a fabricated empty graph."""
    with pytest.raises(ValueError, match="headless_path"):
        asyncio.run(GhidraAnalyzer().run(Context(str(tmp_path), 1000, ())))


@pytest.mark.skipif(
    not os.environ.get("GHIDRA_HEADLESS"),
    reason="Set GHIDRA_HEADLESS to test installed Ghidra",
)
def test_ghidra_real_headless(tmp_path: Path) -> None:
    """Execute the official headless backend and compile the shipped Java exporter."""
    path = tiny_elf(tmp_path / "sample")
    result = asyncio.run(
        GhidraAnalyzer().analyze(
            path,
            {"headless_path": os.environ["GHIDRA_HEADLESS"], "backend_timeout": 120},
        )
    )
    assert result["backend"] == "ghidra" and result["functions"] and result["blocks"]


@pytest.mark.skipif(
    sys.platform != "linux" or not shutil.which("gcc"), reason="Requires Linux compiler"
)
def test_real_dynamic_elf(tmp_path: Path) -> None:
    """Compare actual linked-library imports, relocations and symbol ABI versions."""
    source = tmp_path / "a.c"
    source.write_text(
        '#include <stdio.h>\nint main(void){ puts("safe fixture"); return 0; }\n'
    )
    path = tmp_path / "sample"
    subprocess.run(
        ["gcc", "-g", "-Wl,--build-id", str(source), "-o", str(path)], check=True
    )
    elf = inspect_elf(path)
    imports = asyncio.run(ImportsAnalyzer().analyze(path, {}))
    assert "libc.so.6" in imports["libraries"] and elf["relocations"]
    assert elf["dynamic"] and elf["notes"] and elf["version_requirements"]
    assert "puts" in {s["name"] for s in imports["imports"]}


def test_multi_plugin_engine_knowledge_export(tmp_path: Path) -> None:
    """Real isolated workers deliver correlated results, dashboard and portable checkpoints."""
    root = tmp_path / "target"
    root.mkdir()
    tiny_elf(root / "sample")
    (root / "data.yaml").write_text("a: 1\n")
    projects = ProjectManager(tmp_path / "workspace")
    project = projects.create("KESL", root=root)
    base = projects.path(project["id"])
    store = Store(base / "research.sqlite3")
    try:
        manager = ResearchManager(store, base)
        plan = ResearchPlan(
            workers=3,
            tasks=tuple(
                TaskSpec(p, plugin=p, timeout=60)
                for p in (
                    "elf_analyzer",
                    "imports",
                    "cfg",
                    "callgraph",
                    "strings",
                    "config",
                    "yaml",
                )
            ),
        )
        run = manager.create(plan, Context(str(root), 100000, ()))
        result = asyncio.run(manager.execute(run, str(root)))
        assert result["completed"] == 7 and result["errors"] == 0
        assert store.db.execute("SELECT COUNT(*) FROM Functions").fetchone()[0] == 2
        assert (
            store.db.execute(
                "SELECT COUNT(*) FROM Relationships WHERE relation='calls'"
            ).fetchone()[0]
            == 1
        )
        assert (
            store.db.execute("SELECT COUNT(*) FROM PluginFileCache").fetchone()[0] >= 7
        )
        research_dashboard(manager, run, tmp_path / "dashboard.html")
        assert "Plugins" in (tmp_path / "dashboard.html").read_text(encoding="utf-8")
        archive = tmp_path / "project.zip"
        projects.export(project["id"], archive)
        other = ProjectManager(tmp_path / "imported")
        try:
            imported = other.import_archive(archive)
            with sqlite3.connect(other.path(imported["id"]) / "research.sqlite3") as db:
                assert (
                    db.execute("SELECT COUNT(*) FROM PluginFileCache").fetchone()[0]
                    >= 7
                )
        finally:
            other.close()
    finally:
        store.close()
        projects.close()


def test_explicit_file_scope_and_task_options(tmp_path: Path) -> None:
    """Per-task options select only their assigned file and reject scope escapes."""
    root = tmp_path / "target"
    root.mkdir()
    (root / "a.json").write_text('{"a":1}')
    (root / "b.json").write_text('{"b":1}')
    context = Context(
        str(root), 1000, (), plugin_options={"config": {"files": ["b.json"]}}
    )
    result: Any = asyncio.run(ConfigAnalyzer().run(context))
    assert [r["path"] for r in result["records"]] == ["b.json"]
    with pytest.raises(ValueError, match="outside target"):
        asyncio.run(
            ConfigAnalyzer().run(
                replace(context, plugin_options={"config": {"files": ["../outside"]}})
            )
        )
    projects = ProjectManager(tmp_path / "workspace")
    project = projects.create("options", root=root)
    base = projects.path(project["id"])
    store = Store(base / "research.sqlite3")
    try:
        manager = ResearchManager(store, base)
        manager.create(
            ResearchPlan(
                tasks=(TaskSpec("a", plugin="config", options={"files": ["a.json"]}),)
            ),
            context,
        )
        stored = json.loads(
            store.db.execute("SELECT context FROM ResearchTasks").fetchone()[0]
        )
        assert stored["plugin_options"]["config"]["files"] == ["a.json"]
        assert context.plugin_options["config"]["files"] == ["b.json"]
    finally:
        store.close()
        projects.close()


def test_memory_snapshot_and_preparation(tmp_path: Path) -> None:
    """An offline diagnostic export retains its observed PID and generates explicit plans."""
    target = tmp_path / "target"
    target.mkdir()
    sample = {
        "plugin": "memory",
        "records": [
            {
                "path": "proc/123@456",
                "analysis": {
                    "pid": 123,
                    "starttime": "456",
                    "maps": [],
                    "captured_at": 1,
                },
            }
        ],
    }
    (target / "process-diagnostics.json").write_text(json.dumps(sample))
    (target / "settings.yaml").write_text("value: 1")
    (tmp_path / "discovery.json").write_text(
        json.dumps(
            {
                "package": "kesl",
                "version": "test",
                "snapshot": [{"relative": "settings.yaml", "category": "config"}],
            }
        )
    )
    counts = prepare(tmp_path, tmp_path / "config")
    assert counts["config"] == counts["yaml"] == counts["memory"] == 1
    plan = ResearchPlan.load(tmp_path / "config/kesl-plan.yaml")
    assert len(plan.tasks) == 4
    result: Any = asyncio.run(
        MemoryAnalyzer().run(
            Context(
                str(target),
                10000,
                (),
                plugin_options={
                    "memory": {
                        "authorized": True,
                        "pids": [123],
                        "snapshots": ["process-diagnostics.json"],
                    }
                },
            )
        )
    )
    assert result["records"][0]["analysis"]["captured_at"] == 1
    assert "not live" in result["records"][0]["analysis"]["provenance"]
    missing: Any = asyncio.run(
        MemoryAnalyzer().run(
            Context(
                str(target),
                10000,
                (),
                plugin_options={
                    "memory": {
                        "authorized": True,
                        "pids": [999],
                        "snapshots": ["process-diagnostics.json"],
                    }
                },
            )
        )
    )
    assert missing["statistics"]["errors"] == 1 and missing["warnings"]


def test_streaming_multibyte_boundary(tmp_path: Path) -> None:
    """An incremental decoder preserves offsets when a UTF-8 sequence crosses 64 KiB."""
    path = tmp_path / "boundary"
    path.write_bytes(bytes(65535) + "Привет мир".encode() + b"\x00")
    result = asyncio.run(StringsAnalyzer().analyze(path, {"encodings": ["utf-8"]}))
    assert result["strings"] == [
        {"offset": 65535, "encoding": "utf-8", "text": "Привет мир", "categories": []}
    ]


def test_archive_v2_upgrade(tmp_path: Path) -> None:
    """An archive without new plugin tables still imports and receives additive tables."""
    manager = ProjectManager(tmp_path / "old")
    project = manager.create("v2 fixture")
    archive = tmp_path / "new.zip"
    manager.export(project["id"], archive)
    manager.close()
    with zipfile.ZipFile(archive) as z:
        manifest = json.loads(z.read("manifest.json"))
        data = json.loads(z.read("data.json"))
    for table in PLUGIN_TABLES:
        del data[table]
    payload = json.dumps(data).encode()
    manifest["version"] = 2
    manifest["files"]["data.json"] = {
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }
    old = tmp_path / "old.zip"
    with zipfile.ZipFile(old, "w") as z:
        z.writestr("manifest.json", json.dumps(manifest))
        z.writestr("data.json", payload)
    destination = ProjectManager(tmp_path / "upgraded")
    try:
        imported = destination.import_archive(old)
        with sqlite3.connect(
            destination.path(imported["id"]) / "research.sqlite3"
        ) as db:
            assert db.execute("SELECT count(*) FROM PluginFileCache").fetchone()[0] == 0
    finally:
        destination.close()
