"""Project catalog, isolated storage, attachments and validated portable archives."""

import hashlib
import json
import logging
import os
import shutil
import sqlite3
import tempfile
import uuid
import zipfile
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from core.knowledge import KnowledgeEngine
from database.knowledge import STATES, initialize, utcnow, validate
from database.plugin_state import PLUGIN_TABLES, initialize_plugins
from database.research import ENGINE_TABLES, initialize_research, validate_research
from database.store import Store

LEGACY_TABLES = (
    "jobs",
    "reviews",
    "links",
    "review_events",
    "KnowledgeSchema",
    "Projects",
    "KnowledgeEntities",
    *STATES,
    "Relationships",
    "IngestedJobs",
)
V2_TABLES = (*LEGACY_TABLES, *ENGINE_TABLES)
TABLES = (*V2_TABLES, *PLUGIN_TABLES)
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024


class ProjectManager:
    """Keep project selection separate from each project's private research memory."""

    def __init__(self, workspace: Path) -> None:
        """Open a catalog without opening or modifying any legacy research database."""
        self.workspace = workspace.resolve()
        self.directory = self.workspace / "projects"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.catalog = sqlite3.connect(self.workspace / "catalog.sqlite3", timeout=30)
        self.catalog.row_factory = sqlite3.Row
        self.catalog.executescript("""
            CREATE TABLE IF NOT EXISTS Catalog(id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                                             root TEXT);
            CREATE TABLE IF NOT EXISTS Selection(slot INTEGER PRIMARY KEY CHECK(slot=1),
                                               project_id TEXT NOT NULL);
        """)

    def close(self) -> None:
        """Release the catalog connection."""
        self.catalog.close()

    def audit(self, action: str, identifier: str | None = None) -> None:
        """Log the operation name without copying private notes into catalog logs."""
        folder = self.path(identifier) if identifier else self.workspace
        handler = RotatingFileHandler(
            folder / "operations.log",
            maxBytes=5_000_000,
            backupCount=5,
            encoding="utf-8",
        )
        try:
            handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
            handler.emit(
                logging.LogRecord(
                    "projects",
                    logging.INFO,
                    __file__,
                    0,
                    "operation=%s",
                    (action,),
                    None,
                )
            )
        finally:
            handler.close()

    def resolve(self, selector: str | None = None) -> dict[str, Any] | None:
        """Find by UUID/name or current selection; never infer a project from a path."""
        if selector is None:
            selected = self.catalog.execute(
                "SELECT project_id FROM Selection WHERE slot=1"
            ).fetchone()
            if selected is None:
                return None
            selector = selected[0]
        row = self.catalog.execute(
            "SELECT * FROM Catalog WHERE id=? OR name=?", (selector, selector)
        ).fetchone()
        if row is None:
            raise ValueError(f"Unknown project: {selector}")
        return dict(row)

    def path(self, identifier: str) -> Path:
        """Resolve only canonical UUID directories beneath the project workspace."""
        if str(uuid.UUID(identifier)) != identifier:
            raise ValueError("Invalid project UUID")
        return self.directory / identifier

    def create(
        self,
        name: str,
        description: str = "",
        product: str = "",
        version: str = "",
        root: Path | None = None,
    ) -> dict[str, Any]:
        """Create an empty project, applying only the requested KESL metadata preset."""
        if not name.strip() or len(name) > 120:
            raise ValueError("Project name must contain 1–120 characters")
        if root is not None and not root.is_dir():
            raise ValueError("Target root must be an existing directory")
        if self.catalog.execute(
            "SELECT 1 FROM Catalog WHERE name=?", (name,)
        ).fetchone():
            raise ValueError("Project name already exists")
        if name == "KESL":
            product = product or "Kaspersky Endpoint Security for Linux"
            version = version or "12.5"
            description = (
                description
                or "Authorized Bug Bounty research in an isolated test environment."
            )
        project = {
            "id": str(uuid.uuid4()),
            "name": name,
            "description": description,
            "product": product,
            "product_version": version,
            "created_at": utcnow(),
        }
        destination = self.path(project["id"])
        store = Store(destination / "research.sqlite3")
        try:
            initialize(store.db, project)
            result = KnowledgeEngine(store).project()
            with self.catalog:
                self.catalog.execute(
                    "INSERT INTO Catalog VALUES(?,?,?)",
                    (project["id"], name, str(root.resolve()) if root else None),
                )
        except BaseException:
            store.close()
            shutil.rmtree(destination)
            raise
        finally:
            store.close()
        return result

    def open(self, selector: str, root: Path | None = None) -> dict[str, Any]:
        """Select a project and optionally bind its local target directory."""
        item = self.resolve(selector)
        assert item is not None
        if root is not None and not root.is_dir():
            raise ValueError("Target root must be an existing directory")
        with self.catalog:
            if root is not None:
                self.catalog.execute(
                    "UPDATE Catalog SET root=? WHERE id=?",
                    (str(root.resolve()), item["id"]),
                )
                item["root"] = str(root.resolve())
            self.catalog.execute(
                "INSERT OR REPLACE INTO Selection VALUES(1,?)", (item["id"],)
            )
        return item

    def list(self) -> list[dict[str, Any]]:
        """Read project metadata without combining their knowledge or queues."""
        result = []
        for row in self.catalog.execute("SELECT * FROM Catalog ORDER BY name"):
            store = Store(self.path(row["id"]) / "research.sqlite3")
            try:
                result.append({**KnowledgeEngine(store).project(), "root": row["root"]})
            finally:
                store.close()
        return result

    def attach(self, identifier: str, source: Path, name: str | None = None) -> str:
        """Copy a regular file as immutable, content-addressed project evidence."""
        if source.is_symlink() or not source.is_file():
            raise ValueError("Artifact must be a regular file")
        if source.stat().st_size > MAX_ARCHIVE_BYTES // 2:
            raise ValueError("Artifact exceeds 256 MiB limit")
        base = self.path(identifier)
        if not (base / "research.sqlite3").is_file():
            raise ValueError("Unknown project database")
        folder = base / "artifacts"
        folder.mkdir(exist_ok=True)
        digest = hashlib.sha256()
        descriptor, temporary = tempfile.mkstemp(dir=folder)
        try:
            with os.fdopen(descriptor, "wb") as output, source.open("rb") as stream:
                size = 0
                while chunk := stream.read(65536):
                    size += len(chunk)
                    if size > MAX_ARCHIVE_BYTES // 2:
                        raise ValueError("Artifact grew beyond size limit")
                    digest.update(chunk)
                    output.write(chunk)
            sha = digest.hexdigest()
            os.replace(temporary, folder / sha)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        store = Store(base / "research.sqlite3")
        try:
            return KnowledgeEngine(store).add(
                "Artifacts",
                name or source.name,
                evidence={"blob": f"artifacts/{sha}", "sha256": sha, "bytes": size},
            )
        finally:
            store.close()

    def export(self, identifier: str, destination: Path) -> None:
        """Export a consistent SQLite snapshot as lossless JSON rows plus owned blobs."""
        base = self.path(identifier)
        if destination.resolve() in {
            base / "research.sqlite3",
            self.workspace / "catalog.sqlite3",
        }:
            raise ValueError("Export destination cannot overwrite a database")
        source = sqlite3.connect(base / "research.sqlite3")
        snapshot = sqlite3.connect(":memory:")
        snapshot.row_factory = sqlite3.Row
        try:
            source.backup(snapshot)
            initialize_research(snapshot)
            initialize_plugins(snapshot)
            project = validate(snapshot)
            data = {
                table: [dict(r) for r in snapshot.execute(f"SELECT * FROM {table}")]
                for table in TABLES
            }
        finally:
            source.close()
            snapshot.close()
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        blobs: dict[str, Path] = {}
        for row in data["KnowledgeEntities"]:
            evidence = json.loads(row["evidence"])
            if row["kind"] == "Artifacts" and "blob" in evidence:
                blob = evidence["blob"]
                if (
                    blob != "artifacts/" + evidence["sha256"]
                    or len(evidence["sha256"]) != 64
                ):
                    raise ValueError("Invalid artifact path")
                if any(c not in "0123456789abcdef" for c in evidence["sha256"]):
                    raise ValueError("Invalid artifact digest")
                blobs[blob] = base / blob
        manifest: dict[str, Any] = {
            "format": "research-project",
            "version": 3,
            "project_id": project["id"],
            "files": {},
        }
        manifest["files"]["data.json"] = {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
        }
        for name, path in blobs.items():
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if digest != path.name:
                raise ValueError("Artifact integrity check failed")
            manifest["files"][name] = {"sha256": digest, "bytes": path.stat().st_size}
        if sum(f["bytes"] for f in manifest["files"].values()) > MAX_ARCHIVE_BYTES:
            raise ValueError("Project exceeds portable archive limit (512 MiB)")
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(dir=destination.parent, suffix=".tmp")
        os.close(descriptor)
        try:
            with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("manifest.json", json.dumps(manifest))
                archive.writestr("data.json", payload)
                for name, path in blobs.items():
                    archive.write(path, name)
            os.replace(temporary, destination)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def import_archive(self, source: Path) -> dict[str, Any]:
        """Validate archive content and rebuild a known schema without executing archive SQL."""
        with tempfile.TemporaryDirectory(
            dir=self.workspace, prefix="import-"
        ) as scratch:
            staging = Path(scratch)
            with zipfile.ZipFile(source) as archive:
                infos = archive.infolist()
                names = [i.filename for i in infos]
                if len(set(names)) != len(names) or len(names) > 10000:
                    raise ValueError("Duplicate or excessive archive entries")
                if sum(i.file_size for i in infos) > MAX_ARCHIVE_BYTES + 1048576:
                    raise ValueError("Archive exceeds size limit")
                if (
                    "manifest.json" not in names
                    or archive.getinfo("manifest.json").file_size > 1048576
                ):
                    raise ValueError("Missing or oversized manifest")
                manifest = json.loads(archive.read("manifest.json"))
                if manifest.get("format") != "research-project" or manifest.get(
                    "version"
                ) not in (1, 2, 3):
                    raise ValueError("Unsupported project archive")
                expected = manifest["files"]
                if (
                    set(names) != {"manifest.json", *expected}
                    or "data.json" not in expected
                ):
                    raise ValueError("Archive entries do not match manifest")
                for name, details in expected.items():
                    valid_blob = (
                        name.startswith("artifacts/")
                        and len(name) == 74
                        and all(c in "0123456789abcdef" for c in name[10:])
                    )
                    if name != "data.json" and not valid_blob:
                        raise ValueError("Unsafe archive path")
                    content = archive.read(name)
                    if (
                        len(content) != details["bytes"]
                        or hashlib.sha256(content).hexdigest() != details["sha256"]
                    ):
                        raise ValueError("Archive integrity check failed")
                    path = staging / name
                    path.parent.mkdir(exist_ok=True)
                    path.write_bytes(content)
            data = json.loads((staging / "data.json").read_text(encoding="utf-8"))
            archive_tables = {1: LEGACY_TABLES, 2: V2_TABLES, 3: TABLES}[
                manifest["version"]
            ]
            if set(data) != set(archive_tables) or len(data["Projects"]) != 1:
                raise ValueError("Incomplete project archive")
            project = data["Projects"][0]
            identifier = project["id"]
            destination = self.path(identifier)
            if identifier != manifest["project_id"]:
                raise ValueError("Project ID mismatch")
            if (
                destination.exists()
                or self.catalog.execute(
                    "SELECT 1 FROM Catalog WHERE id=? OR name=?",
                    (identifier, project["name"]),
                ).fetchone()
            ):
                raise ValueError(
                    "Project ID or name already exists; import into a different workspace"
                )
            store = Store(staging / "research.sqlite3")
            try:
                initialize(store.db, project)
                initialize_research(store.db)
                with store.db:
                    if manifest["version"] >= 2:
                        store.db.execute("DELETE FROM ResearchSchema")
                    store.db.execute("DELETE FROM KnowledgeSchema")
                    store.db.execute("DELETE FROM Projects")
                    for table in archive_tables:
                        columns = [
                            r[1]
                            for r in store.db.execute(f"PRAGMA table_info({table})")
                        ]
                        for row in data[table]:
                            if set(row) != set(columns):
                                raise ValueError("Invalid archive columns")
                            store.db.execute(
                                f"INSERT INTO {table}({','.join(columns)}) "
                                f"VALUES({','.join('?' for _ in columns)})",
                                [row[c] for c in columns],
                            )
                    validate(store.db)
                    validate_research(store.db)
                    for row in data["KnowledgeEntities"]:
                        evidence = json.loads(row["evidence"])
                        if not isinstance(evidence, dict):
                            raise ValueError("Entity evidence must be a mapping")
                        if row["kind"] == "Artifacts" and "blob" in evidence:
                            blob = evidence["blob"]
                            if (
                                blob not in expected
                                or blob != "artifacts/" + evidence["sha256"]
                            ):
                                raise ValueError("Missing artifact attachment")
                            if expected[blob] != {
                                "sha256": evidence["sha256"],
                                "bytes": evidence["bytes"],
                            }:
                                raise ValueError("Artifact metadata mismatch")
                store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                store.close()
            (staging / "data.json").unlink()
            os.replace(staging, destination)
            try:
                with self.catalog:
                    self.catalog.execute(
                        "INSERT INTO Catalog VALUES(?,?,NULL)",
                        (identifier, project["name"]),
                    )
            except BaseException:
                shutil.rmtree(destination)
                raise
            return dict(project)
