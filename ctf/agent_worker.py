"""Isolated process for one bounded strategy. Results contain provenance, not claims of acceptance."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import resource
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import zipfile
from collections import deque
from pathlib import Path

from ctf.advanced import periodic_xor, python_constraints, rsa
from ctf.advanced import transforms as advanced_transforms
from ctf.solve import _decodings
from ctf.techniques import crypto, encodings, source_constraints

PATTERN = re.compile(rb"(?:SOLARCTF|solarctf|solar|flag|CTF|ctf|crypto|picoCTF)\{[A-Za-z0-9_:@!?.+/-]{3,160}\}")
MAX_BYTES = 32 * 1024 * 1024
MAX_FILE = 4 * 1024 * 1024


def artifacts(root: Path):
    remaining = MAX_BYTES
    count = 0
    for folder, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and not (Path(folder)/d).is_symlink())
        for name in sorted(names):
            path = Path(folder)/name
            if path.is_symlink() or not path.is_file():
                continue
            if count >= 100 or remaining <= 0:
                return
            with path.open("rb") as stream:
                data = stream.read(min(MAX_FILE, remaining))
            remaining -= len(data)
            count += 1
            yield str(path.relative_to(root)), data


def unpack(data: bytes) -> list[tuple[str, bytes]]:
    out = []
    remaining = 8 * 1024 * 1024
    def safe(name):
        parts = name.replace("\\", "/").split("/")
        return not name.startswith(("/", "\\")) and ".." not in parts and ":" not in parts[0]
    try:
        if data.startswith(b"PK\x03\x04"):
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for item in z.infolist()[:100]:
                    if (not safe(item.filename) or item.is_dir() or item.flag_bits & 1
                            or stat.S_ISLNK(item.external_attr >> 16)
                            or item.file_size > min(MAX_FILE, remaining)
                            or item.file_size > max(1, item.compress_size)*100):
                        continue
                    with z.open(item) as stream:
                        content = stream.read(min(MAX_FILE, remaining)+1)
                    if len(content) > min(MAX_FILE, remaining):
                        continue
                    remaining -= len(content)
                    out.append(("zip:"+item.filename, content))
        elif data.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ")) or data[257:262] == b"ustar":
            try:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                    for index, item in enumerate(archive):
                        if index >= 100:
                            break
                        if not item.isfile() or not safe(item.name) or item.size > min(MAX_FILE, remaining):
                            continue
                        stream = archive.extractfile(item)
                        if stream:
                            content = stream.read(min(MAX_FILE, remaining)+1)
                            remaining -= len(content)
                            out.append(("tar:"+item.name, content))
            except tarfile.ReadError:
                import bz2
                import gzip
                import lzma
                opener = (lambda source: gzip.GzipFile(fileobj=source)) if data.startswith(b"\x1f\x8b") else bz2.BZ2File if data.startswith(b"BZh") else lzma.LZMAFile
                with opener(io.BytesIO(data)) as stream:
                    content = stream.read(MAX_FILE+1)
                if len(content) <= MAX_FILE:
                    out.append(("decompress", content))
    except (OSError, ValueError, EOFError, zipfile.BadZipFile, tarfile.TarError):
        pass
    return out


def graph(data: bytes, smart: bool = False, deadline=None) -> tuple[list[dict], int]:
    queue = deque([(data, [], 0)])
    seen = {hashlib.sha256(data).digest()}
    found = {}
    visited, total = 0, len(data)
    while queue and visited < 400:
        if deadline is not None and time.monotonic() >= deadline:
            break
        blob, methods, depth = queue.popleft()
        visited += 1
        # Archive members are inspected only after path/size validation.
        archive = blob.startswith((b"PK\x03\x04", b"\x1f\x8b", b"BZh", b"\xfd7zXZ")) or blob[257:262] == b"ustar"
        if not archive:
            for match in PATTERN.finditer(blob):
                flag = match.group().decode("ascii")
                found.setdefault(flag, {"flag": flag, "method": " > ".join(methods) or "plain",
                                       "confidence": "heuristic" if any(m.startswith("heuristic-") for m in methods) else "format_match",
                                       "offset": match.start(), "verified": False})
        if depth >= 5:
            continue
        transforms = unpack(blob) if archive else encodings(blob) + source_constraints(blob) + _decodings(blob)
        if not archive and depth < 3:
            transforms += advanced_transforms(blob)
        if smart and not archive and not any(m.startswith(("caesar", "atbash", "xor-", "single-byte-xor", "heuristic-", "rot47")) for m in methods):
            transforms += crypto(blob) + rsa(blob) + periodic_xor(blob)
            if b"assert " in blob and b"len(" in blob:
                transforms += python_constraints(blob)
        for name, value in transforms:
            digest = hashlib.sha256(value).digest()
            if not value or value == blob or digest in seen or len(value) > MAX_FILE:
                continue
            if len(seen) >= 400 or total+len(value) > MAX_BYTES:
                break
            seen.add(digest)
            total += len(value)
            queue.append((value, methods+[name], depth+1))
    return list(found.values())[:100], visited


def native(argv: list[str], seconds: float) -> dict:
    if not shutil.which(argv[0]):
        return {"tool": argv[0], "status": "unavailable"}
    # File output avoids pipe deadlocks; RLIMIT_FSIZE caps output at 16 MiB.
    with open("/job/tool-output.txt", "wb+") as output:
        try:
            done = subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT,
                                  timeout=max(0.1, seconds), check=False)
            output.seek(0)
            return {"tool": argv[0], "status": "completed" if done.returncode == 0 else "error",
                    "output": output.read(256*1024).decode("utf-8", "replace"), "returncode": done.returncode}
        except subprocess.TimeoutExpired:
            return {"tool": argv[0], "status": "timeout"}


def analyze(root: Path, phase: str, budget: float) -> dict:
    started = time.monotonic()
    deadline = started + budget
    results, history, inspections = [], [], []

    def checkpoint():
        target = Path("/job/result.json")
        partial = {"candidates": list({v["flag"]: v for v in results}.values()),
                   "history": history[-100:], "inspections": inspections[-30:],
                   "reason": "partial", "elapsed": time.monotonic()-started}
        temporary = target.with_suffix(".tmp")
        temporary.write_text(json.dumps(partial))
        temporary.replace(target)

    for label, data in artifacts(root):
        if time.monotonic() >= deadline:
            break
        digest = hashlib.sha256(data).hexdigest()
        findings, attempts = graph(data, phase != "fast", deadline)
        for item in findings:
            results.append({**item, "source": label, "sha256": digest})
        history.append({"source": label, "strategy": "transform-graph", "nodes": attempts})
        if (root/label).stat().st_size > len(data):
            history.append({"source": label, "warning": "Transform scan truncated at input size limit"})
        checkpoint()
        path = root/label
        if phase != "fast":
            from ctf.deep import inspect_file
            from ctf.solvers import solve_file
            try:
                for item in solve_file(path):
                    if PATTERN.fullmatch(item["flag"].encode()):
                        results.append({**item, "source": label, "sha256": digest, "verified": False,
                                        "confidence": "format_match"})
                detail = inspect_file(path)
                if detail:
                    inspections.append({"source": label, "detail": detail})
                    for item in detail.get("candidate_flags", []):
                        results.append({**item, "source": label, "sha256": digest,
                                        "confidence": "format_match", "verified": False})
            except Exception as exc:
                history.append({"source": label, "error": type(exc).__name__})
            commands = []
            # UTF-16 strings, packet payloads, audio and image bit planes are
            # interpreted as data inside the worker, never as host commands.
            from ctf.media import recover
            try:
                for method, recovered in recover(data):
                    if time.monotonic() >= deadline:
                        break
                    for item in graph(recovered, deadline=deadline)[0]:
                        results.append({**item, "source": label, "sha256": digest,
                                        "method": method+" > "+item["method"]})
                    if results:
                        checkpoint()
            except Exception as exc:
                history.append({"source": label, "strategy": "media", "error": type(exc).__name__})
            if data.startswith(b"\x7fELF"):
                commands += [["readelf", "-W", "-l", "-d", str(path)], ["objdump", "-d", str(path)]]
            if data[:4] in (bytes.fromhex("0a0d0d0a"), bytes.fromhex("d4c3b2a1"), bytes.fromhex("a1b2c3d4")):
                commands += [["tshark", "-n", "-r", str(path), "-c", "2000", "-T", "fields",
                              "-e", "tcp.payload", "-e", "udp.payload", "-e", "dns.qry.name", "-e", "http.request.uri"]]
            if data.startswith(b"%PDF"):
                commands += [["pdftotext", str(path), "-"]]
            if data.startswith((b"\x89PNG", b"\xff\xd8", b"GIF8")):
                commands += [["exiftool", str(path)], ["zbarimg", "--quiet", "--raw", str(path)]]
                try:
                    from PIL import Image
                    Image.MAX_IMAGE_PIXELS = 4_000_000
                    with Image.open(io.BytesIO(data)) as picture:
                        if picture.width*picture.height <= 4_000_000:
                            pixels = picture.convert("RGB").tobytes()
                            for channel in (pixels, pixels[0::3], pixels[1::3], pixels[2::3]):
                                bits = bytes(v & 1 for v in channel[:2_000_000])
                                recovered = bytes(sum(bits[i+j] << (7-j) for j in range(8))
                                                  for i in range(0, len(bits)-7, 8))
                                for item in graph(recovered, deadline=deadline)[0]:
                                    results.append({**item, "source": label, "sha256": digest, "method": "image-lsb > "+item["method"]})
                except Exception as exc:
                    history.append({"source": label, "strategy": "image-lsb", "error": type(exc).__name__})
            if phase == "deep" and data.startswith(b"\x7fELF"):
                commands += [["/usr/share/ghidra/support/analyzeHeadless", "/job", "analysis", "-import", str(path),
                              "-analysisTimeoutPerFile", "60", "-deleteProject"]]
            for command in commands:
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    break
                report = native(command, min(remaining, 70 if phase == "deep" else 15))
                history.append({"source": label, **report})
                for item in graph(report.get("output", "").encode(), deadline=deadline)[0]:
                    results.append({**item, "source": label, "sha256": digest,
                                    "method": command[0]+" > "+item["method"]})
                if command[0] == "tshark":
                    chunks = re.findall(r"(?m)^[0-9a-f]{8,}\b", report.get("output", ""))
                    try:
                        joined = b"".join(bytes.fromhex(v) for v in chunks)
                        for item in graph(joined, smart=True, deadline=deadline)[0]:
                            results.append({**item, "source": label, "sha256": digest,
                                            "method": "packet-payload-concatenation > "+item["method"]})
                    except ValueError:
                        pass
                checkpoint()
    dedup = {}
    for item in results:
        dedup.setdefault(item["flag"], item)
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return {"candidates": list(dedup.values()), "history": history, "inspections": inspections,
            "elapsed": time.monotonic()-started, "max_rss_kib": usage.ru_maxrss,
            "cpu_seconds": usage.ru_utime+usage.ru_stime,
            "reason": "budget" if time.monotonic() >= deadline else "strategies_exhausted"}


def main():
    request = json.loads(Path(sys.argv[1]).read_text())
    resource.setrlimit(resource.RLIMIT_AS, (request["memory_mb"]*1024**2,)*2)
    resource.setrlimit(resource.RLIMIT_CPU, (int(request["budget"])+1,)*2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (16*1024**2,)*2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if request["phase"] == "llm":
        tool = native([sys.executable, "/job/solver.py"], request["budget"])
        candidates = graph(tool.get("output", "").encode())[0]
        for candidate in candidates:
            candidate.update(source="generated-solver-output", confidence="unverified_generated_solution")
        result = {"candidates": candidates, "history": [tool], "reason": tool["status"]}
    else:
        result = analyze(Path("/input"), request["phase"], request["budget"])
    Path("/job/result.json").write_text(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
