"""Bounded offline inspection of ELF, PCAP, and static web challenge artifacts."""
from __future__ import annotations

import argparse
import io
import ipaddress
import json
import struct
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from ctf.solvers import solve_bytes

MAX_ARTIFACT = 4 * 1024 * 1024
MAX_PACKETS = 250
MAX_PAYLOADS = 40
MAX_FINDINGS = 40
FLAG_CAP = 160

class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.hidden: list[dict[str, str]] = []
        self.comments: list[str] = []
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "input" and (values.get("type") or "").lower() == "hidden":
            self.hidden.append({"name": (values.get("name") or "")[:80],
                                "value": (values.get("value") or "")[:FLAG_CAP]})
        if tag in ("script", "link", "a"):
            for key in ("src", "href"):
                if values.get(key) and len(self.links) < 80:
                    self.links.append((values[key] or "")[:200])
        if tag == "script" and values.get("src"):
            self.scripts.append((values["src"] or "")[:200])

    def handle_comment(self, text: str) -> None:
        if len(self.comments) < 80:
            self.comments.append(text[:1000])


def inspect_web(data: bytes) -> dict[str, Any]:
    page = _Page()
    page.feed(data[:MAX_ARTIFACT].decode("utf-8", errors="replace"))
    candidates: list[dict[str, Any]] = []
    for index, text in enumerate(page.comments):
        for finding in solve_bytes(text.encode("utf-8"))[:MAX_FINDINGS]:
            candidates.append({**finding, "method": "html-comment>" + finding["method"],
                               "evidence": f"comment-index={index}"})
    for field in page.hidden:
        for finding in solve_bytes(field["value"].encode())[:MAX_FINDINGS]:
            candidates.append({**finding, "method": "hidden-input>" + finding["method"],
                               "evidence": f"field={field['name'][:40]}"})
    return {"type": "static-web", "hidden_inputs": page.hidden[:80],
            "links": page.links[:80], "comments_count": len(page.comments),
            "external_scripts": page.scripts[:80],
            "candidate_flags": candidates[:MAX_FINDINGS]}


def inspect_elf(data: bytes) -> dict[str, Any]:
    if not data.startswith(b"\x7fELF"):
        raise ValueError("Not an ELF file")
    elf = ELFFile(io.BytesIO(data))
    segments = list(elf.iter_segments())
    stack = next((segment for segment in segments
                  if segment["p_type"] == "PT_GNU_STACK"), None)
    executable_stack = bool(stack is not None and stack["p_flags"] & 1)
    relro = any(segment["p_type"] == "PT_GNU_RELRO" for segment in segments)
    symbols: list[str] = []
    candidate_flags: list[dict[str, Any]] = []
    sections: list[str] = []
    for section in elf.iter_sections():
        name = section.name[:80]
        sections.append(name)
        if isinstance(section, SymbolTableSection):
            for index, symbol in enumerate(section.iter_symbols()):
                if index >= 4000:
                    break
                label = symbol.name
                if label and len(symbols) < 150:
                    symbols.append(label[:120])
        if name in (".rodata", ".data") and section["sh_size"] <= MAX_ARTIFACT:
            contents = section.data()
            for finding in solve_bytes(contents)[:MAX_FINDINGS]:
                candidate_flags.append({**finding, "method": "elf-" + name + ">" + finding["method"],
                                        "evidence": "ELF section " + name})
    return {"type": "elf", "machine": str(elf["e_machine"]),
            "entrypoint": hex(elf["e_entry"]),
            "elf_type": str(elf["e_type"]),
            "is_pie_or_shared": elf["e_type"] == "ET_DYN",
            "nx_stack": None if stack is None else not executable_stack,
            "relro_segment": relro,
            "stack_canary_symbol": any("__stack_chk_fail" in sym for sym in symbols),
            "section_names": sections[:120],
            "symbols": symbols, "candidate_flags": candidate_flags[:MAX_FINDINGS]}


def _dns_name(data: bytes) -> str | None:
    if len(data) < 13:
        return None
    parts: list[str] = []
    index = 12
    for _ in range(30):
        if index >= len(data):
            return None
        count = data[index]
        index += 1
        if count == 0:
            return ".".join(parts)
        if count > 63 or index + count > len(data):
            return None
        part = data[index:index + count].decode("ascii", errors="replace")
        parts.append(part)
        index += count
    return None


def _ipv4_packet(data: bytes, linktype: int) -> tuple[str, str, str, bytes, int, int] | None:
    if linktype == 1:
        if len(data) < 14:
            return None
        ethtype = int.from_bytes(data[12:14], "big")
        offset = 14
        if ethtype == 0x8100 and len(data) >= 18:
            ethtype = int.from_bytes(data[16:18], "big")
            offset = 18
        if ethtype != 0x0800:
            return None
        data = data[offset:]
    elif linktype != 101:
        return None
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    header_length = (data[0] & 15) * 4
    if header_length < 20 or len(data) < header_length:
        return None
    length = min(len(data), int.from_bytes(data[2:4], "big"))
    if length < header_length or int.from_bytes(data[6:8], "big") & 0x1FFF:
        return None
    src = str(ipaddress.IPv4Address(data[12:16]))
    dest = str(ipaddress.IPv4Address(data[16:20]))
    proto = data[9]
    remaining = data[header_length:length]
    if proto == 6:
        if len(remaining) < 20:
            return None
        size = (remaining[12] >> 4) * 4
        if size < 20 or len(remaining) < size:
            return None
        a, b = struct.unpack("!HH", remaining[:4])
        return src, dest, "tcp", remaining[size:], a, b
    if proto == 17:
        if len(remaining) < 8:
            return None
        a, b = struct.unpack("!HH", remaining[:4])
        return src, dest, "udp", remaining[8:], a, b
    return None


def inspect_pcap(data: bytes) -> dict[str, Any]:
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("Unsupported PCAP header (PCAPNG not handled)")
    if len(data) < 24:
        raise ValueError("Truncated PCAP header")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    position, packets, payloads = 24, 0, 0
    protocols: dict[str, int] = {}
    dns_queries: list[str] = []
    http_requests: list[str] = []
    findings: list[dict[str, Any]] = []
    while packets < MAX_PACKETS and position + 16 <= len(data):
        ts_sec, ts_sub, incl_len, orig_len = struct.unpack(
            endian + "IIII", data[position:position + 16])
        del ts_sec, ts_sub, orig_len
        position += 16
        if incl_len > MAX_ARTIFACT or position + incl_len > len(data):
            break
        packet = data[position:position + incl_len]
        position += incl_len
        packets += 1
        parsed = _ipv4_packet(packet, linktype)
        if parsed is None:
            continue
        src, dest, protocol, payload, sport, dport = parsed
        protocols[protocol] = protocols.get(protocol, 0) + 1
        if protocol == "udp" and (sport == 53 or dport == 53):
            query = _dns_name(payload)
            if query and len(dns_queries) < 100:
                dns_queries.append(query[:200])
        if payload.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ")):
            first = payload.split(b"\r\n", 1)[0]
            if len(http_requests) < 100:
                http_requests.append(first[:200].decode("ascii", errors="replace"))
        if payload and payloads < MAX_PAYLOADS and len(findings) < MAX_FINDINGS:
            payloads += 1
            for finding in solve_bytes(payload[:8192])[:MAX_FINDINGS - len(findings)]:
                findings.append({
                    **finding, "method": "pcap-payload>" + finding["method"],
                    "evidence": f"packet={packets}; {src}:{sport}->{dest}:{dport}",
                })
    return {"type": "pcap", "linktype": linktype,
            "packets_inspected": packets, "protocols": protocols,
            "dns_queries": dns_queries,
            "http_requests": http_requests,
            "candidate_flags": findings, "truncated": position < len(data)}


def inspect_pcapng(data: bytes) -> dict[str, Any]:
    """Read bounded PCAPNG Enhanced Packet Blocks (no external tshark)."""
    if data[:4] != bytes.fromhex("0a0d0d0a") or len(data) < 28:
        raise ValueError("Not a complete PCAPNG section header")
    bom = data[8:12]
    if bom == bytes.fromhex("4d3c2b1a"):
        endian = "<"
    elif bom == bytes.fromhex("1a2b3c4d"):
        endian = ">"
    else:
        raise ValueError("Unsupported PCAPNG byte order")
    interfaces: list[int] = []
    packet_data = bytearray()
    offset = 0
    frame_count = 0
    while offset + 12 <= len(data) and frame_count < MAX_PACKETS:
        block_type, block_length = struct.unpack(endian + "II", data[offset:offset + 8])
        if (block_length < 12 or block_length % 4 != 0
                or offset + block_length > len(data)):
            break
        tail = struct.unpack(endian + "I",
                             data[offset + block_length - 4:offset + block_length])[0]
        if tail != block_length:
            break
        body = data[offset + 8:offset + block_length - 4]
        if block_type == 1 and len(body) >= 8:
            interfaces.append(struct.unpack(endian + "H", body[:2])[0])
        if block_type == 6 and len(body) >= 20:
            interface_id, _, _, caplen, _ = struct.unpack(endian + "IIIII", body[:20])
            if (interface_id < len(interfaces) and interfaces[interface_id] == 1
                    and caplen <= MAX_ARTIFACT and caplen <= len(body) - 20):
                frame = body[20:20 + caplen]
                packet_data.extend(struct.pack("<IIII", 0, 0, caplen, caplen))
                packet_data.extend(frame)
                frame_count += 1
        offset += block_length
    capture = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    result = inspect_pcap(capture + bytes(packet_data))
    result["type"] = "pcapng"
    result["interfaces"] = interfaces[:32]
    result["truncated"] = offset < len(data) or frame_count >= MAX_PACKETS
    return result


def inspect_file(path: Path) -> dict[str, Any]:
    """Read a bounded sample. No external commands or network access."""
    if path.is_symlink() or not path.is_file():
        return {}
    with path.open("rb") as stream:
        data = stream.read(MAX_ARTIFACT)
    try:
        if data.startswith(b"\x7fELF"):
            return inspect_elf(data)
        if data.startswith(b"\x0a\x0d\x0d\x0a"):
            return inspect_pcapng(data)
        if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                        b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            return inspect_pcap(data)
        if path.suffix.lower() in (".html", ".htm"):
            return inspect_web(data)
    except (ELFError, ValueError, TypeError, IndexError, struct.error, OverflowError) as exc:
        return {"type": "unreadable", "error": str(exc)[:200]}
    return {}


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline ELF, PCAP and Web inspection")
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(inspect_file(args.file), ensure_ascii=False, indent=2))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
