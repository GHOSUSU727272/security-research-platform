import codecs
import struct
import zlib
from pathlib import Path

from ctf.deep import inspect_file, inspect_pcapng
from ctf.solvers import solve_bytes


def _block(kind: int, body: bytes) -> bytes:
    padding = (-len(body)) % 4
    payload = body + bytes(padding)
    length = len(payload) + 12
    return struct.pack("<II", kind, length) + payload + struct.pack("<I", length)


def test_pcapng_enhanced_packet_rot() -> None:
    payload = codecs.encode("SOLARCTF{Pcapng_2026}", "rot_13").encode()
    udp = struct.pack("!HHHH", 10101, 20001, len(payload) + 8, 0) + payload
    ip = bytes.fromhex("45000000") + bytes(4) + bytes([64, 17]) + bytes(2)
    ip += bytes([192, 0, 2, 3, 192, 0, 2, 4])
    ip = ip[:2] + struct.pack("!H", len(ip) + len(udp)) + ip[4:]
    packet = bytes(12) + b"\x08\x00" + ip + udp
    shb = _block(0x0a0d0d0a, b"\x4d\x3c\x2b\x1a" +
                 struct.pack("<HHq", 1, 0, -1))
    idb = _block(1, struct.pack("<HHI", 1, 0, 65535))
    epb = _block(6, struct.pack("<IIIII", 0, 0, 0, len(packet), len(packet))
                 + packet)
    report = inspect_pcapng(shb + idb + epb)
    assert report["type"] == "pcapng"
    assert report["packets_inspected"] == 1
    assert any(c["flag"] == "SOLARCTF{Pcapng_2026}"
               for c in report["candidate_flags"])


def test_pcapng_file_routing(tmp_path: Path) -> None:
    path = tmp_path / "empty.pcapng"
    path.write_bytes(_block(0x0a0d0d0a, b"\x4d\x3c\x2b\x1a" +
                            struct.pack("<HHq", 1, 0, -1)))
    assert inspect_file(path)["type"] == "pcapng"


def test_png_compressed_text_flag() -> None:
    payload = b"Comment\x00\x00" + zlib.compress(b"SOLARCTF{PNG_Secret}")
    chunk = struct.pack(">I", len(payload)) + b"zTXt" + payload
    chunk += struct.pack(">I", zlib.crc32(b"zTXt" + payload))
    png = b"\x89PNG\r\n\x1a\n" + chunk
    assert any(c["flag"] == "SOLARCTF{PNG_Secret}" and c["method"] == "png-text"
               for c in solve_bytes(png))


def test_pcapng_invalid_length() -> None:
    data = _block(0x0a0d0d0a, b"\x4d\x3c\x2b\x1a" +
                  struct.pack("<HHq", 1, 0, -1))
    corrupted = data[:-4] + bytes(4)
    result = inspect_pcapng(corrupted)
    assert result["packets_inspected"] == 0
