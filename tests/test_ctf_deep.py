import codecs
import struct
from pathlib import Path

from ctf.deep import inspect_elf, inspect_file, inspect_pcap, inspect_web


def test_html_hidden_encoded_flag() -> None:
    page = b'<input type="hidden" name="token" value="flag&#123;hidden&#125;">'
    result = inspect_web(page)
    assert result["hidden_inputs"][0]["value"] == "flag{hidden}"
    assert any(item["flag"] == "flag{hidden}" for item in result["candidate_flags"])


def test_html_comment_rot() -> None:
    encoded = codecs.encode("flag{comment}", "rot_13")
    data = f"<!-- {encoded} --><script src='scripts/app.js'></script>".encode()
    result = inspect_web(data)
    assert result["external_scripts"] == ["scripts/app.js"]
    assert any(item["flag"] == "flag{comment}" for item in result["candidate_flags"])


def test_minimal_elf() -> None:
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    data = struct.pack("<16sHHIQQQIHHHHHH",
                       ident, 2, 62, 1, 0x401000, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    result = inspect_elf(data)
    assert result["type"] == "elf"
    assert result["machine"] == "EM_X86_64"


def test_pcap_udp_rot_flag() -> None:
    cipher = codecs.encode("flag{packet_inspected}", "rot_13").encode()
    udp = struct.pack("!HHHH", 12345, 9999, len(cipher) + 8, 0) + cipher
    ip = bytes.fromhex("45000000") + bytes(4) + bytes([64,17]) + bytes(2)
    ip += bytes([192, 0, 2, 1, 192, 0, 2, 2])
    ip = ip[:2] + struct.pack("!H", len(ip) + len(udp)) + ip[4:]
    eth = bytes(12) + b"\x08\x00" + ip + udp
    header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 0, 0, len(eth), len(eth))
    result = inspect_pcap(header + record + eth)
    assert result["packets_inspected"] == 1
    assert result["protocols"]["udp"] == 1
    assert any(item["flag"] == "flag{packet_inspected}"
               for item in result["candidate_flags"])


def test_truncated_pcap() -> None:
    result = inspect_pcap(b"\xd4\xc3\xb2\xa1" + bytes(20))
    assert result["packets_inspected"] == 0


def test_file_dispatch(tmp_path: Path) -> None:
    file = tmp_path / "puzzle.html"
    file.write_text("<input type=hidden value='flag{dispatch}'>")
    assert inspect_file(file)["type"] == "static-web"
    outside = tmp_path / "outside"
    outside.write_bytes(b"flag{outside}")
    (tmp_path / "linked.html").symlink_to(outside)
    assert inspect_file(tmp_path / "linked.html") == {}
