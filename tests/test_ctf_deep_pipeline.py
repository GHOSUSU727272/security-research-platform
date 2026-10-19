import codecs
import json
import struct
from pathlib import Path

from ctf.challenges import add, analyze


def test_web_and_pcap_deep_integrated(tmp_path: Path) -> None:
    source = tmp_path / "training"
    source.mkdir()
    (source / "web.html").write_text(
        '<!-- ' + codecs.encode("flag{in_comment}", "rot_13") + ' -->'
        '<input type=hidden name=token value="flag&#123;in_hidden&#125;">'
    )
    message = codecs.encode("flag{on_wire}", "rot_13").encode()
    udp = struct.pack("!HHHH", 42311, 8080, len(message) + 8, 0) + message
    ip = bytes.fromhex("45000000") + bytes(4) + bytes([64, 17]) + bytes(2)
    ip += bytes([192, 0, 2, 1, 192, 0, 2, 2])
    ip = ip[:2] + struct.pack("!H", len(ip) + len(udp)) + ip[4:]
    eth = bytes(12) + b"\x08\x00" + ip + udp
    pcap = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    pcap += struct.pack("<IIII", 0, 0, len(eth), len(eth)) + eth
    (source / "traffic.pcap").write_bytes(pcap)
    workspace = tmp_path / "workspace"
    add(workspace, "challenge", source, "forensics")
    result = analyze(workspace, "challenge")
    assert {"flag{in_comment}", "flag{in_hidden}", "flag{on_wire}"} <= set(
        result["candidate_solutions"]
    )
    assert result["auto_solution_count"] >= 3
    report_html = (workspace / "reports/challenge/index.html").read_text()
    assert "Deep inspection" in report_html
    assert "pcap" in report_html and "static-web" in report_html
    json.loads((workspace / "reports/challenge/report.json").read_text())
