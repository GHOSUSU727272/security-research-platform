import codecs
from pathlib import Path

from ctf.challenges import add, analyze
from ctf.event import solarctf_candidates


def test_event_regex_exact() -> None:
    examples = [
        "SOLARCTF{Valid_2026_ABC}",
        "solarctf{lowercase_prefix}",
        "SOLARCTF{dash-is-invalid}",
        "SOLARCTF{spaces are invalid}",
        "flag{unrelated}",
        "SOLARCTF{}",
        "SOLARCTF{valid}more",
    ]
    assert solarctf_candidates(examples) == ["SOLARCTF{Valid_2026_ABC}"]


def test_event_format_report(tmp_path: Path) -> None:
    source = tmp_path / "files"
    source.mkdir()
    encoded = codecs.encode("SOLARCTF{Test_ABC_123}", "rot_13")
    (source / "encoded.txt").write_text(encoded)
    (source / "other.txt").write_text("flag{not_solar}")
    workspace = tmp_path / "work"
    add(workspace, "solarchallenge", source)
    report = analyze(workspace, "solarchallenge")
    assert report["solarctf_candidates"] == ["SOLARCTF{Test_ABC_123}"]
    assert report["solarctf_candidate_count"] == 1
    html = (workspace / "reports" / "solarchallenge" / "index.html").read_text()
    assert "SOLARCTF format candidates" in html
    assert "SOLARCTF{Test_ABC_123}" in html
    dashboard = (workspace / "index.html").read_text()
    assert "SOLARCTF format" in dashboard
