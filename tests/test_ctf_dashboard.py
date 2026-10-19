from pathlib import Path

from ctf.challenges import add, analyze
from ctf.dashboard import render


def test_dashboard_links_and_escaping(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    (source / "flag.txt").write_text("flag{dashboard}")
    workspace = tmp_path / "workspace"
    add(workspace, "sample", source)
    analyze(workspace, "sample")
    html = render(workspace).read_text()
    assert "reports/sample/index.html" in html
    assert "analyzed" in html
    assert "CTF Workbench" in html
