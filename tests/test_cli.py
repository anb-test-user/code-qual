"""End-to-end CLI tests (heuristic mode, no API key needed)."""
import json

from codequal.cli import main


def test_file_json_and_failon_exit(tmp_path, capsys):
    target = tmp_path / "x.py"
    target.write_text("def f(x=[]):\n    return eval(x)\n", encoding="utf-8")
    code = main(["file", str(target), "--no-ai", "--format", "json", "--fail-on", "high", "-q"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["mode"] == "heuristic"
    assert data["total_findings"] >= 1
    # eval -> high severity -> fail-on high must trip a non-zero exit.
    assert code == 1


def test_fail_on_none_returns_zero(tmp_path, capsys):
    target = tmp_path / "x.py"
    target.write_text("x = (1 == None)\n", encoding="utf-8")
    code = main(["file", str(target), "--no-ai", "--format", "json", "--fail-on", "none", "-q"])
    capsys.readouterr()
    assert code == 0


def test_clean_file_exits_zero(tmp_path, capsys):
    target = tmp_path / "clean.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    code = main(["file", str(target), "--no-ai", "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["total_findings"] == 0
    assert code == 0


def test_version_command(capsys):
    assert main(["version"]) == 0
    assert "codequal" in capsys.readouterr().out


def test_no_command_prints_help(capsys):
    assert main([]) == 0
    assert "usage" in capsys.readouterr().out.lower()
