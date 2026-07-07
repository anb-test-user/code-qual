"""Tests for tools/aikido_report.py (data layer + renderers)."""

import importlib.util
import json
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"

spec = importlib.util.spec_from_file_location("aikido_report", TOOLS_DIR / "aikido_report.py")
ar = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ar)


def test_pick_fallback_chain():
    record = {"remediation": "", "fix": None, "fix_suggestion": "Update to 2.0"}
    assert ar.pick(record, "remediation", "fix", "fix_suggestion") == "Update to 2.0"
    assert ar.pick(record, "missing", default="n/a") == "n/a"
    assert ar.pick({"cves": ["CVE-1", "CVE-2"]}, "cves") == "CVE-1; CVE-2"


def test_normalize_severity():
    assert ar.normalize_severity("Critical") == "critical"
    assert ar.normalize_severity("HIGH") == "high"
    assert ar.normalize_severity(None, score=95) == "critical"
    assert ar.normalize_severity(None, score=75) == "high"
    assert ar.normalize_severity(None, score=50) == "medium"
    assert ar.normalize_severity(None, score=10) == "low"
    assert ar.normalize_severity(None) == "medium"


def test_humanize_type():
    assert ar.humanize_type("open_source") == "Dependency Vulnerability"
    assert ar.humanize_type("sast") == "SAST Finding"
    assert ar.humanize_type("leaked_secret") == "Secret Detection"
    assert ar.humanize_type("some_new_type") == "Some New Type"


def test_filter_issues_by_status():
    issues = [
        {"id": 1, "status": "open"},
        {"id": 2, "status": "ignored"},
        {"id": 3, "status": "snoozed"},
        {"id": 4},  # no status field -> kept (benefit of the doubt)
        {"id": 5, "state": "closed"},
    ]
    kept = ar.filter_issues_by_status(issues, "open")
    assert [i["id"] for i in kept] == [1, 4]
    assert ar.filter_issues_by_status(issues, "all") == issues


def test_grouping_and_counts():
    issues = [
        {"id": 1, "group_id": 10},
        {"id": 2, "group_id": 10},
        {"id": 3, "group_id": 11},
        {"id": 4},  # no group id -> pseudo-group of its own
    ]
    buckets = ar.group_issues_by_group_id(issues)
    assert len(buckets["10"]) == 2
    assert len(buckets["11"]) == 1
    assert sum(len(v) for v in buckets.values()) == 4


def test_group_to_row_field_fallbacks():
    row = ar.group_to_row({
        "id": 5,
        "issue_type": "sast",
        "severity_score": 92,
        "name": "Unsafe eval",
        "summary": "eval() on user input",
        "fix_suggestion": "Avoid eval()",
        "open_issue_count": 3,
    })
    assert row["type"] == "SAST Finding"
    assert row["severity"] == "critical"
    assert row["count"] == 3
    assert row["title"] == "Unsafe eval"
    assert row["description"] == "eval() on user input"
    assert row["remediation"] == "Avoid eval()"


def test_sorting_severity_then_count():
    rows = ar.sort_rows([
        {"severity": "low", "count": 99, "title": "z"},
        {"severity": "critical", "count": 1, "title": "b"},
        {"severity": "critical", "count": 5, "title": "a"},
        {"severity": "high", "count": 2, "title": "c"},
    ])
    assert [(r["severity"], r["count"]) for r in rows] == [
        ("critical", 5), ("critical", 1), ("high", 2), ("low", 99)]


def test_demo_fixture_matches_reference_report():
    rows = ar.load_demo_rows(TOOLS_DIR / "aikido_sample_data.json")
    stats = ar.summarize(rows)
    assert stats["groups"] == 32
    assert stats["issues"] == 212
    assert stats["by_severity"] == {"critical": 5, "high": 19, "medium": 6, "low": 2}
    assert all(r["remediation"] for r in rows), "every row must carry a remediation"


def test_render_csv(tmp_path):
    rows = ar.load_demo_rows(TOOLS_DIR / "aikido_sample_data.json")
    out = tmp_path / "report.csv"
    ar.render_csv(rows, out)
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines[0].split(",")[0:2] == ["Type", "Severity"]
    assert len(lines) == 1 + 32


def test_render_html(tmp_path):
    rows = ar.load_demo_rows(TOOLS_DIR / "aikido_sample_data.json")
    out = tmp_path / "report.html"
    ar.render_html(rows, ar.summarize(rows), out, "April 3, 2026", "open")
    text = out.read_text(encoding="utf-8")
    assert "Security Vulnerability Report" in text
    assert "Remediation" in text
    assert "Update to 2.0" in text


def test_render_pdf(tmp_path):
    pytest.importorskip("reportlab")
    rows = ar.load_demo_rows(TOOLS_DIR / "aikido_sample_data.json")
    out = tmp_path / "report.pdf"
    ar.render_pdf(rows, ar.summarize(rows), out, "April 3, 2026", "open")
    blob = out.read_bytes()
    assert blob.startswith(b"%PDF")
    assert len(blob) > 5000


def test_cli_demo_csv(tmp_path):
    out = tmp_path / "demo.csv"
    assert ar.main(["--demo", "-f", "csv", "-o", str(out)]) == 0
    assert out.exists()


def test_fixture_is_valid_json():
    data = json.loads((TOOLS_DIR / "aikido_sample_data.json").read_text(encoding="utf-8"))
    assert len(data["issue_groups"]) == 32
