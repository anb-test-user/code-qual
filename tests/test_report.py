"""Report formatter tests: terminal, JSON, Markdown, SARIF."""
import json

from codequal.models import Finding, ScanResult, Severity
from codequal.report import render, to_json, to_markdown, to_sarif, to_terminal


def make_result():
    findings = [
        Finding(file="a.py", line=10, severity=Severity.CRITICAL, category="security",
                title="SQL injection", description="User input concatenated into a query.",
                suggestion="Use parameterized queries."),
        Finding(file="a.py", line=2, severity=Severity.LOW, category="style",
                title="Minor nit", description="", suggestion=""),
    ]
    return ScanResult(findings=findings, files_scanned=1, paths=["a.py"], model="m", mode="ai")


def test_sarif_is_valid_and_maps_levels():
    doc = json.loads(to_sarif(make_result()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "CodeQual"
    assert len(run["results"]) == 2
    assert "error" in [r["level"] for r in run["results"]]  # critical -> error
    region = run["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] >= 1 and region["endLine"] >= region["startLine"]


def test_json_counts():
    doc = json.loads(to_json(make_result()))
    assert doc["total_findings"] == 2
    assert doc["counts"]["critical"] == 1
    assert doc["counts"]["low"] == 1


def test_markdown_contains_titles_and_header():
    md = to_markdown(make_result())
    assert "CodeQual report" in md
    assert "SQL injection" in md
    assert "Use parameterized queries." in md


def test_terminal_orders_by_severity():
    term = to_terminal(make_result(), color=False)
    assert "SQL injection" in term and "Minor nit" in term
    assert term.index("SQL injection") < term.index("Minor nit")


def test_no_findings_messages():
    empty = ScanResult(model="m", mode="ai")
    assert "No issues" in to_markdown(empty)
    assert "No issues" in to_terminal(empty, color=False)


def test_render_dispatch():
    r = make_result()
    assert "2.1.0" in render(r, "sarif")
    assert json.loads(render(r, "json"))["total_findings"] == 2
    assert "CodeQual report" in render(r, "markdown")
