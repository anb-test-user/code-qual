"""Render a :class:`ScanResult` as terminal text, JSON, Markdown, or SARIF."""
from __future__ import annotations

import json
from collections import OrderedDict
from typing import Dict, List

from ._version import __version__
from .models import SEVERITY_ORDER, Finding, ScanResult, Severity

FORMATS = ("terminal", "json", "markdown", "sarif")

_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "bright_red": "\033[91m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "cyan": "\033[36m",
    "green": "\033[32m",
    "magenta": "\033[35m",
}

_SEV_TERMINAL = {
    Severity.CRITICAL: ("✖", "bright_red", "bold"),
    Severity.HIGH: ("✖", "red", ""),
    Severity.MEDIUM: ("⚠", "yellow", ""),
    Severity.LOW: ("•", "blue", ""),
    Severity.INFO: ("·", "cyan", ""),
}

_SEV_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def render(result: ScanResult, fmt: str = "terminal", *, color: bool = False) -> str:
    fmt = (fmt or "terminal").lower()
    if fmt == "json":
        return to_json(result)
    if fmt == "markdown":
        return to_markdown(result)
    if fmt == "sarif":
        return to_sarif(result)
    return to_terminal(result, color=color)


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #
def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


# --------------------------------------------------------------------------- #
# Terminal
# --------------------------------------------------------------------------- #
def to_terminal(result: ScanResult, *, color: bool = False) -> str:
    def c(text: str, *styles: str) -> str:
        if not color or not styles:
            return text
        prefix = "".join(_ANSI[s] for s in styles if s in _ANSI)
        return f"{prefix}{text}{_ANSI['reset']}" if prefix else text

    lines: List[str] = []
    header = (
        f"{c('CodeQual', 'bold', 'magenta')}  ·  {result.mode} mode  ·  "
        f"{result.model or 'heuristics'}  ·  {result.files_scanned} file(s)  ·  "
        f"{result.duration_s:.2f}s"
    )
    lines.append(header)

    if not result.findings:
        lines.append(c("✓ No issues found.", "green", "bold"))
    else:
        by_file: "OrderedDict[str, List[Finding]]" = OrderedDict()
        for finding in result.sorted_findings():
            by_file.setdefault(finding.file, []).append(finding)

        for file, findings in by_file.items():
            lines.append("")
            lines.append(c(file, "bold"))
            for f in findings:
                glyph, sev_color, sev_extra = _SEV_TERMINAL[f.severity]
                styles = tuple(s for s in (sev_color, sev_extra) if s)
                badge = c(f"{glyph} {f.severity.value:<8}", *styles)
                meta = c(f"{f.category:<15}", "dim")
                loc = c(f"L{f.line}", "dim")
                lines.append(f"  {badge} {meta} {loc}  {f.title}")
                if f.description:
                    lines.append(c(f"      {f.description}", "dim"))
                if f.suggestion:
                    lines.append(f"      {c('↳', 'green')} {f.suggestion}")

    lines.append("")
    lines.append(_summary_line(result, color, c))
    if result.errors:
        lines.append(c(f"⚠ {len(result.errors)} scan error(s):", "yellow"))
        for err in result.errors[:10]:
            lines.append(c(f"    {err}", "dim"))
    return "\n".join(lines)


def _summary_line(result: ScanResult, color: bool, c) -> str:
    counts = result.counts
    parts = []
    for sev in SEVERITY_ORDER:
        n = counts[sev.value]
        if n:
            glyph, sev_color, _ = _SEV_TERMINAL[sev]
            parts.append(c(f"{n} {sev.value}", sev_color) if color else f"{n} {sev.value}")
    body = "  ".join(parts) if parts else "0 findings"
    return f"Summary: {body}  ({result.total} total)"


# --------------------------------------------------------------------------- #
# Markdown (PR comment friendly)
# --------------------------------------------------------------------------- #
def to_markdown(result: ScanResult) -> str:
    lines: List[str] = ["## 🤖 CodeQual report", ""]
    lines.append(
        f"**Mode:** {result.mode} · **Model:** `{result.model or 'heuristics'}` · "
        f"**Files scanned:** {result.files_scanned} · **Findings:** {result.total}"
    )
    lines.append("")

    if not result.findings:
        lines.append("✅ No issues found in the analyzed code.")
        return "\n".join(lines)

    counts = result.counts
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in SEVERITY_ORDER:
        if counts[sev.value]:
            lines.append(f"| {_SEV_EMOJI[sev]} {sev.value} | {counts[sev.value]} |")
    lines.append("")

    current_file = None
    for f in result.sorted_findings():
        if f.file != current_file:
            current_file = f.file
            lines.append(f"### `{f.file}`")
        span = f"L{f.line}" if f.end_line == f.line else f"L{f.line}-{f.end_line}"
        lines.append(
            f"- {_SEV_EMOJI[f.severity]} **{f.severity.value} · {f.category}** — "
            f"{_md_escape(f.title)} _({span})_"
        )
        if f.description:
            lines.append(f"  {_md_escape(f.description)}")
        if f.suggestion:
            lines.append(f"  💡 {_md_escape(f.suggestion)}")
    return "\n".join(lines)


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").strip()


# --------------------------------------------------------------------------- #
# SARIF 2.1.0 (GitHub code scanning / IDE ingestion)
# --------------------------------------------------------------------------- #
def _sarif_level(severity: Severity) -> str:
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _sarif_uri(path: str) -> str:
    norm = path.replace("\\", "/")
    return norm[2:] if norm.startswith("./") else norm


def to_sarif(result: ScanResult) -> str:
    rules: "OrderedDict[str, dict]" = OrderedDict()
    sarif_results: List[dict] = []

    for f in result.sorted_findings():
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": "".join(w.capitalize() for w in f.category.split("-")) or "General",
                "shortDescription": {"text": f.title[:120]},
                "fullDescription": {"text": (f.description or f.title)[:1000]},
                "defaultConfiguration": {"level": _sarif_level(f.severity)},
                "properties": {"category": f.category, "tags": [f.category]},
            }
        message = f.description or f.title
        if f.suggestion:
            message = f"{message}\n\nSuggestion: {f.suggestion}"
        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "level": _sarif_level(f.severity),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _sarif_uri(f.file)},
                            "region": {"startLine": f.line, "endLine": f.end_line},
                        }
                    }
                ],
                "properties": {
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                    "source": f.source,
                },
            }
        )

    doc: Dict = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQual",
                        "informationUri": "https://github.com/anb-test-user/code-qual",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
