"""Fast, dependency-free offline rules.

Used when the Anthropic SDK / API key are unavailable, when ``--no-ai`` is set,
or as a per-unit fallback if an AI call fails. Intentionally conservative to
keep false positives low; the AI engine provides the deep analysis.
"""
from __future__ import annotations

import ast
import re
from typing import List, Optional

from .models import AnalysisUnit, Finding, Severity

LONG_FUNCTION_LINES = 70
MAX_FINDINGS_PER_UNIT = 80

_PLACEHOLDER = re.compile(
    r"(?i)(example|your[_-]?|changeme|placeholder|xxxx|<.*>|\{\{?.*\}?\}|\$\{|os\.environ|getenv|process\.env)"
)

# (compiled regex, severity, category, title, description, suggestion, confidence, languages-or-None)
_LineRule = tuple


def _line_rules() -> List[_LineRule]:
    return [
        (
            re.compile(r"AKIA[0-9A-Z]{16}"),
            Severity.CRITICAL, "security", "Hardcoded AWS access key id",
            "An AWS access key id appears to be committed in source.",
            "Remove the credential, rotate it immediately, and load it from a secret manager or environment variable.",
            0.97, None,
        ),
        (
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
            Severity.CRITICAL, "security", "Private key committed to source",
            "A private key block is embedded in the file.",
            "Remove the key from the repository, rotate it, and store secrets outside version control.",
            0.97, None,
        ),
        (
            re.compile(
                r"""(?ix)\b([a-z0-9_]*(?:password|passwd|secret|api[_-]?key|apikey|
                access[_-]?token|auth[_-]?token|client[_-]?secret)[a-z0-9_]*)
                \s*[:=]\s*["']([^"']{6,})["']"""
            ),
            Severity.HIGH, "security", "Possible hardcoded secret",
            "A credential-like value appears to be hardcoded as a string literal.",
            "Move the value to an environment variable or secret manager and reference it at runtime.",
            0.8, None,
        ),
        (
            re.compile(r"\b(?:eval|exec)\s*\("),
            Severity.HIGH, "security", "Dynamic code execution (eval/exec)",
            "eval/exec executes arbitrary code and is a common injection sink.",
            "Replace with explicit parsing/dispatch (e.g. a lookup table, json.loads, ast.literal_eval).",
            0.7, {"python", "javascript", "typescript"},
        ),
        (
            re.compile(r"hashlib\.(?:md5|sha1)\s*\(|createHash\(\s*['\"](?:md5|sha1)['\"]"),
            Severity.MEDIUM, "security", "Weak hash algorithm (MD5/SHA-1)",
            "MD5 and SHA-1 are cryptographically broken and unsuitable for security use.",
            "Use SHA-256 or stronger; for passwords use bcrypt/scrypt/argon2.",
            0.75, None,
        ),
        (
            re.compile(r"\.innerHTML\s*="),
            Severity.MEDIUM, "security", "Assignment to innerHTML (XSS risk)",
            "Writing untrusted data to innerHTML can introduce cross-site scripting.",
            "Use textContent, or sanitize/escape the value before insertion.",
            0.6, {"javascript", "typescript"},
        ),
        (
            re.compile(r"document\.write\s*\("),
            Severity.MEDIUM, "security", "Use of document.write",
            "document.write can enable XSS and blocks parsing.",
            "Build DOM nodes explicitly or set textContent instead.",
            0.6, {"javascript", "typescript"},
        ),
        (
            re.compile(r"(?:^|[^.\w])console\.(?:log|debug|info)\s*\("),
            Severity.INFO, "style", "Leftover console logging",
            "Console logging is often debug residue and noisy in production.",
            "Remove the statement or route it through a configurable logger.",
            0.5, {"javascript", "typescript"},
        ),
        (
            re.compile(r"(?:^|\s)var\s+[A-Za-z_$]"),
            Severity.LOW, "maintainability", "Use of 'var'",
            "'var' is function-scoped and error-prone.",
            "Prefer 'const' (or 'let' when reassignment is required).",
            0.5, {"javascript", "typescript"},
        ),
        (
            re.compile(r"(?i)\b(TODO|FIXME|HACK|XXX)\b"),
            Severity.INFO, "maintainability", "Unresolved TODO/FIXME marker",
            "An unresolved task marker remains in the code.",
            "Resolve the item or track it in an issue and remove the marker.",
            0.45, None,
        ),
    ]


_LINE_RULES = _line_rules()


def scan_unit(unit: AnalysisUnit, min_confidence: float = 0.0) -> List[Finding]:
    findings: List[Finding] = []
    lines = unit.content.splitlines()

    for lineno, text in enumerate(lines, start=1):
        if _is_comment_or_blank(text, unit.language):
            # Still allow secret/TODO scanning inside comments; skip code-only rules.
            pass
        for regex, severity, category, title, desc, suggestion, conf, langs in _LINE_RULES:
            if langs is not None and unit.language not in langs:
                continue
            match = regex.search(text)
            if not match:
                continue
            if title == "Possible hardcoded secret" and _looks_like_placeholder(match):
                continue
            findings.append(
                Finding(
                    file=unit.path,
                    line=lineno,
                    severity=severity,
                    category=category,
                    title=title,
                    description=desc,
                    suggestion=suggestion,
                    confidence=conf,
                    source="heuristic",
                    code=text.strip()[:200],
                )
            )

    if unit.language == "python":
        findings.extend(_python_ast_rules(unit, lines))

    findings = _finalize(findings, unit, min_confidence)
    return findings


def _looks_like_placeholder(match: re.Match) -> bool:
    value = match.group(match.lastindex) if match.lastindex else match.group(0)
    return bool(_PLACEHOLDER.search(value)) or set(value) <= {"*", "x", "X", "."}


def _is_comment_or_blank(text: str, language: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return True
    if language == "python":
        return stripped.startswith("#")
    return stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*")


def _python_ast_rules(unit: AnalysisUnit, lines: List[str]) -> List[Finding]:
    out: List[Finding] = []
    try:
        tree = ast.parse(unit.content)
    except SyntaxError:
        return out

    def add(line: int, sev: Severity, cat: str, title: str, desc: str, fix: str, conf: float,
            end: Optional[int] = None) -> None:
        snippet = lines[line - 1].strip()[:200] if 1 <= line <= len(lines) else ""
        out.append(
            Finding(
                file=unit.path, line=line, end_line=end, severity=sev, category=cat,
                title=title, description=desc, suggestion=fix, confidence=conf,
                source="heuristic", code=snippet,
            )
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                add(node.lineno, Severity.MEDIUM, "bug", "Bare 'except:' clause",
                    "A bare except catches everything, including KeyboardInterrupt/SystemExit, and hides bugs.",
                    "Catch a specific exception type, e.g. 'except ValueError:'.", 0.8)
            if node.body and all(isinstance(b, ast.Pass) for b in node.body):
                add(node.lineno, Severity.MEDIUM, "bug", "Exception silently swallowed",
                    "The except body is just 'pass', discarding the error and any context.",
                    "Log the exception or handle it; re-raise if it cannot be handled here.", 0.75)

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defaults = list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]
            for default in defaults:
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    add(default.lineno, Severity.MEDIUM, "bug", "Mutable default argument",
                        "A mutable default is shared across all calls and accumulates state between them.",
                        "Default to None and create the container inside the function body.", 0.85)
            end = getattr(node, "end_lineno", None)
            if end and (end - node.lineno) > LONG_FUNCTION_LINES:
                add(node.lineno, Severity.LOW, "complexity",
                    f"Long function '{node.name}' ({end - node.lineno} lines)",
                    "Very long functions are hard to test and reason about.",
                    "Extract cohesive blocks into smaller, named helper functions.", 0.6, end=end)

        elif isinstance(node, ast.Compare):
            for op, comparator in zip(node.ops, node.comparators):
                if isinstance(op, (ast.Eq, ast.NotEq)) and _is_none(comparator):
                    add(node.lineno, Severity.LOW, "style", "Comparison to None with == / !=",
                        "Identity comparison is the correct and faster way to test for None.",
                        "Use 'is None' / 'is not None'.", 0.7)
                    break

    return out


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _finalize(findings: List[Finding], unit: AnalysisUnit, min_confidence: float) -> List[Finding]:
    if unit.focus_lines is not None:
        findings = [f for f in findings if f.line in unit.focus_lines]
    if min_confidence > 0:
        findings = [f for f in findings if f.confidence >= min_confidence]
    findings.sort(key=lambda f: (-f.severity.rank, f.line))
    return findings[:MAX_FINDINGS_PER_UNIT]
