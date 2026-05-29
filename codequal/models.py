"""Core data models for CodeQual findings and scan results."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class Severity(str, Enum):
    """Ordered severity levels. ``str`` mixin keeps JSON serialization trivial."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self.value]

    @classmethod
    def coerce(cls, value: "Severity | str | None", default: "Severity | None" = None) -> "Severity":
        """Best-effort conversion from arbitrary model/CLI input to a Severity."""
        if isinstance(value, Severity):
            return value
        if value is None:
            return default or Severity.MEDIUM
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return default or Severity.MEDIUM


_SEVERITY_RANK = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}

# Highest-impact first; used for display ordering.
SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

# Stable taxonomy the model is asked to use. Unknown values normalize to "maintainability".
CATEGORIES = [
    "security",
    "bug",
    "performance",
    "maintainability",
    "complexity",
    "style",
    "docs",
    "testing",
]


def normalize_category(value: Optional[str]) -> str:
    if not value:
        return "maintainability"
    v = str(value).strip().lower()
    return v if v in CATEGORIES else "maintainability"


@dataclass
class AnalysisUnit:
    """One unit of code handed to the engine (a whole file or a changed region)."""

    path: str
    language: str
    content: str
    kind: str = "file"  # "file" | "diff"
    focus_lines: Optional[Set[int]] = None  # restrict findings to these new-file lines

    @property
    def line_count(self) -> int:
        return self.content.count("\n") + 1


@dataclass
class Finding:
    """A single code quality issue at a specific location."""

    file: str
    line: int
    severity: Severity
    category: str
    title: str
    description: str = ""
    suggestion: str = ""
    end_line: Optional[int] = None
    confidence: float = 0.85
    rule_id: str = ""
    source: str = "ai"  # "ai" | "heuristic"
    code: str = ""

    def __post_init__(self) -> None:
        self.severity = Severity.coerce(self.severity)
        self.category = normalize_category(self.category)
        self.title = (self.title or "Code quality issue").strip()
        try:
            self.line = int(self.line)
        except (TypeError, ValueError):
            self.line = 1
        if self.line < 1:
            self.line = 1
        if self.end_line is None or self.end_line < self.line:
            self.end_line = self.line
        try:
            self.confidence = max(0.0, min(1.0, float(self.confidence)))
        except (TypeError, ValueError):
            self.confidence = 0.5
        if not self.rule_id:
            self.rule_id = self._derive_rule_id()

    def _derive_rule_id(self) -> str:
        digest = hashlib.sha1(f"{self.category}:{self.title}".lower().encode("utf-8")).hexdigest()[:8]
        slug = re.sub(r"[^a-z0-9]+", "-", self.category.lower()).strip("-") or "general"
        return f"codequal/{slug}/{digest}"

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        return cls(
            file=data.get("file", ""),
            line=data.get("line", 1),
            severity=data.get("severity", "medium"),
            category=data.get("category", "maintainability"),
            title=data.get("title", ""),
            description=data.get("description", ""),
            suggestion=data.get("suggestion", ""),
            end_line=data.get("end_line"),
            confidence=data.get("confidence", 0.85),
            rule_id=data.get("rule_id", ""),
            source=data.get("source", "ai"),
            code=data.get("code", ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "severity": self.severity.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "suggestion": self.suggestion,
            "confidence": round(self.confidence, 3),
            "rule_id": self.rule_id,
            "source": self.source,
            "code": self.code,
        }


@dataclass
class ScanResult:
    """Aggregated result of scanning one or more analysis units."""

    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    paths: List[str] = field(default_factory=list)
    model: str = ""
    mode: str = "ai"  # "ai" | "heuristic"
    duration_s: float = 0.0
    errors: List[str] = field(default_factory=list)
    target: str = ""

    def add(self, findings: List[Finding]) -> None:
        self.findings.extend(findings)

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.file, f.line, -f.confidence))

    @property
    def counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def count_at_or_above(self, threshold: Severity) -> int:
        return sum(1 for f in self.findings if f.severity.rank >= threshold.rank)

    @property
    def total(self) -> int:
        return len(self.findings)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResult":
        result = cls(
            files_scanned=int(data.get("files_scanned", 0) or 0),
            paths=list(data.get("paths", []) or []),
            model=data.get("model", "") or "",
            mode=data.get("mode", "ai") or "ai",
            duration_s=float(data.get("duration_s", 0.0) or 0.0),
            errors=list(data.get("errors", []) or []),
            target=data.get("target", "") or "",
        )
        result.findings = [Finding.from_dict(f) for f in data.get("findings", []) if isinstance(f, dict)]
        return result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "model": self.model,
            "mode": self.mode,
            "files_scanned": self.files_scanned,
            "duration_s": round(self.duration_s, 3),
            "total_findings": self.total,
            "counts": self.counts,
            "paths": self.paths,
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
