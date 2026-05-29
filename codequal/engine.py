"""The AI analysis engine.

Sends each :class:`AnalysisUnit` to Claude with a cached system prompt and a
forced structured-output tool call, parsing results into :class:`Finding`s.
Falls back to offline heuristics when the SDK/API key are unavailable or when an
individual call fails, so a scan always produces signal.
"""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional, Tuple

from . import heuristics
from .config import DEFAULT_MODEL
from .models import AnalysisUnit, Finding, Severity
from .prompts import REPORT_TOOL, SYSTEM_PROMPT, format_unit_prompt


@dataclass
class EngineConfig:
    model: str = DEFAULT_MODEL
    max_workers: int = 8
    max_tokens: int = 4096
    temperature: float = 0.0
    min_confidence: float = 0.0
    no_ai: bool = False
    require_ai: bool = False


class Engine:
    """Analyzes units, using Claude when available and heuristics otherwise."""

    def __init__(self, config: Optional[EngineConfig] = None) -> None:
        self.config = config or EngineConfig()
        self._client = None
        self.unavailable_reason: Optional[str] = None
        if not self.config.no_ai:
            self._client = self._make_client()
        else:
            self.unavailable_reason = "--no-ai set"
        if self.config.require_ai and self._client is None:
            raise RuntimeError(
                "AI mode required but unavailable: "
                + (self.unavailable_reason or "set ANTHROPIC_API_KEY and install 'anthropic'")
            )

    @property
    def mode(self) -> str:
        return "ai" if self._client is not None else "heuristic"

    def _make_client(self):
        if not os.environ.get("ANTHROPIC_API_KEY"):
            self.unavailable_reason = "ANTHROPIC_API_KEY not set"
            return None
        try:
            import anthropic  # noqa: WPS433 (intentional lazy import)
        except ImportError as exc:
            self.unavailable_reason = f"anthropic SDK not installed ({exc})"
            return None
        try:
            return anthropic.Anthropic(max_retries=3)
        except Exception as exc:  # pragma: no cover - defensive
            self.unavailable_reason = f"could not initialize Anthropic client: {exc}"
            return None

    def analyze(self, units: List[AnalysisUnit]) -> Tuple[List[Finding], List[str]]:
        """Return (findings, errors) for the given units."""
        findings: List[Finding] = []
        errors: List[str] = []
        if not units:
            return findings, errors

        if self._client is None:
            for unit in units:
                findings.extend(heuristics.scan_unit(unit, self.config.min_confidence))
            return findings, errors

        workers = max(1, min(self.config.max_workers, len(units)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_unit = {pool.submit(self._analyze_one, unit): unit for unit in units}
            for future in as_completed(future_to_unit):
                unit = future_to_unit[future]
                try:
                    findings.extend(future.result())
                except Exception as exc:  # network/API/parse failure for one unit
                    errors.append(f"{unit.path}: {type(exc).__name__}: {exc}")
                    # Degrade gracefully so the file still yields some signal.
                    findings.extend(heuristics.scan_unit(unit, self.config.min_confidence))
        return findings, errors

    def _analyze_one(self, unit: AnalysisUnit) -> List[Finding]:
        response = self._client.messages.create(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            system=[{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
            tools=[REPORT_TOOL],
            tool_choice={"type": "tool", "name": REPORT_TOOL["name"]},
            messages=[{"role": "user", "content": format_unit_prompt(unit)}],
        )
        return self._parse(unit, response)

    def _parse(self, unit: AnalysisUnit, response) -> List[Finding]:
        raw_findings: List[dict] = []
        for block in getattr(response, "content", []) or []:
            if getattr(block, "type", None) == "tool_use" and getattr(block, "name", "") == REPORT_TOOL["name"]:
                payload = getattr(block, "input", {}) or {}
                if isinstance(payload, dict):
                    raw_findings = payload.get("findings", []) or []
                break

        max_line = unit.line_count
        results: List[Finding] = []
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            finding = self._to_finding(unit, item, max_line)
            if finding is None:
                continue
            if finding.confidence < self.config.min_confidence:
                continue
            if unit.focus_lines is not None and finding.line not in unit.focus_lines:
                continue
            results.append(finding)
        return results

    def _to_finding(self, unit: AnalysisUnit, item: dict, max_line: int) -> Optional[Finding]:
        title = item.get("title")
        if not title:
            return None
        try:
            line = int(item.get("line", 1))
        except (TypeError, ValueError):
            line = 1
        line = max(1, min(line, max_line))
        end_line = item.get("end_line")
        try:
            end_line = int(end_line) if end_line is not None else None
            if end_line is not None:
                end_line = max(line, min(end_line, max_line))
        except (TypeError, ValueError):
            end_line = None
        return Finding(
            file=unit.path,
            line=line,
            end_line=end_line,
            severity=Severity.coerce(item.get("severity"), Severity.MEDIUM),
            category=item.get("category", "maintainability"),
            title=str(title),
            description=str(item.get("description", "")),
            suggestion=str(item.get("suggestion", "")),
            confidence=item.get("confidence", 0.85),
            source="ai",
        )
