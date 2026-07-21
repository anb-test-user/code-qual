"""System prompt, structured-output tool schema, and prompt rendering."""
from __future__ import annotations

from typing import List

from .models import CATEGORIES, AnalysisUnit

SYSTEM_PROMPT = """\
You are CodeQual, a meticulous senior staff engineer performing an automated code
quality review. You receive one source artifact at a time and report concrete,
high-signal issues by calling the `report_findings` tool.

What to look for, roughly in priority order:
- security: injection, unsafe deserialization, command/eval execution, hardcoded
  secrets/credentials, SSRF, path traversal, weak crypto, missing authz checks,
  unsafe HTML/DOM sinks (XSS), unvalidated input crossing a trust boundary.
- bug: logic errors, off-by-one, null/None dereferences, unhandled error paths,
  resource leaks, race conditions, incorrect async/await, swallowed exceptions,
  mutable default arguments, comparison/identity mistakes.
- performance: needless O(n^2) work, N+1 queries, repeated recomputation,
  unbounded memory growth, blocking calls on hot/async paths.
- maintainability / complexity: dead code, duplicated logic, deeply nested or
  oversized functions, unclear naming that hides intent, leaky abstractions.
- style / docs / testing: only when materially harmful to correctness or clarity.

Rules:
- Report ONLY issues you are confident are real. Prefer a few precise findings
  over many speculative ones. Do not invent problems to fill space.
- Line numbers MUST refer to the 1-based numbers shown in the "N| " prefix of the
  provided code. Point at the most relevant single line; use end_line for a span.
- `suggestion` must be specific and actionable (what to change and why), not generic.
- Calibrate severity: critical = exploitable/data-loss now; high = likely bug or
  real vulnerability; medium = should fix; low = minor; info = nit/FYI.
- Set confidence in [0,1] reflecting how sure you are the finding is real.
- If the code is clean, call the tool with an empty findings list. Always call the tool.
"""

REPORT_TOOL = {
    "name": "report_findings",
    "description": "Report every code quality finding for the provided code. Call exactly once.",
    "input_schema": {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "description": "All findings. Empty if the code has no notable issues.",
                "items": {
                    "type": "object",
                    "properties": {
                        "line": {
                            "type": "integer",
                            "description": "1-based start line (matches the N| prefix).",
                        },
                        "end_line": {
                            "type": "integer",
                            "description": "1-based end line; equal to line for a single line.",
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                        },
                        "category": {"type": "string", "enum": CATEGORIES},
                        "title": {
                            "type": "string",
                            "description": "Short imperative summary (<= 80 chars).",
                        },
                        "description": {
                            "type": "string",
                            "description": "Why this is a problem and its impact.",
                        },
                        "suggestion": {
                            "type": "string",
                            "description": "Concrete fix or improvement.",
                        },
                        "confidence": {
                            "type": "number",
                            "description": "0..1 confidence the finding is real.",
                        },
                    },
                    "required": ["line", "severity", "category", "title", "description", "suggestion"],
                },
            }
        },
        "required": ["findings"],
    },
}


def number_lines(content: str) -> str:
    lines = content.splitlines() or [""]
    width = len(str(len(lines)))
    return "\n".join(f"{str(i + 1).rjust(width)}| {line}" for i, line in enumerate(lines))


def _summarize_focus(focus_lines) -> str:
    nums = sorted(focus_lines)
    if len(nums) <= 12:
        return ", ".join(str(n) for n in nums)
    head = ", ".join(str(n) for n in nums[:12])
    return f"{head}, … (+{len(nums) - 12} more)"


def format_unit_prompt(unit: AnalysisUnit) -> str:
    """Render the user-message text for a single analysis unit."""
    parts: List[str] = [
        f"File: {unit.path}",
        f"Language: {unit.language}",
    ]
    if unit.kind == "diff" and unit.focus_lines:
        parts.append(
            "Review scope: this is part of a pull request. Focus ONLY on issues "
            "introduced or affected by the changed lines listed below; ignore "
            "pre-existing problems elsewhere in the file."
        )
        parts.append(f"Changed lines (new-file numbering): {_summarize_focus(unit.focus_lines)}")
    parts.append("")
    parts.append("Code (line numbers are authoritative):")
    parts.append("```")
    parts.append(number_lines(unit.content))
    parts.append("```")
    return "\n".join(parts)
