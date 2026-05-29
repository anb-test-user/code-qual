"""Pull-request / diff-scoped scanning.

Computes the changed regions between a base ref and the working tree (or a head
ref), then scans the *current* content of each changed file while restricting
findings to lines the PR actually touched.
"""
from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

from ..engine import Engine
from ..languages import is_supported, language_for, matches_any
from ..models import AnalysisUnit, ScanResult

_HUNK_RE = re.compile(r"^@@ .*\+(\d+)(?:,(\d+))? @@")


def parse_unified_diff(diff_text: str) -> Dict[str, Set[int]]:
    """Map each changed file to the set of added/modified new-file line numbers.

    Expects a ``git diff --unified=0`` style patch (no context lines).
    """
    files: Dict[str, Set[int]] = {}
    current: Optional[str] = None
    new_line = 0

    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            if target == "/dev/null":
                current = None
            else:
                current = _strip_diff_prefix(target)
                files.setdefault(current, set())
        elif line.startswith("--- "):
            continue
        elif line.startswith("@@"):
            match = _HUNK_RE.match(line)
            new_line = int(match.group(1)) if match else 0
        elif current is not None and line.startswith("+"):
            files[current].add(new_line)
            new_line += 1
        elif current is not None and line.startswith("-"):
            continue  # deletion: new-file cursor does not advance
        elif current is not None and not line.startswith("\\"):
            new_line += 1  # context line (present only with >0 context)

    return {path: lines for path, lines in files.items() if lines}


def _strip_diff_prefix(path: str) -> str:
    for prefix in ("a/", "b/"):
        if path.startswith(prefix):
            return path[len(prefix):]
    return path


def _git_diff(root: Path, base: str, head: str) -> str:
    rev = f"{base}...{head}" if head else base
    proc = subprocess.run(
        ["git", "-C", str(root), "diff", "--unified=0", "--no-color", "--no-ext-diff", rev],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"git diff failed for '{rev}'")
    return proc.stdout


def scan_pr(
    root: str | Path = ".",
    *,
    base: str = "origin/main",
    head: str = "",
    engine: Optional[Engine] = None,
    max_bytes: int = 200_000,
    include: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
) -> ScanResult:
    """Scan only the regions changed between ``base`` and ``head`` (or working tree)."""
    engine = engine or Engine()
    root_path = Path(root)
    started = time.time()

    try:
        diff_text = _git_diff(root_path, base, head)
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        return ScanResult(
            errors=[f"diff failed: {exc}"],
            target=f"{base}...{head or 'WORKTREE'}",
            model=engine.config.model,
            mode=engine.mode,
            duration_s=time.time() - started,
        )

    changed = parse_unified_diff(diff_text)
    units: List[AnalysisUnit] = []
    paths: List[str] = []
    errors: List[str] = []

    for rel, lines in changed.items():
        if not is_supported(rel):
            continue
        if include and not matches_any(rel, include):
            continue
        if exclude and matches_any(rel, exclude):
            continue
        file_path = root_path / rel
        if not file_path.is_file():
            continue  # deleted/renamed-away; nothing current to scan
        try:
            if file_path.stat().st_size > max_bytes:
                continue
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append(f"{rel}: {exc}")
            continue
        units.append(
            AnalysisUnit(
                path=rel,
                language=language_for(rel) or "text",
                content=content,
                kind="diff",
                focus_lines=lines,
            )
        )
        paths.append(rel)

    findings, scan_errors = engine.analyze(units)
    return ScanResult(
        findings=findings,
        files_scanned=len(units),
        paths=paths,
        model=engine.config.model,
        mode=engine.mode,
        duration_s=time.time() - started,
        errors=errors + scan_errors,
        target=f"{base}...{head or 'WORKTREE'}",
    )
