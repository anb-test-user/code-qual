"""Single-file and raw-content scanning."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional, Set

from ..engine import Engine
from ..languages import language_for
from ..models import AnalysisUnit, ScanResult


def scan_content(
    path: str,
    content: str,
    *,
    engine: Optional[Engine] = None,
    language: Optional[str] = None,
    focus_lines: Optional[Set[int]] = None,
    kind: str = "file",
) -> ScanResult:
    """Scan an in-memory buffer (used by the IDE plugin and the local server)."""
    engine = engine or Engine()
    language = language or language_for(path) or "text"
    unit = AnalysisUnit(path=path, language=language, content=content, kind=kind, focus_lines=focus_lines)

    started = time.time()
    findings, errors = engine.analyze([unit])
    result = ScanResult(
        findings=findings,
        files_scanned=1,
        paths=[path],
        model=engine.config.model,
        mode=engine.mode,
        duration_s=time.time() - started,
        errors=errors,
        target=path,
    )
    return result


def scan_file(
    path: str | Path,
    *,
    engine: Optional[Engine] = None,
    display_path: Optional[str] = None,
) -> ScanResult:
    """Read ``path`` from disk and scan it."""
    file_path = Path(path)
    shown = display_path or str(path)
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return ScanResult(
            files_scanned=0,
            paths=[shown],
            errors=[f"{shown}: {exc}"],
            target=shown,
            model=(engine.config.model if engine else ""),
            mode=(engine.mode if engine else "heuristic"),
        )
    return scan_content(shown, content, engine=engine, language=language_for(file_path))
