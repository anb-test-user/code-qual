"""Whole-repository scanning."""
from __future__ import annotations

import time
from pathlib import Path
from typing import List, Optional

from ..engine import Engine
from ..languages import language_for, iter_source_files
from ..models import AnalysisUnit, ScanResult


def scan_repo(
    root: str | Path = ".",
    *,
    engine: Optional[Engine] = None,
    include: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
    max_bytes: int = 200_000,
    max_files: Optional[int] = None,
) -> ScanResult:
    """Discover and scan every supported source file under ``root``."""
    engine = engine or Engine()
    root_path = Path(root)

    units: List[AnalysisUnit] = []
    paths: List[str] = []
    errors: List[str] = []

    for file_path in iter_source_files(root_path, include=include, exclude=exclude, max_bytes=max_bytes):
        if max_files is not None and len(units) >= max_files:
            break
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append(f"{file_path}: {exc}")
            continue
        try:
            rel = str(file_path.relative_to(root_path))
        except ValueError:
            rel = str(file_path)
        units.append(AnalysisUnit(path=rel, language=language_for(file_path) or "text", content=content))
        paths.append(rel)

    started = time.time()
    findings, scan_errors = engine.analyze(units)
    return ScanResult(
        findings=findings,
        files_scanned=len(units),
        paths=paths,
        model=engine.config.model,
        mode=engine.mode,
        duration_s=time.time() - started,
        errors=errors + scan_errors,
        target=str(root_path),
    )
