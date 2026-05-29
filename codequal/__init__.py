"""CodeQual — an AI-native code quality scanner.

Scans source for security, bug, performance, and maintainability issues using
Claude when an ``ANTHROPIC_API_KEY`` is present, and fast offline heuristics
otherwise. One engine powers three surfaces: repo scanning, PR scanning, and an
IDE plugin.
"""
from __future__ import annotations

from ._version import __version__
from .config import Config, load_config
from .engine import Engine, EngineConfig
from .models import AnalysisUnit, Finding, ScanResult, Severity
from .scanners import scan_content, scan_file, scan_pr, scan_repo

__all__ = [
    "__version__",
    "Config",
    "load_config",
    "Engine",
    "EngineConfig",
    "AnalysisUnit",
    "Finding",
    "ScanResult",
    "Severity",
    "scan_content",
    "scan_file",
    "scan_pr",
    "scan_repo",
]
