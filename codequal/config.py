"""Configuration loading from ``.codequal.toml`` and environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - older interpreters
    tomllib = None  # type: ignore

from .languages import DEFAULT_MAX_BYTES
from .models import Severity

DEFAULT_MODEL = "claude-sonnet-4-6"
CONFIG_FILENAME = ".codequal.toml"


@dataclass
class Config:
    """Resolved settings, merged from defaults < file < environment < CLI flags."""

    model: str = DEFAULT_MODEL
    max_workers: int = 8
    max_tokens: int = 4096
    fail_on: Severity = Severity.HIGH
    min_confidence: float = 0.0
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    max_bytes: int = DEFAULT_MAX_BYTES
    no_ai: bool = False
    require_ai: bool = False


def _find_config_file(root: os.PathLike | str) -> Optional[Path]:
    start = Path(root).resolve()
    for directory in [start, *start.parents]:
        candidate = directory / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
    return None


def load_config(root: os.PathLike | str = ".") -> Config:
    """Build a Config from the nearest ``.codequal.toml`` plus env overrides."""
    cfg = Config()

    config_file = _find_config_file(root)
    if config_file is not None and tomllib is not None:
        try:
            data = tomllib.loads(config_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        section = data.get("codequal", data) if isinstance(data, dict) else {}
        _apply_mapping(cfg, section)

    # Environment overrides.
    env_model = os.environ.get("CODEQUAL_MODEL")
    if env_model:
        cfg.model = env_model
    env_fail_on = os.environ.get("CODEQUAL_FAIL_ON")
    if env_fail_on:
        cfg.fail_on = Severity.coerce(env_fail_on, Severity.HIGH)
    if os.environ.get("CODEQUAL_NO_AI", "").lower() in {"1", "true", "yes"}:
        cfg.no_ai = True

    return cfg


def _apply_mapping(cfg: Config, data: dict) -> None:
    if not isinstance(data, dict):
        return
    if isinstance(data.get("model"), str):
        cfg.model = data["model"]
    if isinstance(data.get("max_workers"), int):
        cfg.max_workers = max(1, data["max_workers"])
    if isinstance(data.get("max_tokens"), int):
        cfg.max_tokens = max(1024, data["max_tokens"])
    if data.get("fail_on") is not None:
        cfg.fail_on = Severity.coerce(data["fail_on"], Severity.HIGH)
    if isinstance(data.get("min_confidence"), (int, float)):
        cfg.min_confidence = float(data["min_confidence"])
    if isinstance(data.get("include"), list):
        cfg.include = [str(x) for x in data["include"]]
    if isinstance(data.get("exclude"), list):
        cfg.exclude = [str(x) for x in data["exclude"]]
    if isinstance(data.get("max_bytes"), int):
        cfg.max_bytes = max(1, data["max_bytes"])
    if isinstance(data.get("no_ai"), bool):
        cfg.no_ai = data["no_ai"]
