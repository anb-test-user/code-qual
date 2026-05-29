"""Language detection and source-file discovery (gitignore-aware)."""
from __future__ import annotations

import fnmatch
import os
import subprocess
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

EXTENSION_LANGUAGE = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".swift": "swift",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
    ".sql": "sql",
    ".tf": "terraform",
    ".yaml": "yaml",
    ".yml": "yaml",
}

# Directories never worth scanning. Used only for the non-git fallback walk;
# inside a git repo we defer to `git ls-files` which already respects .gitignore.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".tox", "venv", ".venv", "env",
    "dist", "build", "out", "target", ".next", ".nuxt", "coverage",
    ".idea", ".vscode", "vendor", "site-packages", ".gradle", "bin", "obj",
}

DEFAULT_MAX_BYTES = 200_000


def language_for(path: os.PathLike | str) -> Optional[str]:
    return EXTENSION_LANGUAGE.get(Path(path).suffix.lower())


def is_supported(path: os.PathLike | str) -> bool:
    return language_for(path) is not None


def _matches_any(rel_path: str, patterns: Iterable[str]) -> bool:
    norm = rel_path.replace(os.sep, "/")
    base = os.path.basename(norm)
    return any(fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(base, pat) for pat in patterns)


def _git_tracked_files(root: Path) -> Optional[List[Path]]:
    """Tracked + untracked-but-not-ignored files, or None if not a git repo."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    files: List[Path] = []
    seen = set()
    for line in proc.stdout.splitlines():
        rel = line.strip()
        if not rel or rel in seen:
            continue
        seen.add(rel)
        files.append(root / rel)
    return files


def _walk_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            yield Path(dirpath) / filename


def iter_source_files(
    root: os.PathLike | str,
    *,
    include: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> Iterator[Path]:
    """Yield supported source files under ``root``, honoring .gitignore when possible."""
    root_path = Path(root)
    candidates = _git_tracked_files(root_path)
    if candidates is None:
        candidates = _walk_files(root_path)

    for path in candidates:
        if not path.is_file() or not is_supported(path):
            continue
        try:
            rel = str(path.relative_to(root_path))
        except ValueError:
            rel = str(path)
        if include and not _matches_any(rel, include):
            continue
        if exclude and _matches_any(rel, exclude):
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
        except OSError:
            continue
        yield path
