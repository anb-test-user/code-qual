"""Command-line interface: ``codequal repo | pr | file | render | serve | version``."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from ._version import __version__
from .config import Config, load_config
from .engine import Engine, EngineConfig
from .models import ScanResult, Severity
from .report import FORMATS, render
from .scanners import scan_file, scan_pr, scan_repo

_FAIL_CHOICES = ["critical", "high", "medium", "low", "info", "none"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codequal",
        description="AI-native code quality scanner (repo, PR, and IDE surfaces).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  codequal repo .                      scan the whole repository\n"
            "  codequal repo src -f sarif -o out.sarif\n"
            "  codequal pr --base origin/main       scan only PR-changed lines\n"
            "  codequal file app.py                 scan a single file\n"
            "  codequal pr --base origin/main -f json -o r.json && \\\n"
            "    codequal render r.json -f sarif -o r.sarif --fail-on high\n"
            "  codequal serve                       run the IDE backend server\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"codequal {__version__}")
    sub = parser.add_subparsers(dest="command")

    engine_opts = argparse.ArgumentParser(add_help=False)
    eng = engine_opts.add_argument_group("engine")
    eng.add_argument("--model", default=None, help="Claude model id (default: claude-sonnet-4-6)")
    eng.add_argument("--no-ai", action="store_true", help="force offline heuristic mode")
    eng.add_argument("--require-ai", action="store_true", help="fail if the AI engine is unavailable")
    eng.add_argument("--max-workers", type=int, default=None, help="concurrent analysis workers")
    eng.add_argument("--max-tokens", type=int, default=None, help="max output tokens per call")
    eng.add_argument("--min-confidence", type=float, default=None, help="drop findings below this confidence")

    output_opts = argparse.ArgumentParser(add_help=False)
    out = output_opts.add_argument_group("output")
    out.add_argument("-f", "--format", choices=FORMATS, default="terminal")
    out.add_argument("-o", "--output", default=None, help="write the report to a file instead of stdout")
    out.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    out.add_argument("--fail-on", choices=_FAIL_CHOICES, default=None,
                     help="exit non-zero if any finding is at/above this severity (default: high)")
    out.add_argument("-q", "--quiet", action="store_true", help="suppress the stderr status line")

    p_repo = sub.add_parser("repo", parents=[engine_opts, output_opts], help="scan an entire repository/directory")
    p_repo.add_argument("path", nargs="?", default=".")
    p_repo.add_argument("--include", action="append", default=None, metavar="GLOB")
    p_repo.add_argument("--exclude", action="append", default=None, metavar="GLOB")
    p_repo.add_argument("--max-bytes", type=int, default=None, help="skip files larger than this")
    p_repo.add_argument("--max-files", type=int, default=None, help="cap number of files scanned")

    p_pr = sub.add_parser("pr", parents=[engine_opts, output_opts], help="scan only lines changed in a PR/diff")
    p_pr.add_argument("path", nargs="?", default=".", help="repository root")
    p_pr.add_argument("--base", default="origin/main", help="base ref to diff against")
    p_pr.add_argument("--head", default="", help="head ref (default: working tree)")
    p_pr.add_argument("--include", action="append", default=None, metavar="GLOB")
    p_pr.add_argument("--exclude", action="append", default=None, metavar="GLOB")

    p_file = sub.add_parser("file", parents=[engine_opts, output_opts], help="scan a single file")
    p_file.add_argument("path", nargs="?", default=None)
    p_file.add_argument("--stdin", action="store_true", help="read content from stdin")
    p_file.add_argument("--name", default="stdin", help="display name for --stdin content")

    p_render = sub.add_parser("render", parents=[output_opts], help="re-render a JSON report to another format")
    p_render.add_argument("path", nargs="?", default=None, help="JSON report file (default: stdin)")

    p_serve = sub.add_parser("serve", parents=[engine_opts], help="run the local HTTP server for the IDE plugin")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8787)

    sub.add_parser("version", help="print version")
    return parser


def _engine_config(args: argparse.Namespace, cfg: Config) -> EngineConfig:
    return EngineConfig(
        model=args.model or cfg.model,
        max_workers=args.max_workers if args.max_workers is not None else cfg.max_workers,
        max_tokens=args.max_tokens if args.max_tokens is not None else cfg.max_tokens,
        min_confidence=args.min_confidence if args.min_confidence is not None else cfg.min_confidence,
        no_ai=args.no_ai or cfg.no_ai,
        require_ai=args.require_ai or cfg.require_ai,
    )


def _resolve_fail_on(args: argparse.Namespace, cfg: Config) -> Optional[Severity]:
    if args.fail_on is None:
        return cfg.fail_on
    if args.fail_on == "none":
        return None
    return Severity.coerce(args.fail_on)


def _use_color(choice: str, to_file: bool, fmt: str) -> bool:
    if fmt != "terminal" or to_file:
        return False
    if choice == "always":
        return True
    if choice == "never":
        return False
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _emit(result: ScanResult, args: argparse.Namespace) -> None:
    to_file = bool(args.output)
    text = render(result, args.format, color=_use_color(args.color, to_file, args.format))
    if to_file:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        if not args.quiet:
            print(f"wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        print(text)
    if not args.quiet and (to_file or args.format != "terminal"):
        print(
            f"codequal: {result.mode} mode · {result.total} finding(s) · "
            f"{result.files_scanned} file(s) · {result.duration_s:.2f}s",
            file=sys.stderr,
        )


def _make_engine(args: argparse.Namespace, cfg: Config) -> Optional[Engine]:
    try:
        return Engine(_engine_config(args, cfg))
    except RuntimeError as exc:
        print(f"codequal: {exc}", file=sys.stderr)
        return None


def _gate(result: ScanResult, fail_on: Optional[Severity]) -> int:
    if fail_on is not None and result.count_at_or_above(fail_on) > 0:
        return 1
    return 0


def _do_render(args: argparse.Namespace) -> int:
    if args.path:
        try:
            raw = Path(args.path).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"codequal: {exc}", file=sys.stderr)
            return 2
    else:
        raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except ValueError as exc:
        print(f"codequal: invalid JSON report: {exc}", file=sys.stderr)
        return 2
    result = ScanResult.from_dict(data)
    _emit(result, args)
    if args.fail_on in (None, "none"):  # render only gates when explicitly asked
        return 0
    return _gate(result, Severity.coerce(args.fail_on))


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    command = args.command

    if command is None:
        build_parser().print_help()
        return 0
    if command == "version":
        print(f"codequal {__version__}")
        return 0
    if command == "render":
        return _do_render(args)

    if command == "serve":
        from .server import serve
        engine = _make_engine(args, load_config("."))
        if engine is None:
            return 2
        serve(host=args.host, port=args.port, engine=engine)
        return 0

    # Scanning commands share engine setup and reporting.
    root = args.path if (command in ("repo", "pr") and args.path) else "."
    cfg = load_config(root)
    engine = _make_engine(args, cfg)
    if engine is None:
        return 2

    if command == "repo":
        result = scan_repo(
            args.path,
            engine=engine,
            include=args.include if args.include is not None else (cfg.include or None),
            exclude=args.exclude if args.exclude is not None else (cfg.exclude or None),
            max_bytes=args.max_bytes if args.max_bytes is not None else cfg.max_bytes,
            max_files=args.max_files,
        )
    elif command == "pr":
        result = scan_pr(
            args.path,
            base=args.base,
            head=args.head,
            engine=engine,
            max_bytes=cfg.max_bytes,
            include=args.include if args.include is not None else (cfg.include or None),
            exclude=args.exclude if args.exclude is not None else (cfg.exclude or None),
        )
    elif command == "file":
        if args.stdin or args.path is None:
            from .scanners import scan_content
            result = scan_content(args.name, sys.stdin.read(), engine=engine)
        else:
            result = scan_file(args.path, engine=engine)
    else:  # pragma: no cover - argparse guards this
        print(f"codequal: unknown command {command}", file=sys.stderr)
        return 2

    _emit(result, args)
    return _gate(result, _resolve_fail_on(args, cfg))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
