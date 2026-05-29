# CodeQual

**An AI-native code quality scanner.** One engine, three surfaces:

- 🔁 **PR scanning** — review only the lines a pull request changed, gate CI, comment results.
- 📦 **Repo scanning** — sweep an entire codebase for security, bug, performance, and maintainability issues.
- 🧩 **IDE plugin** — inline findings in VS Code as you save.

CodeQual uses **Claude** for deep, context-aware analysis when an API key is
available, and falls back to fast **offline heuristics** otherwise — so it always
produces signal, in CI, on a plane, or in a locked-down container.

```
CodeQual  ·  ai mode  ·  claude-sonnet-4-6  ·  1 file(s)  ·  1.84s

examples/sample_bad.py
  ✖ critical security        L8   Hardcoded AWS access key id
      An AWS access key id appears to be committed in source.
      ↳ Remove the credential, rotate it, and load it from a secret manager.
  ✖ high     security        L28  Dynamic code execution (eval/exec)
      ↳ Replace eval with explicit parsing/dispatch (json.loads, ast.literal_eval).
  ⚠ medium   bug             L12  Mutable default argument
      ↳ Default to None and create the container inside the function body.

Summary: 1 critical  1 high  4 medium  1 low  (7 total)
```

---

## Install

```bash
pip install -e .          # core (offline heuristics work out of the box)
pip install -e ".[ai]"    # + the Anthropic SDK for the Claude-powered engine
export ANTHROPIC_API_KEY=sk-ant-...   # enables AI mode automatically
```

Requires Python 3.9+. With no key (or `--no-ai`) CodeQual runs in heuristic mode.

## Usage

```bash
codequal repo .                       # scan the whole repository
codequal repo src -f sarif -o out.sarif   # SARIF for code scanning / IDEs
codequal pr  --base origin/main       # scan only PR-changed lines
codequal file app.py                  # scan a single file
codequal serve                        # local HTTP backend for the IDE plugin
codequal render report.json -f markdown   # re-render a saved JSON report
```

Every scanning command accepts the same options:

| Flag | Meaning |
| --- | --- |
| `-f, --format` | `terminal` (default), `json`, `markdown`, `sarif` |
| `-o, --output` | write the report to a file instead of stdout |
| `--fail-on` | exit non-zero at/above a severity (`critical…info`, or `none`); default `high` |
| `--model` | Claude model id (default `claude-sonnet-4-6`) |
| `--no-ai` / `--require-ai` | force heuristics / fail if AI is unavailable |
| `--min-confidence` | drop findings below a confidence (0..1) |
| `--max-workers` | concurrent analysis workers |

Exit code is `1` when findings meet the `--fail-on` threshold, so CodeQual drops
straight into any CI gate.

## The three surfaces

### 1. Repo scanning
Walks every supported source file (respecting `.gitignore` via `git ls-files`),
analyzes them concurrently, and reports. Filter with `--include`/`--exclude` globs.

### 2. PR scanning
Computes the diff between a base ref and the working tree (or a head ref), then
scans the **current** content of each changed file while restricting findings to
the lines the PR actually touched — no noise from pre-existing issues.

```bash
codequal pr --base origin/main -f markdown   # ready-to-paste PR comment
```

A ready-to-use GitHub Action lives in [`.github/workflows/codequal.yml`](.github/workflows/codequal.yml):
it scans the PR diff once, uploads SARIF to GitHub code scanning, posts/updates a
summary comment, and fails the check on `high`+ findings. Add `ANTHROPIC_API_KEY`
as a repo secret to enable AI mode (it works in heuristic mode without one).

### 3. IDE plugin (VS Code)
A TypeScript extension in [`ide/vscode/`](ide/vscode) shells out to the `codequal`
CLI and renders findings as inline diagnostics.

```bash
cd ide/vscode && npm install && npm run compile
# then press F5 in VS Code to launch an Extension Development Host
```

Commands: **CodeQual: Scan Current File**, **Scan Workspace**, **Clear Findings**.
Scans on save by default. Settings: `codequal.path`, `codequal.useAI`,
`codequal.model`, `codequal.minConfidence`, `codequal.scanOnSave`. See
[`ide/vscode/README.md`](ide/vscode/README.md).

## Configuration

Drop a `.codequal.toml` at your repo root (see the [template](.codequal.toml)):

```toml
[codequal]
model = "claude-sonnet-4-6"
fail_on = "high"
min_confidence = 0.0
exclude = ["**/vendor/**", "**/*.min.js"]
```

Resolution order: built-in defaults → `.codequal.toml` → environment
(`CODEQUAL_MODEL`, `CODEQUAL_FAIL_ON`, `CODEQUAL_NO_AI`) → CLI flags.

## How it works

```
            ┌──────────────── Engine ────────────────┐
 repo  ─┐   │ Claude (cached system prompt + forced   │
 pr    ─┼─► │ tool-use → structured findings, run     │ ─► ScanResult ─► report
 file  ─┘   │ concurrently) ── falls back to ──────┐  │      (terminal/json/
 IDE   ─────┘                       heuristics ◄───┘  │       markdown/sarif)
            └─────────────────────────────────────────┘
```

- **Structured output:** the model is forced to call a `report_findings` tool, so
  results are typed (`severity`, `category`, `line`, `suggestion`, `confidence`).
- **Prompt caching:** the reviewer system prompt is sent as a cached block, so
  multi-file scans reuse it cheaply.
- **Resilience:** if a single AI call fails, that file degrades to heuristics
  instead of failing the whole scan.

## Development

```bash
make dev     # editable install + test deps
make test    # run the pytest suite (offline, no API key needed)
make demo    # scan the bundled examples/sample_bad.py
make ide     # build the VS Code extension
```

## License

MIT — see [LICENSE](LICENSE).
