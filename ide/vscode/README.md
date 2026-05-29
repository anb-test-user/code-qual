# CodeQual for VS Code

Inline code quality findings powered by the [CodeQual](../../README.md) engine —
security, bug, performance, and maintainability issues surfaced right in the editor.

## Requirements

The `codequal` CLI must be installed and on your `PATH`:

```bash
pip install -e ".[ai]"          # from the repo root
export ANTHROPIC_API_KEY=sk-ant-...   # optional; enables AI mode
```

If it isn't on your `PATH`, set `codequal.path` to its absolute location.

## Build / run

```bash
npm install
npm run compile     # outputs out/extension.js
```

Open this folder in VS Code and press **F5** to launch an Extension Development
Host with the extension loaded.

## Commands

| Command | Description |
| --- | --- |
| `CodeQual: Scan Current File` | Scan the active editor (also the status-bar button). |
| `CodeQual: Scan Workspace` | Scan the whole workspace folder. |
| `CodeQual: Clear Findings` | Clear all CodeQual diagnostics. |

Files are also scanned automatically on save (toggle with `codequal.scanOnSave`).

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `codequal.path` | `codequal` | Path to the CLI executable. |
| `codequal.useAI` | `true` | Use the Claude engine when a key is set; otherwise heuristics. |
| `codequal.model` | `""` | Override the Claude model id. |
| `codequal.minConfidence` | `0` | Drop findings below this confidence (0..1). |
| `codequal.scanOnSave` | `true` | Scan a file when it is saved. |

## How it works

The extension runs `codequal file <path> --format json --fail-on none` (or
`codequal repo <root> …` for a workspace scan), parses the structured findings,
and maps each to a VS Code diagnostic — severity → Error/Warning/Information/Hint,
with the suggestion shown in the hover.
