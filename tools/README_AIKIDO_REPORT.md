# Aikido Security Report Builder

`aikido_report.py` pulls your issues from the [Aikido](https://www.aikido.dev)
public API and renders them into a polished PDF report — **including the
remediation / fix suggestion** that the platform shows but the default
exported report omits.

The report contains an executive summary, a severity-distribution chart, and a
findings table with these columns:

| Column | Source |
| --- | --- |
| Type | issue group `type` (`open_source` → "Dependency Vulnerability", `sast` → "SAST Finding", `leaked_secret` → "Secret Detection", …) |
| Severity | issue group `severity` (critical / high / medium / low) |
| Count of subissues | number of individual issues in the group (from `GET /issues/export`, grouped by `group_id`) |
| Issue Title | issue group `title` |
| Description | issue group `description` |
| Remediation | issue group `remediation` from [`GET /issues/groups/{id}`](https://apidocs.aikido.dev/reference/getissuegroupdetails) |

## Setup

1. In Aikido, go to **Settings → Integrations → API** and create API
   credentials (a client ID + secret).
2. Export them:

   ```bash
   export AIKIDO_CLIENT_ID=...
   export AIKIDO_CLIENT_SECRET=...
   # or, if you already have a bearer token:
   export AIKIDO_API_TOKEN=...
   ```

3. Install the two dependencies (only needed for live API access + PDF output):

   ```bash
   pip install requests reportlab
   ```

   Or skip the install entirely and use [uv](https://docs.astral.sh/uv/), which
   reads the script's inline dependency block:

   ```bash
   uv run tools/aikido_report.py
   ```

## Usage

```bash
python3 tools/aikido_report.py                      # open issues → Aikido_Security_Report_<date>.pdf
python3 tools/aikido_report.py -f csv -o issues.csv # same data as CSV
python3 tools/aikido_report.py -f html -o report.html
python3 tools/aikido_report.py --demo               # offline sample data, no API needed
```

**Only open issues are included by default.** Non-open issues (ignored,
snoozed, closed/resolved) are excluded twice over: the export request asks the
API for open issues only (`filter_status=open`), and a client-side check drops
any returned issue whose own status field says otherwise. Pass `--status all`
only if you explicitly want everything.

### Scoping the report

By default the report covers **all teams, repositories, and scan types**.
Narrow it with:

```bash
python3 tools/aikido_report.py --list-teams          # discover team ids
python3 tools/aikido_report.py --list-repos          # discover repository ids
python3 tools/aikido_report.py --team 12             # one team (id or exact name)
python3 tools/aikido_report.py --repo backend-api    # repos (ids or name substrings, comma-separated)
python3 tools/aikido_report.py --type sast,secrets   # scan types only
python3 tools/aikido_report.py --team 12 --repo 42,billing --type open_source
```

Scan type values: `open_source` (dependencies), `sast`, `secrets`
(`leaked_secret`), `iac`, `cloud`, `dast`, `surface`, `malware`, `eol`.
Filters are applied server-side where the API supports it **and** re-checked
client-side against each exported issue, so out-of-scope issues cannot leak
into the report either way. Active filters are printed on the report under
the generated date ("Scope: …").

| Flag | Meaning |
| --- | --- |
| `--status` | issue status filter (default `open` — non-open issues are excluded; `all` includes everything) |
| `--team` | only issues of this team (id or exact name) |
| `--repo` | only issues of these repositories (ids or name substrings, comma-separated) |
| `--type` | only these scan types (comma-separated) |
| `--severity` | only these severities, e.g. `critical,high` (comma-separated) |
| `--list-teams`, `--list-repos` | print ids/names to use with the flags above, then exit |
| `-f, --format` | `pdf` (default), `html`, `csv` |
| `-o, --output` | output path |
| `--title`, `--subtitle` | report heading text (defaults match the reference report) |
| `--base-url` | Aikido base URL (default `https://app.me.aikido.dev`, the ME-region instance; other regions use `https://app.aikido.dev`; also `AIKIDO_BASE_URL`) |
| `--max-workers` | concurrent group-detail requests (default 5) |
| `--demo` | render from `aikido_sample_data.json` instead of the API |
| `--dump-json PATH` | also save the raw API payloads |
| `-v` | verbose progress / retry logging |

## Windows

The script is Windows-compatible: use `py` instead of `python3`, and `start`
instead of `open`. In PowerShell:

```powershell
py -m pip install requests reportlab
$env:AIKIDO_CLIENT_ID="..."; $env:AIKIDO_CLIENT_SECRET="..."
py aikido_report.py                       # PDF
py aikido_report.py -f html -o report.html; start report.html
```

CSV output is written with a UTF-8 BOM so it opens correctly in Excel.

## How it works

1. Authenticates via the OAuth2 client-credentials grant
   (`POST /api/oauth/token`), unless `AIKIDO_API_TOKEN` is set.
2. `GET /api/public/v1/issues/export?format=json&filter_status=open` fetches
   every individual issue; grouping by `group_id` yields the subissue counts.
3. `GET /api/public/v1/issues/groups/{id}` is called once per group (5 in
   parallel, with retry/backoff that honors `Retry-After` on rate limits) to
   fetch the title, description, and **remediation**.
4. Rows are sorted critical → low and rendered.

## Troubleshooting

The script reads every column through a fallback chain of field names (e.g.
remediation: `remediation` → `fix` → `fix_suggestion` → `recommended_fix` → …),
so it tolerates small API differences. If a column comes out empty against
your workspace, run with `--dump-json raw.json`, look up the real field name
in `raw.json`, and add it to the matching `pick(...)` chain in
`group_to_row()` — a one-line fix.
