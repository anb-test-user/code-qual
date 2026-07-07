#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "requests>=2.28",
#     "reportlab>=4.0",
# ]
# ///
"""Aikido Security Report Builder.

Pulls issues from the Aikido public API — including the remediation /
fix suggestion that the platform shows but the default exported report omits —
and renders them into a polished PDF (or HTML / CSV) report.

Only OPEN issues are included by default; non-open issues (ignored, snoozed,
closed/resolved) are excluded both by the API-side status filter and by a
client-side check on each issue's own status field. Pass ``--status all`` to
include everything.

Data flow
---------
1. ``GET /api/public/v1/issues/export?format=json`` — every individual issue.
   Issues are grouped client-side by their ``group_id``, which yields the
   "Count of subissues" column.
2. ``GET /api/public/v1/issues/groups/{id}`` — one call per issue group
   (the ``getissuegroupdetails`` endpoint), which carries the group's title,
   description and, crucially, the remediation text.
3. Rows are sorted critical → low and rendered.

Authentication
--------------
Create API credentials in Aikido under *Settings → Integrations → API*.
Then either:

* export ``AIKIDO_CLIENT_ID`` and ``AIKIDO_CLIENT_SECRET`` (the script
  exchanges them for a bearer token via the OAuth2 client-credentials grant), or
* export ``AIKIDO_API_TOKEN`` with a ready-made bearer token.

Usage
-----
    uv run tools/aikido_report.py                       # live, writes PDF
    python3 tools/aikido_report.py --demo               # offline sample data
    python3 tools/aikido_report.py -f csv -o issues.csv
    python3 tools/aikido_report.py --dump-json raw.json # debug field names

Only ``reportlab`` is needed for PDF output and only ``requests`` for live API
access; ``--demo -f csv``/``html`` runs on the standard library alone.
"""

from __future__ import annotations

import argparse
import csv
import html as html_mod
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# FILL THESE IN to run the script as-is (create them in Aikido under
# Settings → Integrations → API). Leave empty to use the AIKIDO_* environment
# variables or CLI flags instead, which take precedence over these values.
# Do NOT commit real credentials.
# ---------------------------------------------------------------------------
AIKIDO_CLIENT_ID = ""
AIKIDO_CLIENT_SECRET = ""
AIKIDO_API_TOKEN = ""  # alternative: a ready-made bearer token

def _inline_credential(name):
    """Read a fill-in constant from above, tolerating a deleted/edited line."""
    value = globals().get(name, "")
    return str(value).strip() if value else ""


DEFAULT_BASE_URL = "https://app.aikido.dev"
TOKEN_PATH = "/api/oauth/token"
API_PREFIX = "/api/public/v1"

SEVERITIES = ["critical", "high", "medium", "low"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Status palette (fills) with darker text-safe variants for colored text.
SEVERITY_FILL = {
    "critical": "#d03b3b",
    "high": "#ec835a",
    "medium": "#fab219",
    "low": "#0ca30c",
}
SEVERITY_TEXT = {
    "critical": "#b32e2e",
    "high": "#c2410c",
    "medium": "#8a6d00",
    "low": "#006300",
}

INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
HAIRLINE = "#e1e0d9"
HEADER_BG = "#1f2a44"
ROW_ALT_BG = "#f5f6f8"

# Aikido issue "type" values → human-readable labels (unknown types fall back
# to a title-cased version of the raw value).
TYPE_LABELS = {
    "open_source": "Dependency Vulnerability",
    "dependency": "Dependency Vulnerability",
    "sast": "SAST Finding",
    "leaked_secret": "Secret Detection",
    "secret": "Secret Detection",
    "iac": "IaC Finding",
    "cloud": "Cloud Posture",
    "container": "Container Finding",
    "dast": "DAST Finding",
    "surface_monitoring": "Surface Monitoring",
    "malware": "Malware",
    "eol": "End-of-Life Runtime",
    "end_of_life": "End-of-Life Runtime",
    "mobile": "Mobile Finding",
    "license": "License Issue",
}

COLUMNS = [
    "Type",
    "Severity",
    "Count of subissues",
    "Issue Title",
    "Description",
    "Remediation",
]


# ---------------------------------------------------------------------------
# Field mapping — the Aikido API is read defensively through fallback chains,
# so a renamed field is a one-line fix here (see --dump-json to inspect the
# raw payloads).
# ---------------------------------------------------------------------------

def pick(record, *keys, default=""):
    """Return the first non-empty value among ``keys`` in ``record``."""
    if not isinstance(record, dict):
        return default
    for key in keys:
        value = record.get(key)
        if value is None or value == "" or value == []:
            continue
        if isinstance(value, (list, tuple)):
            return "; ".join(str(v) for v in value if v not in (None, ""))
        if isinstance(value, dict):
            return "; ".join(f"{k}: {v}" for k, v in value.items() if v not in (None, ""))
        return value
    return default


def normalize_severity(value, score=None):
    """Map an API severity (string, or numeric score fallback) to one of SEVERITIES."""
    if isinstance(value, str) and value.strip():
        v = value.strip().lower()
        if v in SEVERITY_RANK:
            return v
        for s in SEVERITIES:
            if v.startswith(s):
                return s
    for candidate in (value, score):
        if isinstance(candidate, (int, float)):
            n = float(candidate)
            if n >= 90:
                return "critical"
            if n >= 70:
                return "high"
            if n >= 40:
                return "medium"
            return "low"
    return "medium"


def humanize_type(value):
    raw = str(value or "").strip()
    if not raw:
        return "Finding"
    return TYPE_LABELS.get(raw.lower(), raw.replace("_", " ").title())


def group_to_row(group, member_count=None):
    """Normalize one issue-group payload into a report row.

    ``member_count`` is the number of issues seen for this group in the
    export; when absent (demo mode, or an issue the export didn't cover) the
    group's own count fields are used.
    """
    count = member_count
    if not count:
        raw_count = pick(group, "issue_count", "open_issue_count", "count", default=None)
        issues = group.get("issues") if isinstance(group, dict) else None
        if isinstance(issues, list) and issues:
            count = len(issues)
        else:
            try:
                count = int(raw_count)
            except (TypeError, ValueError):
                count = 1
    severity = normalize_severity(
        pick(group, "severity", default=None),
        pick(group, "severity_score", "score", default=None),
    )
    return {
        "group_id": pick(group, "id", "group_id", default=""),
        "type": humanize_type(pick(group, "type", "issue_type", "category")),
        "severity": severity,
        "count": max(1, int(count)),
        "title": str(pick(group, "title", "name", "issue_title", "rule",
                          default="(untitled issue group)")),
        "description": str(pick(group, "description", "summary", "details", "explanation")),
        "remediation": str(pick(group, "remediation", "fix", "fix_suggestion",
                                "recommended_fix", "remediation_suggestion", "solution",
                                "how_to_fix")),
    }


def filter_issues_by_status(issues, status):
    """Client-side safety net for the status filter.

    The export endpoint is asked for the requested status via
    ``filter_status``, but if the API were to ignore an unrecognized filter
    parameter, non-matching issues would silently flow into the report.
    Issues that carry a status field that doesn't match are dropped here;
    issues without a recognizable status field are kept.
    """
    if not status or status == "all":
        return issues
    kept = []
    for issue in issues:
        own = str(pick(issue, "status", "state", default="")).strip().lower()
        if not own or own == status:
            kept.append(issue)
    return kept


def group_issues_by_group_id(issues):
    """Bucket exported issues by their group id; returns {group_id: [issue, ...]}."""
    buckets = {}
    for issue in issues:
        gid = pick(issue, "group_id", "issue_group_id", "groupId", default=None)
        if gid in (None, ""):
            gid = f"ungrouped-{pick(issue, 'id', default=id(issue))}"
        buckets.setdefault(str(gid), []).append(issue)
    return buckets


def sort_rows(rows):
    return sorted(
        rows,
        key=lambda r: (SEVERITY_RANK.get(r["severity"], len(SEVERITIES)),
                       -r["count"], r["title"].lower()),
    )


def summarize(rows):
    by_severity = {s: 0 for s in SEVERITIES}
    total_issues = 0
    for row in rows:
        by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1
        total_issues += row["count"]
    return {
        "groups": len(rows),
        "issues": total_issues,
        "by_severity": by_severity,
    }


# ---------------------------------------------------------------------------
# Aikido API client
# ---------------------------------------------------------------------------

class AikidoClient:
    """Minimal Aikido public-API client with retry/backoff and rate-limit handling."""

    def __init__(self, base_url=DEFAULT_BASE_URL, client_id=None, client_secret=None,
                 token=None, timeout=30, verbose=False):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = token
        self.timeout = timeout
        self.verbose = verbose
        import requests  # deferred so offline modes don't need it

        self._requests = requests
        self._session = requests.Session()

    def _log(self, message):
        if self.verbose:
            print(message, file=sys.stderr)

    def _request(self, method, url, max_attempts=5, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        last_error = None
        for attempt in range(max_attempts):
            try:
                response = self._session.request(method, url, **kwargs)
            except self._requests.RequestException as exc:
                last_error = exc
            else:
                if response.status_code == 429 or response.status_code >= 500:
                    retry_after = response.headers.get("Retry-After")
                    delay = float(retry_after) if retry_after else 2 ** (attempt + 1)
                    self._log(f"  {response.status_code} from {url}; retrying in {delay:.0f}s")
                    time.sleep(delay)
                    continue
                response.raise_for_status()
                return response
            time.sleep(2 ** (attempt + 1))
        if last_error:
            raise last_error
        raise RuntimeError(f"{method} {url} kept failing after {max_attempts} attempts")

    def authenticate(self):
        if self.token:
            return
        if not (self.client_id and self.client_secret):
            raise SystemExit(
                "No Aikido credentials. Fill in AIKIDO_CLIENT_ID + AIKIDO_CLIENT_SECRET "
                "at the top of this script, or set them as environment variables "
                "(create them in Aikido under Settings → Integrations → API). "
                "Alternatively provide an existing bearer token via AIKIDO_API_TOKEN."
            )
        self._log("Authenticating (OAuth2 client credentials)…")
        response = self._request(
            "POST",
            self.base_url + TOKEN_PATH,
            auth=(self.client_id, self.client_secret),
            json={"grant_type": "client_credentials"},
        )
        payload = response.json()
        self.token = pick(payload, "access_token", "token", default=None)
        if not self.token:
            raise SystemExit(f"Token endpoint returned no access_token: {payload}")

    def _get(self, path, timeout=None, **params):
        return self._request(
            "GET",
            f"{self.base_url}{API_PREFIX}{path}",
            headers={"Authorization": f"Bearer {self.token}",
                     "Accept": "application/json"},
            params={k: v for k, v in params.items() if v is not None},
            timeout=timeout or self.timeout,
        )

    def export_issues(self, status="open"):
        params = {"format": "json"}
        if status and status != "all":
            params["filter_status"] = status
        # the export can be large on big workspaces — give it extra time
        payload = self._get("/issues/export", timeout=120, **params).json()
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("issues", "data", "items", "results"):
                if isinstance(payload.get(key), list):
                    return payload[key]
        raise SystemExit(f"Unexpected /issues/export response shape: {type(payload).__name__}")

    def get_issue_group(self, group_id):
        payload = self._get(f"/issues/groups/{group_id}").json()
        if isinstance(payload, dict):
            for key in ("group", "data", "issue_group"):
                if isinstance(payload.get(key), dict):
                    return payload[key]
            return payload
        raise SystemExit(f"Unexpected /issues/groups/{group_id} response shape")


def fetch_rows(client, status="open", max_workers=5, dump=None):
    """Live pipeline: export issues, fetch each group's details, normalize rows."""
    client.authenticate()
    print(f"Exporting issues (status={status})…", file=sys.stderr)
    issues = client.export_issues(status)
    matching = filter_issues_by_status(issues, status)
    if len(matching) != len(issues):
        print(f"  dropped {len(issues) - len(matching)} issues whose status "
              f"is not '{status}'", file=sys.stderr)
    issues = matching
    buckets = group_issues_by_group_id(issues)
    print(f"Fetched {len(issues)} issues in {len(buckets)} issue groups; "
          f"fetching group details…", file=sys.stderr)

    groups = {}
    real_ids = [gid for gid in buckets if not gid.startswith("ungrouped-")]
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(client.get_issue_group, gid): gid for gid in real_ids}
        for done, future in enumerate(as_completed(futures), 1):
            gid = futures[future]
            groups[gid] = future.result()
            if done % 10 == 0 or done == len(real_ids):
                print(f"  {done}/{len(real_ids)} groups", file=sys.stderr)

    if dump is not None:
        dump["issues"] = issues
        dump["groups"] = groups

    rows = []
    for gid, members in buckets.items():
        group = groups.get(gid)
        if group is None:
            # No group details available (ungrouped issue) — build the row
            # from the issue itself so nothing silently disappears.
            group = members[0]
        rows.append(group_to_row(group, member_count=len(members)))
    return sort_rows(rows)


def load_demo_rows(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = [group_to_row(g) for g in data.get("issue_groups", [])]
    return sort_rows(rows)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def executive_summary(stats, status):
    b = stats["by_severity"]
    scope = "open " if status == "open" else ""
    return (
        f"This report presents {stats['groups']} {scope}vulnerability issue groups "
        f"(containing {stats['issues']} individual issues) identified across your "
        f"infrastructure by the Aikido security platform. Of these groups, "
        f"{b['critical']} are classified as Critical, {b['high']} as High, "
        f"{b['medium']} as Medium, and {b['low']} as Low severity. Immediate "
        f"remediation is recommended for all Critical and High severity findings "
        f"to reduce organizational risk exposure."
    )


def render_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(COLUMNS)
        for r in rows:
            writer.writerow([r["type"], r["severity"].upper(), r["count"],
                             r["title"], r["description"], r["remediation"]])


DEFAULT_TITLE = "Security Vulnerability Report"
DEFAULT_SUBTITLE = "Enterprise Security Assessment — Aikido Platform"


def render_html(rows, stats, path, generated, status,
                title=DEFAULT_TITLE, subtitle=DEFAULT_SUBTITLE):
    e = html_mod.escape
    max_count = max((stats["by_severity"][s] for s in SEVERITIES), default=0) or 1
    bars = "".join(
        f'<div class="bar-row"><span class="bar-label">{s.capitalize()}</span>'
        f'<span class="bar-track"><span class="bar" style="width:{stats["by_severity"][s] / max_count * 100:.1f}%;'
        f'background:{SEVERITY_FILL[s]}"></span></span>'
        f'<span class="bar-count">{stats["by_severity"][s]}</span></div>'
        for s in SEVERITIES
    )
    body_rows = "".join(
        "<tr>"
        f"<td>{e(r['type'])}</td>"
        f'<td><span class="sev" style="color:{SEVERITY_TEXT[r["severity"]]}">{r["severity"].upper()}</span></td>'
        f'<td class="num">{r["count"]}</td>'
        f"<td>{e(r['title'])}</td>"
        f"<td>{e(r['description'])}</td>"
        f"<td>{e(r['remediation'])}</td>"
        "</tr>"
        for r in rows
    )
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<style>
  body {{ font-family: system-ui, -apple-system, "Segoe UI", sans-serif; color: {INK};
         margin: 2rem auto; max-width: 70rem; padding: 0 1rem; }}
  h1 {{ margin-bottom: .2rem; }} .subtitle {{ color: {INK_SECONDARY}; }}
  .generated {{ color: {INK_MUTED}; font-size: .85rem; }}
  hr {{ border: 0; border-top: 1px solid {HAIRLINE}; margin: 1.2rem 0; }}
  .bar-row {{ display: flex; align-items: center; gap: .6rem; margin: .35rem 0; }}
  .bar-label {{ width: 5rem; font-weight: 600; font-size: .9rem; }}
  .bar-track {{ flex: 1; }}
  .bar {{ display: block; height: 12px; border-radius: 3px; min-width: 3px; }}
  .bar-count {{ width: 2.5rem; text-align: right; font-variant-numeric: tabular-nums; }}
  table {{ border-collapse: collapse; width: 100%; font-size: .82rem; margin-top: 1rem; }}
  th {{ background: {HEADER_BG}; color: #fff; text-align: left; }}
  th, td {{ border: 1px solid {HAIRLINE}; padding: .45rem .5rem; vertical-align: top; }}
  tbody tr:nth-child(even) {{ background: {ROW_ALT_BG}; }}
  .sev {{ font-weight: 700; }} .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  footer {{ margin-top: 1.5rem; color: {INK_MUTED}; font-size: .8rem; }}
</style></head><body>
<h1>{e(title)}</h1>
<p class="subtitle">{e(subtitle)}</p>
<p class="generated">Generated: {e(generated)}</p>
<hr>
<h2>Executive Summary</h2>
<p>{e(executive_summary(stats, status))}</p>
<h2>Severity Distribution</h2>
{bars}
<h2>Detailed Findings <small>({stats['groups']} issue groups)</small></h2>
<table><thead><tr>{''.join(f'<th>{e(c)}</th>' for c in COLUMNS)}</tr></thead>
<tbody>{body_rows}</tbody></table>
<footer>Confidential — Aikido Security Report</footer>
</body></html>
"""
    Path(path).write_text(doc, encoding="utf-8")


def _pdf_styles():
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.styles import ParagraphStyle

    def style(name, **kw):
        base = dict(fontName="Helvetica", fontSize=8, leading=10.5,
                    textColor=colors.HexColor(INK), alignment=TA_LEFT)
        base.update(kw)
        return ParagraphStyle(name, **base)

    return {
        "title": style("title", fontName="Helvetica-Bold", fontSize=22, leading=26),
        "subtitle": style("subtitle", fontSize=11, leading=14,
                          textColor=colors.HexColor(INK_SECONDARY)),
        "generated": style("generated", fontSize=9, leading=12,
                           textColor=colors.HexColor(INK_MUTED)),
        "h2": style("h2", fontName="Helvetica-Bold", fontSize=13, leading=16,
                    spaceBefore=14, spaceAfter=6),
        "body": style("body", fontSize=9.5, leading=13.5),
        # break-anywhere wrap only where long unbreakable tokens occur (package
        # names, file paths); plain English cells wrap at spaces
        "cell": style("cell"),
        "longcell": style("longcell", wordWrap="CJK"),
        "headercell": style("headercell", fontName="Helvetica-Bold",
                            textColor=colors.white),
    }


def _severity_bars(counts, width):
    from reportlab.lib import colors
    from reportlab.platypus import Flowable

    class SeverityBars(Flowable):
        """Severity distribution: label — bar — count, one row per severity."""

        ROW_H, BAR_H, LABEL_W, COUNT_W = 20, 9, 72, 34

        def __init__(self):
            super().__init__()
            self.width = width
            self.height = self.ROW_H * len(SEVERITIES)

        def wrap(self, *_):
            return self.width, self.height

        def draw(self):
            c = self.canv
            ink = colors.HexColor(INK)
            max_count = max(counts.values()) or 1
            track_w = self.width - self.LABEL_W - self.COUNT_W - 16
            for i, sev in enumerate(SEVERITIES):
                count = counts.get(sev, 0)
                y = self.height - (i + 1) * self.ROW_H
                y_bar = y + (self.ROW_H - self.BAR_H) / 2
                y_text = y_bar + 1.5
                c.setFillColor(ink)
                c.setFont("Helvetica-Bold", 9)
                c.drawString(0, y_text, sev.capitalize())
                bar_w = max(3, track_w * count / max_count) if count else 0
                if bar_w:
                    c.setFillColor(colors.HexColor(SEVERITY_FILL[sev]))
                    c.roundRect(self.LABEL_W, y_bar, bar_w, self.BAR_H, 2,
                                stroke=0, fill=1)
                c.setFillColor(ink)
                c.setFont("Helvetica", 9)
                c.drawRightString(self.LABEL_W + track_w + self.COUNT_W,
                                  y_text, str(count))

    return SeverityBars()


def _findings_table(rows, styles, usable):
    from reportlab.lib import colors
    from reportlab.platypus import Paragraph, Table, TableStyle

    data = [[Paragraph(c, styles["headercell"]) for c in COLUMNS]]
    for r in rows:
        sev = r["severity"]
        data.append([
            Paragraph(html_mod.escape(r["type"]), styles["cell"]),
            Paragraph(f'<b><font color="{SEVERITY_TEXT[sev]}">{sev.upper()}</font></b>',
                      styles["cell"]),
            Paragraph(str(r["count"]), styles["cell"]),
            Paragraph(html_mod.escape(r["title"]), styles["longcell"]),
            Paragraph(html_mod.escape(r["description"]), styles["longcell"]),
            Paragraph(html_mod.escape(r["remediation"]), styles["longcell"]),
        ])

    table = Table(
        data,
        colWidths=[68, 52, 36, 96, usable - 68 - 52 - 36 - 96 - 136, 136],
        repeatRows=1,
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(HEADER_BG)),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor(ROW_ALT_BG)]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor(HAIRLINE)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def _page_footer(margin, page_width):
    from reportlab.lib import colors

    def footer(canvas, doc_):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor(HAIRLINE))
        canvas.setLineWidth(0.5)
        canvas.line(margin, margin - 8, page_width - margin, margin - 8)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor(INK_MUTED))
        canvas.drawString(margin, margin - 20, "Confidential — Aikido Security Report")
        canvas.drawRightString(page_width - margin, margin - 20, f"Page {doc_.page}")
        canvas.restoreState()

    return footer


def render_pdf(rows, stats, path, generated, status,
               title=DEFAULT_TITLE, subtitle=DEFAULT_SUBTITLE):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import (HRFlowable, Paragraph, SimpleDocTemplate,
                                    Spacer)

    margin = 36
    usable = A4[0] - 2 * margin
    styles = _pdf_styles()

    story = [
        Paragraph(html_mod.escape(title), styles["title"]),
        Spacer(1, 4),
        Paragraph(html_mod.escape(subtitle), styles["subtitle"]),
        Spacer(1, 2),
        Paragraph(f"Generated: {generated}", styles["generated"]),
        Spacer(1, 8),
        HRFlowable(width="100%", thickness=0.75, color=colors.HexColor(HAIRLINE)),
        Paragraph("Executive Summary", styles["h2"]),
        Paragraph(executive_summary(stats, status), styles["body"]),
        Paragraph("Severity Distribution", styles["h2"]),
        _severity_bars(stats["by_severity"], usable),
        Paragraph(
            f'Detailed Findings <font size="9" color="{INK_MUTED}">'
            f'&nbsp;&nbsp;{stats["groups"]} issue groups</font>', styles["h2"]),
        _findings_table(rows, styles, usable),
    ]

    footer = _page_footer(margin, A4[0])
    doc = SimpleDocTemplate(
        str(path), pagesize=A4,
        leftMargin=margin, rightMargin=margin, topMargin=margin + 6, bottomMargin=margin + 14,
        title=title, author="Aikido Report Builder",
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build a security report (with remediation column) from the Aikido API.")
    parser.add_argument("--status", default="open",
                        help="issue status filter (default: open — non-open issues "
                             "such as ignored/snoozed/closed are excluded; "
                             "use 'all' to include everything)")
    parser.add_argument("--title", default=DEFAULT_TITLE, help="report title")
    parser.add_argument("--subtitle", default=DEFAULT_SUBTITLE, help="report subtitle")
    parser.add_argument("-f", "--format", choices=["pdf", "html", "csv"], default="pdf")
    parser.add_argument("-o", "--output", default=None,
                        help="output path (default: Aikido_Security_Report_<date>.<ext>)")
    parser.add_argument("--base-url", default=os.environ.get("AIKIDO_BASE_URL", DEFAULT_BASE_URL),
                        help=f"Aikido base URL (default: {DEFAULT_BASE_URL})")
    parser.add_argument("--client-id",
                        default=os.environ.get("AIKIDO_CLIENT_ID")
                        or _inline_credential("AIKIDO_CLIENT_ID"))
    parser.add_argument("--client-secret",
                        default=os.environ.get("AIKIDO_CLIENT_SECRET")
                        or _inline_credential("AIKIDO_CLIENT_SECRET"))
    parser.add_argument("--token",
                        default=os.environ.get("AIKIDO_API_TOKEN")
                        or _inline_credential("AIKIDO_API_TOKEN"),
                        help="ready-made bearer token (skips the OAuth exchange)")
    parser.add_argument("--max-workers", type=int, default=5,
                        help="concurrent group-detail requests (default: 5)")
    parser.add_argument("--demo", action="store_true",
                        help="render from bundled sample data instead of the API")
    parser.add_argument("--demo-data", default=str(Path(__file__).with_name("aikido_sample_data.json")),
                        help="sample data file used by --demo")
    parser.add_argument("--dump-json", metavar="PATH",
                        help="also save the raw API payloads (for debugging field names)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    if args.demo:
        rows = load_demo_rows(args.demo_data)
    else:
        client = AikidoClient(base_url=args.base_url, client_id=args.client_id,
                              client_secret=args.client_secret, token=args.token,
                              verbose=args.verbose)
        dump = {} if args.dump_json else None
        rows = fetch_rows(client, status=args.status, max_workers=args.max_workers,
                          dump=dump)
        if args.dump_json:
            Path(args.dump_json).write_text(json.dumps(dump, indent=2, default=str),
                                            encoding="utf-8")
            print(f"Raw API payloads saved to {args.dump_json}", file=sys.stderr)

    if not rows:
        print("No issues found for the given filters — nothing to report.", file=sys.stderr)
        return 1

    stats = summarize(rows)
    generated = datetime.now().strftime("%B %-d, %Y at %I:%M %p") \
        if os.name != "nt" else datetime.now().strftime("%B %d, %Y at %I:%M %p")
    output = args.output or f"Aikido_Security_Report_{datetime.now():%Y%m%d}.{args.format}"

    if args.format == "csv":
        render_csv(rows, output)
    elif args.format == "html":
        render_html(rows, stats, output, generated, args.status,
                    title=args.title, subtitle=args.subtitle)
    else:
        render_pdf(rows, stats, output, generated, args.status,
                   title=args.title, subtitle=args.subtitle)

    b = stats["by_severity"]
    print(f"Wrote {output} — {stats['groups']} issue groups / {stats['issues']} issues "
          f"({b['critical']} critical, {b['high']} high, {b['medium']} medium, {b['low']} low)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
