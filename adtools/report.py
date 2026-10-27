"""Report rendering: self-contained HTML (default), JSON and CSV, organized under a reports directory.

Layout::

    reports/
      user-groups/20261027-142233_jdoe.html
      group-members/20261027-142301_vpn-users.html
      compare/20261027-142410_jdoe_vs_asmith.html
      search/20261027-142502_search.html
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any

from .ad import CompareResult, DirectoryObject, GroupsResult, MembersResult

FORMATS = ("html", "json", "csv")

GROUP_COLUMNS = ("name", "membership", "via groups", "scope", "kind", "mail", "description", "dn")
MEMBER_COLUMNS = ("name", "type", "membership", "via groups", "disabled", "mail", "description", "dn")


@dataclass
class Section:
    title: str
    columns: tuple[str, ...]
    rows: list[dict[str, Any]]
    note: str = ""


@dataclass
class Report:
    kind: str  # subdirectory name, e.g. "user-groups"
    title: str
    slug: str
    summary: list[tuple[str, Any]]
    sections: list[Section]
    generated: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "report": self.kind,
            "title": self.title,
            "generated": self.generated.isoformat(),
            "summary": dict(self.summary),
            "sections": [{"title": s.title, "rows": s.rows} for s in self.sections],
        }


def _now() -> datetime:
    return datetime.now(UTC)


def _principal_summary(p: DirectoryObject) -> list[tuple[str, Any]]:
    return [
        ("Account", p.name),
        ("Display name", p.get("displayName")),
        ("Email", p.get("mail")),
        ("UPN", p.get("userPrincipalName")),
        ("Disabled", "yes" if p.disabled else "no"),
        ("DN", p.dn),
    ]


def user_groups_report(result: GroupsResult) -> Report:
    rows = [m.as_dict() for m in result.groups]
    direct = sum(1 for m in result.groups if m.direct)
    summary = [
        *_principal_summary(result.principal),
        ("Direct groups (incl. primary)", direct),
        ("Nested-only groups", len(rows) - direct if result.nested else "not queried"),
        ("Total", len(rows)),
    ]
    return Report(
        "user-groups",
        f"Group memberships of {result.principal.name}",
        result.principal.name,
        summary,
        [Section("Groups", GROUP_COLUMNS, rows)],
        _now(),
    )


def group_members_report(result: MembersResult) -> Report:
    rows = [m.as_dict() for m in result.members]
    direct = sum(1 for m in result.members if m.direct)
    g = result.group
    summary = [
        ("Group", g.name),
        ("Email", g.get("mail")),
        ("Description", g.get("description")),
        ("DN", g.dn),
        ("Direct members (incl. primary)", direct),
        ("Nested-only members", len(rows) - direct if result.nested else "not queried"),
        ("Users", sum(1 for r in rows if r["type"] == "user")),
        ("Groups", sum(1 for r in rows if r["type"] == "group")),
        ("Total", len(rows)),
    ]
    return Report(
        "group-members",
        f"Members of {g.name}",
        g.name,
        summary,
        [Section("Members", MEMBER_COLUMNS, rows)],
        _now(),
    )


def compare_report(result: CompareResult) -> Report:
    a, b = result.first.principal, result.second.principal
    common_rows = []
    for ma, mb in result.common:
        row = ma.as_dict()
        row.pop("membership")
        row.pop("via groups")
        row[f"{a.name} via"] = ma.via
        row[f"{b.name} via"] = mb.via
        common_rows.append(row)
    only_a = [m.as_dict() for m in result.only_first]
    only_b = [m.as_dict() for m in result.only_second]
    summary = [
        (f"{a.name}", f"{a.get('displayName') or ''} ({a.dn})"),
        (f"{b.name}", f"{b.get('displayName') or ''} ({b.dn})"),
        ("Groups in common", len(common_rows)),
        (f"Only {a.name}", len(only_a)),
        (f"Only {b.name}", len(only_b)),
        ("Nested groups included", "yes" if result.first.nested else "no"),
    ]
    common_columns = ("name", f"{a.name} via", f"{b.name} via", "scope", "kind", "description", "dn")
    return Report(
        "compare",
        f"Group comparison: {a.name} vs {b.name}",
        f"{a.name}_vs_{b.name}",
        summary,
        [
            Section(f"Only {a.name}", GROUP_COLUMNS, only_a, f"Groups {b.name} is not in"),
            Section(f"Only {b.name}", GROUP_COLUMNS, only_b, f"Groups {a.name} is not in"),
            Section("In common", common_columns, common_rows),
        ],
        _now(),
    )


def search_report(filter_text: str, base: str, objects: list[DirectoryObject], attributes: list[str]) -> Report:
    columns = tuple(attributes) if attributes else ()
    rows = []
    for o in objects:
        row: dict[str, Any] = {"dn": o.dn}
        for name, values in o.attributes.items():
            row[name] = values[0] if len(values) == 1 else values
        rows.append(row)
    if not columns:
        seen: dict[str, None] = {}
        for row in rows:
            seen.update(dict.fromkeys(k for k in row if k != "dn"))
        columns = tuple(seen)
    return Report(
        "search",
        "LDAP search",
        "search",
        [("Filter", filter_text), ("Base", base), ("Results", len(rows))],
        [Section("Results", ("dn", *columns), rows)],
        _now(),
    )


# --- writers ------------------------------------------------------------------


def slugify(text: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-.")
    return slug[:80] or "report"


def write_report(report: Report, reports_dir: str | Path = "reports", formats: tuple[str, ...] = ("html",)) -> list[Path]:
    """Write the report in each format and return the paths written."""
    unknown = set(formats) - set(FORMATS)
    if unknown:
        raise ValueError(f"unknown format(s): {', '.join(sorted(unknown))}")
    directory = Path(reports_dir) / report.kind
    directory.mkdir(parents=True, exist_ok=True)
    stem = f"{report.generated:%Y%m%d-%H%M%S}_{slugify(report.slug)}"
    paths = []
    for fmt in formats:
        path = directory / f"{stem}.{fmt}"
        if fmt == "html":
            path.write_text(render_html(report), encoding="utf-8")
        elif fmt == "json":
            path.write_text(json.dumps(report.as_dict(), indent=2, default=str) + "\n", encoding="utf-8")
        else:
            path.write_text(render_csv(report), encoding="utf-8", newline="")
        paths.append(path)
    return paths


def render_csv(report: Report) -> str:
    buffer = io.StringIO()
    columns: dict[str, None] = {"section": None}
    for section in report.sections:
        columns.update(dict.fromkeys(section.columns))
    writer = csv.DictWriter(buffer, fieldnames=list(columns), extrasaction="ignore")
    writer.writeheader()
    for section in report.sections:
        for row in section.rows:
            writer.writerow({"section": section.title, **{k: _csv_cell(v) for k, v in row.items()}})
    return buffer.getvalue()


def _csv_cell(value: Any) -> str:
    text = _text(value)
    # Neutralize spreadsheet formula injection (CWE-1236).
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def render_text(report: Report) -> str:
    lines = [report.title, "=" * len(report.title)]
    lines += [f"{k}: {_text(v)}" for k, v in report.summary if _text(v)]
    for section in report.sections:
        lines += ["", f"{section.title} ({len(section.rows)})", "-" * (len(section.title) + 8)]
        columns = [c for c in section.columns if c not in ("dn", "description")]
        widths = {c: max([len(c)] + [len(_text(r.get(c))) for r in section.rows]) for c in columns}
        lines.append("  ".join(c.ljust(widths[c]) for c in columns))
        for row in section.rows:
            lines.append("  ".join(_text(row.get(c)).ljust(widths[c]) for c in columns))
    return "\n".join(lines) + "\n"


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        return "; ".join(_text(v) for v in value)
    return str(value)


_CSS = """
:root{--bg:#ffffff;--fg:#1d2330;--muted:#5d6675;--line:#dde1e8;--head:#f3f5f8;--accent:#2457c5;
--direct:#e6f0ff;--nested:#f1ecfb;--primary:#e7f6ec;--warn:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#14171d;--fg:#e4e7ec;--muted:#98a2b3;--line:#2d333d;
--head:#1c2029;--accent:#7aa2ff;--direct:#1d2a44;--nested:#2a2240;--primary:#1b3326;--warn:#ff8a80}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:1280px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 4px}
.meta,.note{color:var(--muted);font-size:12.5px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:16px 0;padding:12px 16px;
border:1px solid var(--line);border-radius:8px;background:var(--head)}
dt{color:var(--muted)}dd{margin:0;word-break:break-word}
input[type=search]{width:100%;max-width:360px;padding:6px 10px;margin:8px 0;border:1px solid var(--line);
border-radius:6px;background:var(--bg);color:var(--fg);font:inherit}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%}
th,td{padding:6px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--head);cursor:pointer;user-select:none;white-space:nowrap;position:sticky;top:0}
th[aria-sort=ascending]::after{content:" \\25B2"}th[aria-sort=descending]::after{content:" \\25BC"}
tr:last-child td{border-bottom:0}
td.dn{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;color:var(--muted)}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;white-space:nowrap}
.pill.direct{background:var(--direct)}.pill.nested{background:var(--nested)}.pill.primary{background:var(--primary)}
.yes{color:var(--warn);font-weight:600}
.empty{padding:12px;color:var(--muted)}
"""

_JS = """
document.querySelectorAll("table").forEach(function(t){
  t.querySelectorAll("th").forEach(function(th,i){
    th.addEventListener("click",function(){
      var asc=th.getAttribute("aria-sort")!=="ascending";
      t.querySelectorAll("th").forEach(function(o){o.removeAttribute("aria-sort")});
      th.setAttribute("aria-sort",asc?"ascending":"descending");
      var rows=Array.from(t.tBodies[0].rows);
      rows.sort(function(a,b){var x=a.cells[i].textContent,y=b.cells[i].textContent;
        return (asc?1:-1)*x.localeCompare(y,undefined,{numeric:true,sensitivity:"base"})});
      rows.forEach(function(r){t.tBodies[0].appendChild(r)});
    });
  });
});
document.querySelectorAll("input[data-filter]").forEach(function(box){
  var t=document.getElementById(box.getAttribute("data-filter"));
  box.addEventListener("input",function(){var q=box.value.toLowerCase();
    Array.from(t.tBodies[0].rows).forEach(function(r){
      r.hidden=q&&r.textContent.toLowerCase().indexOf(q)<0});});
});
"""


def render_html(report: Report) -> str:
    out = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>{escape(report.title)}</title><style>{_CSS}</style></head><body><main>",
        f"<h1>{escape(report.title)}</h1>",
        f'<p class="meta">Generated {escape(report.generated.strftime("%Y-%m-%d %H:%M:%S UTC"))} by ad-tools</p>',
        "<dl>",
    ]
    for key, value in report.summary:
        out.append(f"<dt>{escape(str(key))}</dt><dd>{escape(_text(value)) or '&mdash;'}</dd>")
    out.append("</dl>")
    for index, section in enumerate(report.sections):
        table_id = f"t{index}"
        out.append(f"<h2>{escape(section.title)} ({len(section.rows)})</h2>")
        if section.note:
            out.append(f'<p class="note">{escape(section.note)}</p>')
        if not section.rows:
            out.append('<div class="wrap"><div class="empty">None</div></div>')
            continue
        out.append(
            f'<input type="search" placeholder="Filter rows" '
            f'aria-label="Filter {escape(section.title)}" data-filter="{table_id}">'
        )
        out.append(f'<div class="wrap"><table id="{table_id}"><thead><tr>')
        out.extend(f"<th>{escape(c)}</th>" for c in section.columns)
        out.append("</tr></thead><tbody>")
        for row in section.rows:
            out.append("<tr>" + "".join(_cell(c, row.get(c)) for c in section.columns) + "</tr>")
        out.append("</tbody></table></div>")
    out.append(f"</main><script>{_JS}</script></body></html>")
    return "\n".join(out)


def _cell(column: str, value: Any) -> str:
    text = escape(_text(value))
    if column == "membership" or column.endswith(" via"):
        cls = {"direct": "direct", "nested": "nested", "primary group": "primary"}.get(_text(value), "")
        return f'<td><span class="pill {cls}">{text}</span></td>'
    if column == "disabled":
        return f'<td class="{"yes" if value else ""}">{text}</td>'
    if column == "dn":
        return f'<td class="dn">{text}</td>'
    return f"<td>{text}</td>"
