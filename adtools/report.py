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
from dataclasses import dataclass, field
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


# Safety valve for pathological graphs; a subtree is never expanded twice, so real trees stay well under it.
MAX_TREE_NODES = 20000


@dataclass
class TreeNode:
    """One object in the hierarchy view. ``link`` is how it hangs off its parent."""

    name: str
    type: str
    dn: str
    link: str = ""  # "direct" | "nested" | "primary group" ("" for the root)
    disabled: bool = False
    note: str = ""  # "shown above" | "cycle" | "truncated"
    children: list[TreeNode] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name, "type": self.type, "dn": self.dn}
        if self.link:
            out["link"] = self.link
        if self.disabled:
            out["disabled"] = True
        if self.note:
            out["note"] = self.note
        if self.children:
            out["children"] = [c.as_dict() for c in self.children]
        return out


@dataclass
class Report:
    kind: str  # subdirectory name, e.g. "user-groups"
    title: str
    slug: str
    summary: list[tuple[str, Any]]
    sections: list[Section]
    generated: datetime
    tree: TreeNode | None = None
    tree_title: str = ""

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "report": self.kind,
            "title": self.title,
            "generated": self.generated.isoformat(),
            "summary": dict(self.summary),
        }
        if self.tree is not None:
            out["tree"] = self.tree.as_dict()
        out["sections"] = [{"title": s.title, "rows": s.rows} for s in self.sections]
        return out


def build_tree(root: DirectoryObject, edges: dict[str, dict[str, str]], objects: dict[str, DirectoryObject]) -> TreeNode:
    """Expand ``edges`` from ``root`` into a tree.

    A subtree reached a second time (a diamond) is not expanded again but marked
    "shown above"; a link back to an ancestor is marked "cycle".
    """
    objects = {**objects, root.dn.lower(): root}
    expanded: set[str] = set()
    count = 0

    def order(item: tuple[str, str]) -> tuple[int, str]:
        obj = objects[item[0]]
        return (0 if obj.object_class == "group" else 1, obj.name.lower())

    def walk(key: str, link: str, path: frozenset[str]) -> TreeNode:
        nonlocal count
        count += 1
        obj = objects[key]
        node = TreeNode(obj.name, obj.object_class, obj.dn, link, obj.disabled)
        children = edges.get(key, {})
        if key in path:
            node.note = "cycle"
        elif children and key in expanded:
            node.note = "shown above"
        elif children and count >= MAX_TREE_NODES:
            node.note = "truncated"
        else:
            expanded.add(key)
            for child_key, child_link in sorted(children.items(), key=order):
                node.children.append(walk(child_key, child_link, path | {key}))
        return node

    return walk(root.dn.lower(), "", frozenset())


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
    tree = build_tree(result.principal, result.edges, {m.obj.dn.lower(): m.obj for m in result.groups})
    return Report(
        "user-groups",
        f"Group memberships of {result.principal.name}",
        result.principal.name,
        summary,
        [Section("Groups", GROUP_COLUMNS, rows)],
        _now(),
        tree,
        f"{result.principal.name} is a member of",
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
    tree = build_tree(g, result.edges, {m.obj.dn.lower(): m.obj for m in result.members})
    return Report(
        "group-members",
        f"Members of {g.name}",
        g.name,
        summary,
        [Section("Members", MEMBER_COLUMNS, rows)],
        _now(),
        tree,
        f"Members of {g.name}",
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
    if report.tree is not None and report.tree.children:
        lines += ["", "Hierarchy", "---------", *tree_lines(report.tree)]
    for section in report.sections:
        lines += ["", f"{section.title} ({len(section.rows)})", "-" * (len(section.title) + 8)]
        columns = [c for c in section.columns if c not in ("dn", "description")]
        widths = {c: max([len(c)] + [len(_text(r.get(c))) for r in section.rows]) for c in columns}
        lines.append("  ".join(c.ljust(widths[c]) for c in columns))
        for row in section.rows:
            lines.append("  ".join(_text(row.get(c)).ljust(widths[c]) for c in columns))
    return "\n".join(lines) + "\n"


def _node_label(node: TreeNode) -> str:
    extras = [x for x in (node.type if node.type != "group" else "", node.link if node.link != "direct" else "") if x]
    if node.disabled:
        extras.append("disabled")
    if node.note:
        extras.append(node.note)
    return node.name + (f" [{', '.join(extras)}]" if extras else "")


def tree_lines(node: TreeNode, prefix: str = "", last: bool = True, root: bool = True) -> list[str]:
    lines = [_node_label(node)] if root else [f"{prefix}{'└── ' if last else '├── '}{_node_label(node)}"]
    child_prefix = "" if root else prefix + ("    " if last else "│   ")
    for i, child in enumerate(node.children):
        lines += tree_lines(child, child_prefix, i == len(node.children) - 1, root=False)
    return lines


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
--direct:#e6f0ff;--nested:#f1ecfb;--primary:#e7f6ec;--warn:#b42318;--pop:#ffffff;--hover:#eef2f8;
--shadow:0 8px 24px rgba(16,24,40,.16)}
@media (prefers-color-scheme:dark){:root{--bg:#14171d;--fg:#e4e7ec;--muted:#98a2b3;--line:#2d333d;
--head:#1c2029;--accent:#7aa2ff;--direct:#1d2a44;--nested:#2a2240;--primary:#1b3326;--warn:#ff8a80;
--pop:#1c2029;--hover:#252b36;--shadow:0 8px 24px rgba(0,0,0,.5)}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:1280px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 4px}
.meta,.note{color:var(--muted);font-size:12.5px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:16px 0;padding:12px 16px;
border:1px solid var(--line);border-radius:8px;background:var(--head)}
dt{color:var(--muted)}dd{margin:0;word-break:break-word}
button{font:inherit;color:inherit}
input[type=search]{width:100%;max-width:360px;padding:6px 10px;border:1px solid var(--line);
border-radius:6px;background:var(--bg);color:var(--fg);font:inherit}
.xf-bar{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px;margin:8px 0}
.xf-status{color:var(--muted);font-size:12.5px}
.linkish{background:none;border:0;padding:0;color:var(--accent);cursor:pointer;font-size:12.5px}
.linkish:hover{text-decoration:underline}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%}
th,td{padding:6px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--head);white-space:nowrap;position:sticky;top:0;padding-right:4px}
.xf-label{cursor:pointer;user-select:none}
th[aria-sort=ascending] .xf-label::after{content:" \25B2";font-size:10px}
th[aria-sort=descending] .xf-label::after{content:" \25BC";font-size:10px}
.xf-btn{margin-left:4px;width:22px;height:22px;border:1px solid var(--line);border-radius:4px;background:var(--bg);
cursor:pointer;font-size:11px;line-height:1;color:var(--muted);vertical-align:middle}
.xf-btn:hover{border-color:var(--accent);color:var(--accent)}
th.xf-on .xf-btn{background:var(--accent);border-color:var(--accent);color:var(--bg)}
tr:last-child td{border-bottom:0}
td.dn{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;color:var(--muted)}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;white-space:nowrap}
.pill.direct{background:var(--direct)}.pill.nested{background:var(--nested)}.pill.primary{background:var(--primary)}
.yes{color:var(--warn);font-weight:600}
.empty{padding:12px;color:var(--muted)}
.xf-pop{position:absolute;z-index:10;width:280px;max-width:calc(100vw - 16px);background:var(--pop);
border:1px solid var(--line);border-radius:8px;box-shadow:var(--shadow);padding:8px;font-size:13px}
.xf-pop input[type=search]{max-width:none;margin:6px 0}
.xf-sort{display:flex;flex-direction:column;border-bottom:1px solid var(--line);padding-bottom:6px}
.xf-sort button{text-align:left;background:none;border:0;padding:5px 6px;border-radius:4px;cursor:pointer}
.xf-sort button:hover,.xf-list label:hover{background:var(--hover)}
.xf-list{max-height:260px;overflow:auto;border:1px solid var(--line);border-radius:6px;padding:4px 0}
.xf-list label{display:flex;align-items:center;gap:6px;padding:3px 8px;cursor:pointer}
.xf-list label span:first-of-type{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.xf-all{font-weight:600}
.xf-count{color:var(--muted);font-size:11.5px}
.xf-blank{font-style:italic;color:var(--muted)}
.xf-more{margin:4px 8px;color:var(--muted);font-size:12px}
.xf-actions{display:flex;justify-content:flex-end;gap:6px;margin-top:8px}
.xf-actions button{padding:5px 12px;border-radius:6px;border:1px solid var(--line);background:var(--bg);cursor:pointer}
.xf-actions .xf-primary{background:var(--accent);border-color:var(--accent);color:var(--bg)}
.tree-wrap{border:1px solid var(--line);border-radius:8px;padding:8px 12px;overflow-x:auto}
.tree-tools{display:flex;gap:12px;margin:8px 0}
ul.tree,ul.tree ul{list-style:none;margin:0;padding-left:20px}
ul.tree{padding-left:0}
ul.tree ul{border-left:1px dashed var(--line);margin-left:7px}
ul.tree li{margin:2px 0;white-space:nowrap}
ul.tree summary{cursor:pointer}
ul.tree .leaf{padding-left:16px}
.tn{font-weight:500}.tk,.tnote{color:var(--muted);font-size:12px}
.tnote{font-style:italic}
@media print{.xf-btn,.xf-bar input,.linkish,.tree-tools{display:none}}
"""

_JS = r"""
(function(){
function vals(td){var raw=td.getAttribute("data-v");
  if(raw){try{var a=JSON.parse(raw);return a.length?a.map(String):[""]}catch(e){}}
  return [td.textContent.trim()]}
function cmp(a,b){return a.localeCompare(b,undefined,{numeric:true,sensitivity:"base"})}
function el(tag,cls,text){var e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=text;return e}
var pop=el("div","xf-pop");pop.hidden=true;pop.setAttribute("role","dialog");document.body.appendChild(pop);
var current=null;
function closePop(){pop.hidden=true;if(current){current.setAttribute("aria-expanded","false");current=null}}
function place(){if(!current||pop.hidden)return;var r=current.getBoundingClientRect(),vw=document.documentElement.clientWidth;
  pop.style.left=(window.scrollX+Math.max(8,Math.min(r.left,vw-pop.offsetWidth-8)))+"px";
  pop.style.top=(window.scrollY+r.bottom+4)+"px"}
document.addEventListener("mousedown",function(e){if(!pop.hidden&&!pop.contains(e.target)&&!(current&&current.contains(e.target)))closePop()});
document.addEventListener("keydown",function(e){if(e.key==="Escape"&&!pop.hidden){var b=current;closePop();if(b)b.focus()}});
window.addEventListener("resize",place);  // not close: a phone's on-screen keyboard resizes the window

document.querySelectorAll("table.xf").forEach(function(t){
  var tbody=t.tBodies[0],rows=Array.from(tbody.rows),ths=Array.from(t.tHead.rows[0].cells);
  var cache=rows.map(function(r){return Array.from(r.cells).map(vals)});
  var filters=ths.map(function(){return null}),quick="";
  var box=document.querySelector('input[data-filter="'+t.id+'"]');
  var status=document.querySelector('[data-status="'+t.id+'"]');
  var clearAll=document.querySelector('[data-clear="'+t.id+'"]');
  function passes(i,skip){
    for(var c=0;c<filters.length;c++){if(c===skip||!filters[c])continue;
      var ok=false,v=cache[i][c];for(var k=0;k<v.length;k++){if(filters[c].has(v[k])){ok=true;break}}if(!ok)return false}
    return !quick||rows[i].textContent.toLowerCase().indexOf(quick)>=0}
  function apply(){var shown=0;rows.forEach(function(r,i){var ok=passes(i,-1);r.hidden=!ok;if(ok)shown++});
    ths.forEach(function(th,c){th.classList.toggle("xf-on",!!filters[c]);
      var label="Filter "+th.getAttribute("data-col")+(filters[c]?" (filtered)":"");
      th.querySelector(".xf-btn").setAttribute("aria-label",label)});
    var any=quick||filters.some(Boolean);
    status.textContent=any?"Showing "+shown+" of "+rows.length+" rows":rows.length+" rows";clearAll.hidden=!any}
  function sort(c,asc){var idx=rows.map(function(_,i){return i});
    idx.sort(function(a,b){return (asc?1:-1)*cmp(cache[a][c].join("; "),cache[b][c].join("; "))});
    ths.forEach(function(th){th.removeAttribute("aria-sort")});ths[c].setAttribute("aria-sort",asc?"ascending":"descending");
    rows=idx.map(function(i){return rows[i]});cache=idx.map(function(i){return cache[i]});
    rows.forEach(function(r){tbody.appendChild(r)})}
  function open(c,btn){
    closePop();current=btn;btn.setAttribute("aria-expanded","true");
    var counts=new Map();
    rows.forEach(function(r,i){if(passes(i,c))cache[i][c].forEach(function(v){counts.set(v,(counts.get(v)||0)+1)})});
    var values=Array.from(counts.keys()).sort(cmp),LIMIT=1000;
    var checked=new Set(filters[c]?values.filter(function(v){return filters[c].has(v)}):values);
    pop.textContent="";
    function button(label,cls,fn){var b=el("button",cls,label);b.type="button";b.addEventListener("click",fn);return b}
    var sorts=el("div","xf-sort");
    sorts.appendChild(button("Sort A → Z","",function(){sort(c,true);closePop()}));
    sorts.appendChild(button("Sort Z → A","",function(){sort(c,false);closePop()}));
    pop.appendChild(sorts);
    var search=el("input");search.type="search";search.placeholder="Search";search.setAttribute("aria-label","Search values");
    pop.appendChild(search);
    var list=el("div","xf-list");pop.appendChild(list);
    function matching(){var q=search.value.toLowerCase();
      return values.filter(function(v){return !q||(v===""?"(blanks)":v.toLowerCase()).indexOf(q)>=0})}
    function render(){
      list.textContent="";var vis=matching();
      var all=el("label","xf-all"),allBox=el("input");allBox.type="checkbox";
      function syncAll(){var n=vis.filter(function(v){return checked.has(v)}).length;
        allBox.checked=vis.length>0&&n===vis.length;allBox.indeterminate=n>0&&n<vis.length}
      allBox.addEventListener("change",function(){var on=allBox.checked;
        vis.forEach(function(v){if(on)checked.add(v);else checked.delete(v)});render()});
      all.appendChild(allBox);all.appendChild(el("span","",search.value?"(Select all search results)":"(Select all)"));
      list.appendChild(all);
      vis.slice(0,LIMIT).forEach(function(v){var l=el("label"),cb=el("input");cb.type="checkbox";cb.checked=checked.has(v);
        cb.addEventListener("change",function(){if(cb.checked)checked.add(v);else checked.delete(v);syncAll()});
        l.appendChild(cb);l.appendChild(el("span",v===""?"xf-blank":"",v===""?"(Blanks)":v));
        l.appendChild(el("span","xf-count",String(counts.get(v))));list.appendChild(l)});
      if(vis.length>LIMIT)list.appendChild(el("p","xf-more",(vis.length-LIMIT)+" more values — type to search"));
      if(!vis.length)list.appendChild(el("p","xf-more","No matches"));
      syncAll()}
    function ok(){var q=search.value,chosen=(q?matching():values).filter(function(v){return checked.has(v)});
      filters[c]=(!q&&chosen.length===values.length)?null:new Set(chosen);apply();closePop();btn.focus()}
    search.addEventListener("input",render);
    search.addEventListener("keydown",function(e){if(e.key==="Enter"){e.preventDefault();ok()}});
    render();
    var actions=el("div","xf-actions");
    actions.appendChild(button("Clear filter","",function(){filters[c]=null;apply();closePop();btn.focus()}));
    actions.appendChild(button("OK","xf-primary",ok));
    pop.appendChild(actions);
    pop.hidden=false;place();search.focus()}
  ths.forEach(function(th,c){var b=th.querySelector(".xf-btn");
    b.addEventListener("click",function(e){e.stopPropagation();if(current===b){closePop();return}open(c,b)});
    th.querySelector(".xf-label").addEventListener("click",function(){sort(c,th.getAttribute("aria-sort")!=="ascending")})});
  if(box)box.addEventListener("input",function(){quick=box.value.toLowerCase();apply()});
  clearAll.addEventListener("click",function(){
    filters=filters.map(function(){return null});quick="";if(box)box.value="";apply()});
  apply();
});
document.querySelectorAll("[data-tree-action]").forEach(function(b){b.addEventListener("click",function(){
  var expand=b.getAttribute("data-tree-action")==="expand";
  document.getElementById(b.getAttribute("data-tree")).querySelectorAll("details").forEach(function(d){d.open=expand})})});
})();
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
    if report.tree is not None and report.tree.children:
        out.append(
            f'<h2>Hierarchy</h2><p class="note">{escape(report.tree_title)}, level by level. '
            "A group reached more than once is expanded the first time only.</p>"
        )
        out.append(
            '<div class="tree-tools">'
            '<button type="button" class="linkish" data-tree="tree" data-tree-action="expand">Expand all</button>'
            '<button type="button" class="linkish" data-tree="tree" data-tree-action="collapse">Collapse all</button>'
            "</div>"
        )
        out.append(f'<div class="tree-wrap"><ul class="tree" id="tree">{_tree_html(report.tree, 0)}</ul></div>')
    for index, section in enumerate(report.sections):
        table_id = f"t{index}"
        out.append(f"<h2>{escape(section.title)} ({len(section.rows)})</h2>")
        if section.note:
            out.append(f'<p class="note">{escape(section.note)}</p>')
        if not section.rows:
            out.append('<div class="wrap"><div class="empty">None</div></div>')
            continue
        out.append(
            '<div class="xf-bar">'
            f'<input type="search" placeholder="Search all columns" '
            f'aria-label="Search {escape(section.title)}" data-filter="{table_id}">'
            f'<span class="xf-status" data-status="{table_id}" aria-live="polite"></span>'
            f'<button type="button" class="linkish" data-clear="{table_id}" hidden>Clear all filters</button>'
            "</div>"
        )
        out.append(f'<div class="wrap"><table class="xf" id="{table_id}"><thead><tr>')
        out.extend(
            f'<th data-col="{escape(c)}"><span class="xf-label">{escape(c)}</span>'
            f'<button type="button" class="xf-btn" aria-haspopup="dialog" aria-expanded="false" '
            f'aria-label="Filter {escape(c)}">&#9662;</button></th>'
            for c in section.columns
        )
        out.append("</tr></thead><tbody>")
        for row in section.rows:
            out.append("<tr>" + "".join(_cell(c, row.get(c)) for c in section.columns) + "</tr>")
        out.append("</tbody></table></div>")
    out.append(f"</main><script>{_JS}</script></body></html>")
    return "\n".join(out)


_LINK_CLASS = {"direct": "direct", "nested": "nested", "primary group": "primary"}


def _tree_html(node: TreeNode, depth: int) -> str:
    label = f'<span class="tn">{escape(node.name)}</span>'
    if node.link:
        label += f' <span class="pill {_LINK_CLASS.get(node.link, "")}">{escape(node.link)}</span>'
    if node.type and node.type != "group":
        label += f' <span class="tk">{escape(node.type)}</span>'
    if node.disabled:
        label += ' <span class="yes">disabled</span>'
    if node.note:
        label += f' <span class="tnote">({escape(node.note)})</span>'
    label = f'<span title="{escape(node.dn)}">{label}</span>'
    if not node.children:
        return f'<li class="leaf">{label}</li>'
    children = "".join(_tree_html(c, depth + 1) for c in node.children)
    return f"<li><details{' open' if depth < 2 else ''}><summary>{label}</summary><ul>{children}</ul></details></li>"


def _cell(column: str, value: Any) -> str:
    text = escape(_text(value))
    data = f' data-v="{escape(json.dumps([_text(v) for v in value]))}"' if isinstance(value, list) else ""
    if column == "membership" or column.endswith(" via"):
        cls = {"direct": "direct", "nested": "nested", "primary group": "primary"}.get(_text(value), "")
        return f'<td><span class="pill {cls}">{text}</span></td>'
    if column == "disabled":
        return f'<td class="{"yes" if value else ""}">{text}</td>'
    if column == "dn":
        return f'<td class="dn">{text}</td>'
    return f"<td{data}>{text}</td>"
