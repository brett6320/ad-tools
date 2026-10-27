"""Exercise the HTML report's filters and tree in a real headless Chrome, when one is installed."""

import html
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from adtools.report import group_members_report, user_groups_report, write_report

from .fakedir import FakeADClient, sample_directory

HARNESS = (Path(__file__).parent / "fixtures" / "report_harness.js").read_text()
CANDIDATES = [
    os.environ.get("CHROME_BIN", ""),
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    *(shutil.which(n) or "" for n in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome")),
]
CHROME = next((c for c in CANDIDATES if c and Path(c).is_file()), None)
pytestmark = pytest.mark.skipif(CHROME is None, reason="Chrome/Chromium not installed")


def run_harness(report, tmp_path) -> dict:
    page = write_report(report, tmp_path)[0]
    page.write_text(page.read_text().replace("</body>", f"<script>{HARNESS}</script></body>"))
    result = subprocess.run(
        [
            CHROME,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--no-first-run",
            f"--user-data-dir={tmp_path / 'profile'}",
            "--virtual-time-budget=3000",
            "--dump-dom",
            page.as_uri(),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    match = re.search(r'<pre id="harness">(.*?)</pre>', result.stdout, re.S)
    assert match, f"harness produced no output: {result.stderr[-2000:]}"
    out = {}
    for line in html.unescape(match.group(1)).splitlines():
        key, value = line.split("=", 1)
        out[key] = json.loads(value)
    assert "ERROR" not in out, out.get("ERROR")
    return out


def test_user_groups_filters_and_tree(tmp_path):
    out = run_harness(user_groups_report(FakeADClient(sample_directory()).user_groups("jdoe")), tmp_path)
    assert out["initial_status"] == "5 rows"
    assert out["values"] == ["(Select all)", "direct2", "nested2", "primary group1"]  # distinct values + counts
    assert out["selectall_indeterminate"] is True
    assert sorted(out["after_membership_filter"]) == ["All Staff", "Domain Users", "Remote Access"]
    assert out["status"] == "Showing 3 of 5 rows" and out["header_on"] is True and out["pop_closed"] is True
    # Value lists reflect the other columns' filters; multi-valued cells are split.
    assert out["via_values"] == ["(Select all)", "(Blanks)1", "Domain Users1", "Engineering1"]
    assert out["via_search"] == ["(Select all search results)", "Engineering1"]
    assert out["after_two_filters"] == ["All Staff"]
    assert out["sorted_desc_aria"] == "descending"
    assert len(out["after_clear"]) == 5 and out["clear_hidden"] is True
    assert out["quick"] == ["All Staff"]
    assert out["scripts"] == 2  # the report's own script and the harness; nothing injected
    assert out["tree_details"] == 3 and out["tree_open_after_collapse"] == 0 and out["tree_open_after_expand"] == 3


def test_group_members_filters_and_tree(tmp_path):
    out = run_harness(group_members_report(FakeADClient(sample_directory()).group_members("VPN Users")), tmp_path)
    assert out["values"] == ["(Select all)", "direct2", "nested3"]
    assert sorted(out["after_membership_filter"]) == ["Platform", "asmith", "olduser"]
    assert out["tree_text"].startswith("VPN UsersEngineering direct")
