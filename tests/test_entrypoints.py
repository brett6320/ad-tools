"""Entry point scripts must be executable (in git, so the bit survives a clone) and must run."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GIT = shutil.which("git")


def tracked_modes() -> dict[str, str]:
    if GIT is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    out = subprocess.run([GIT, "ls-files", "-s"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    modes = {}
    for line in out.splitlines():
        meta, path = line.split("\t", 1)
        modes[path] = meta.split()[0]
    return modes


def test_launcher_is_tracked_as_executable():
    assert tracked_modes().get("ad-query") == "100755"


def test_every_shebang_script_is_executable():
    not_executable = [
        path
        for path, mode in tracked_modes().items()
        if (ROOT / path).is_file() and (ROOT / path).read_bytes()[:2] == b"#!" and mode != "100755"
    ]
    assert not_executable == [], f"chmod +x and `git update-index --chmod=+x` these: {not_executable}"


def test_launcher_runs_from_another_directory(tmp_path):
    result = subprocess.run(
        [sys.executable, str(ROOT / "ad-query"), "--version"], cwd=tmp_path, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("ad-query ")


def test_module_entrypoint_runs(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "adtools", "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )
    assert result.returncode == 0, result.stderr
    assert "groups" in result.stdout
