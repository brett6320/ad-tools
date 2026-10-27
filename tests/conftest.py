import os

import pytest


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch, tmp_path_factory):
    """Keep a developer's real AD_* variables and .env files out of the tests."""
    for key in list(os.environ):
        if key.startswith("AD_"):
            monkeypatch.delenv(key)
    empty = tmp_path_factory.getbasetemp() / "empty.env"
    empty.write_text("")
    monkeypatch.setenv("AD_ENV_FILE", str(empty))
