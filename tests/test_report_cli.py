import json

import pytest

from adtools import ad as ad_module
from adtools import cli
from adtools.ldap import LDAPError
from adtools.report import (
    compare_report,
    group_members_report,
    render_csv,
    render_html,
    render_text,
    search_report,
    slugify,
    user_groups_report,
    write_report,
)

from .fakedir import FakeADClient, sample_directory


@pytest.fixture
def fake():
    return FakeADClient(sample_directory())


def test_user_groups_html(fake, tmp_path):
    report = user_groups_report(fake.user_groups("jdoe"))
    paths = write_report(report, tmp_path, ("html", "json", "csv"))
    assert [p.parent.name for p in paths] == ["user-groups"] * 3
    assert paths[0].name.endswith("_jdoe.html")
    html = paths[0].read_text()
    assert "<title>Group memberships of jdoe</title>" in html
    assert 'class="pill nested">nested' in html and "All Staff" in html
    data = json.loads(paths[1].read_text())
    assert data["summary"]["Total"] == 5
    assert "section,name" in paths[2].read_text().splitlines()[0]


def test_html_escapes_directory_content(fake):
    fake.directory.group("<script>alert(1)</script>", 3000, members=["CN=jdoe,OU=Users,DC=corp,DC=example,DC=com"])
    html = render_html(user_groups_report(fake.user_groups("jdoe")))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_members_and_compare_reports(fake):
    members = group_members_report(fake.group_members("VPN Users"))
    assert dict(members.summary)["Users"] == 3
    text = render_text(members)
    assert "Members of VPN Users" in text and "olduser" in text

    comparison = compare_report(fake.compare_users("jdoe", "asmith"))
    assert comparison.kind == "compare" and comparison.slug == "jdoe_vs_asmith"
    titles = [s.title for s in comparison.sections]
    assert titles == ["Only jdoe", "Only asmith", "In common"]
    assert "jdoe via" in comparison.sections[2].columns
    html = render_html(comparison)
    assert "Only jdoe (0)" in html and "Only asmith (1)" in html and "In common (5)" in html


def test_empty_section_html(fake):
    report = compare_report(fake.compare_users("jdoe", "jdoe"))
    assert '<div class="empty">None</div>' in render_html(report)


def test_search_report_columns(fake):
    objs = list(fake.search("(objectClass=group)", ["cn"]))
    report = search_report("(objectClass=group)", "DC=x", objs, [])
    assert report.sections[0].columns[0] == "dn" and "cn" in report.sections[0].columns


def test_csv_formula_injection_neutralized(fake):
    fake.directory.objects["CN=jdoe,OU=Users,DC=corp,DC=example,DC=com"]["description"] = [b"=HYPERLINK(1)"]
    csv_text = render_csv(group_members_report(fake.group_members("VPN Users")))
    assert "'=HYPERLINK(1)" in csv_text


def test_slugify_and_formats(tmp_path):
    assert slugify("../../etc/passwd") == "etc-passwd"
    assert slugify("***") == "report"
    with pytest.raises(ValueError):
        write_report(search_report("x", "y", [], []), tmp_path, ("pdf",))


# --- CLI -------------------------------------------------------------------------


@pytest.fixture
def cli_env(monkeypatch, tmp_path, fake):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AD_ENV_FILE", str(tmp_path / ".env"))
    (tmp_path / ".env").write_text("AD_SERVER=dc.test\nAD_DOMAIN=corp.example.com\nAD_BIND_USER=svc@corp\n")

    class Client:
        def __init__(self, settings):
            self.settings = settings
            fake.settings = settings

        def __enter__(self):
            return fake

        def __exit__(self, *exc):
            return None

    monkeypatch.setattr(cli, "ADClient", Client)
    return tmp_path


def test_cli_groups_default_html(cli_env, capsys):
    assert cli.main(["groups", "john.doe@corp.example.com"]) == 0
    out = capsys.readouterr().out.strip().replace("\\", "/")  # Windows prints native separators
    assert out.startswith("reports/user-groups/") and out.endswith("_jdoe.html")
    assert (cli_env / out).is_file()


def test_cli_members_compare_search(cli_env, capsys):
    assert cli.main(["members", "VPN Users", "--direct-only", "--format", "json,csv", "--stdout"]) == 0
    out = capsys.readouterr().out.replace("\\", "/")
    assert "group-members/" in out and ".json" in out and ".csv" in out and "Members of VPN Users" in out
    assert cli.main(["compare", "jdoe", "asmith", "--reports-dir", "out"]) == 0
    assert "out/compare/" in capsys.readouterr().out.replace("\\", "/")
    assert cli.main(["search", "(objectClass=group)", "--attrs", "*"]) == 0
    assert "reports/search/" in capsys.readouterr().out.replace("\\", "/")


def test_cli_errors(cli_env, capsys, caplog):
    assert cli.main(["groups", "nobody"]) == 2
    assert "no match" in caplog.text
    assert cli.main(["groups", "jdoe", "--format", "pdf"]) == 2
    assert cli.main(["search", "(bad"]) == 2


def test_cli_rejects_stored_password(cli_env, caplog):
    (cli_env / ".env").write_text("AD_SERVER=dc.test\nAD_DOMAIN=corp.example.com\nAD_PASSWORD=pw\n")
    assert cli.main(["groups", "jdoe"]) == 2
    assert "never stored" in caplog.text


# --- ADClient connection handling ----------------------------------------------------


class FakeConn:
    opened: list[str] = []

    def __init__(self, host, port, mode, ctx, timeout):
        self.host, self.port, self._sock = host, port, None

    def open(self):
        FakeConn.opened.append(f"{self.host}:{self.port}")
        if self.host == "down":
            raise OSError("connection refused")
        if self.host == "badpw":
            self._sock = object()
            return self
        self._sock = object()
        return self

    binds: list[tuple[str, str]] = []

    def bind(self, user, password):
        FakeConn.binds.append((user, password))
        if self.host == "badpw":
            raise LDAPError("bind failed: invalidCredentials", 49)

    def close(self):
        self._sock = None


class Prompts:
    def __init__(self):
        self.asked = []

    def append_and_return(self, prompt):
        self.asked.append(prompt)
        return "typed"


def test_client_failover(monkeypatch):
    prompts = Prompts()
    FakeConn.opened = []
    monkeypatch.setattr(ad_module, "LDAPConnection", FakeConn)
    client = ad_module.ADClient(
        server="down,up",
        domain="corp.example.com",
        bind_user="u",
        ssl_context=object(),
        password_prompt=prompts.append_and_return,
    )
    with client:
        assert client.connection.host == "up"
    assert FakeConn.opened == ["down:636", "up:636"]
    assert prompts.asked == ["Password for u: "]  # prompted once, reused across failover
    assert FakeConn.binds[-1] == ("u", "typed")
    assert not any("typed" in repr(v) for v in vars(client).values())  # not kept on the client


def test_client_auth_failure_does_not_fail_over(monkeypatch):
    FakeConn.opened = []
    monkeypatch.setattr(ad_module, "LDAPConnection", FakeConn)
    client = ad_module.ADClient(
        server="badpw,up", domain="x.com", bind_user="u", ssl_context=object(), password_prompt=lambda p: "wrong"
    )
    with pytest.raises(LDAPError, match="invalidCredentials"):
        client.connect()
    assert FakeConn.opened == ["badpw:636"]


def test_client_all_down(monkeypatch):
    monkeypatch.setattr(ad_module, "LDAPConnection", FakeConn)
    client = ad_module.ADClient(server="down", domain="x.com", ssl_context=object())
    with pytest.raises(LDAPError, match="any server"):
        client.connect()


def test_client_prompts_on_terminal(monkeypatch):
    monkeypatch.setattr(ad_module, "LDAPConnection", FakeConn)
    monkeypatch.setattr(ad_module.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(ad_module.getpass, "getpass", lambda prompt: "from-tty")
    with ad_module.ADClient(server="up", domain="x.com", bind_user="u", ssl_context=object()):
        assert FakeConn.binds[-1] == ("u", "from-tty")


def test_client_refuses_without_terminal(monkeypatch):
    monkeypatch.setattr(ad_module.sys.stdin, "isatty", lambda: False, raising=False)
    client = ad_module.ADClient(server="dc", domain="x.com", bind_user="u", ssl_context=object())
    with pytest.raises(ad_module.ConfigError, match="interactive terminal"):
        client.connect()


def test_client_empty_password(monkeypatch):
    client = ad_module.ADClient(server="dc", domain="x.com", bind_user="u", ssl_context=object(), password_prompt=lambda p: "")
    with pytest.raises(ad_module.ConfigError, match="no password"):
        client.connect()


def test_anonymous_bind_does_not_prompt(monkeypatch):
    monkeypatch.setattr(ad_module, "LDAPConnection", FakeConn)

    def never(prompt):
        raise AssertionError("prompted")

    with ad_module.ADClient(server="up", domain="x.com", ssl_context=object(), password_prompt=never):
        assert FakeConn.binds[-1] == ("", "")


def test_client_binds_with_domain_prefix_and_posix_user(monkeypatch):
    from adtools import config

    monkeypatch.setattr(ad_module, "LDAPConnection", FakeConn)
    monkeypatch.setattr(config.getpass, "getuser", lambda: "jdoe")
    asked = []
    client = ad_module.ADClient(
        server="up", domain="x.com", bind_domain="CORP", ssl_context=object(), password_prompt=lambda p: asked.append(p) or "pw"
    )
    with client:
        assert FakeConn.binds[-1] == ("CORP\\jdoe", "pw")
    assert asked == ["Password for CORP\\jdoe: "]


def test_cli_bind_domain_flag(cli_env, monkeypatch):
    seen = {}
    real = cli.ADClient

    def capture(settings):
        seen["user"] = settings.effective_bind_user
        return real(settings)

    monkeypatch.setattr(cli, "ADClient", capture)
    (cli_env / ".env").write_text("AD_SERVER=dc.test\nAD_DOMAIN=corp.example.com\n")
    assert cli.main(["groups", "jdoe", "--bind-domain", "CORP", "--bind-user", "alice"]) == 0
    assert seen["user"] == "CORP\\alice"


def test_client_discovers_dcs_when_no_server(monkeypatch):
    seen = {}

    def fake_discover(domain, site, global_catalog, nameservers, timeout):
        seen.update(domain=domain, site=site, gc=global_catalog, ns=nameservers)
        return ["down", "up"]

    FakeConn.opened = []
    monkeypatch.setattr(ad_module, "LDAPConnection", FakeConn)
    monkeypatch.setattr(ad_module, "discover_domain_controllers", fake_discover)
    client = ad_module.ADClient(domain="corp.example.com", site="HQ", dns_server="10.0.0.10, 10.0.0.11", ssl_context=object())
    with client:
        assert client.connection.host == "up"
    assert seen == {"domain": "corp.example.com", "site": "HQ", "gc": False, "ns": ["10.0.0.10", "10.0.0.11"]}
    assert FakeConn.opened == ["down:636", "up:636"]


def test_explicit_server_skips_discovery(monkeypatch):
    monkeypatch.setattr(ad_module, "discover_domain_controllers", lambda *a, **k: pytest.fail("discovered"))
    assert ad_module.ADClient(server="dc9", domain="corp.example.com").server_candidates() == ["dc9"]


def test_needs_server_or_domain():
    with pytest.raises(ad_module.ConfigError, match="AD_DOMAIN to find"):
        ad_module.ADClient()
    with pytest.raises(ad_module.ConfigError, match="AD_SITE"):
        ad_module.ADClient(domain="x.com", site="bad site")


def test_cli_always_shows_the_server(cli_env, capsys):
    assert cli.main(["groups", "jdoe", "--format", "json"]) == 0
    captured = capsys.readouterr()
    assert captured.err.strip() == "Querying dc.test:636 (LDAPS, TLSv1.3)"
    assert "Querying" not in captured.out  # stdout stays report paths only
    path = cli_env / captured.out.strip()
    assert json.loads(path.read_text())["summary"]["Server"] == "dc.test:636 (LDAPS, TLSv1.3)"


def test_cli_debug_shows_traceback(cli_env, caplog):
    assert cli.main(["groups", "nobody", "--debug"]) == 2
    record = next(r for r in caplog.records if r.levelname == "ERROR")
    assert record.exc_info is not None
    assert ad_module.logging.getLogger("adtools").level == ad_module.logging.DEBUG


def test_cli_debug_from_env_file(cli_env, caplog):
    (cli_env / ".env").write_text("AD_SERVER=dc.test\nAD_DOMAIN=corp.example.com\nAD_DEBUG=true\n")
    assert cli.main(["groups", "nobody"]) == 2
    assert next(r for r in caplog.records if r.levelname == "ERROR").exc_info is not None


def test_cli_default_error_has_no_traceback(cli_env, caplog):
    assert cli.main(["groups", "nobody"]) == 2
    assert next(r for r in caplog.records if r.levelname == "ERROR").exc_info is None
    assert ad_module.logging.getLogger("adtools").level == ad_module.logging.WARNING


def test_server_label_and_failover_warning(monkeypatch, caplog):
    class TLSConn(FakeConn):
        tls_mode = "ldaps"
        tls_version = "TLSv1.3"

    monkeypatch.setattr(ad_module, "LDAPConnection", TLSConn)
    with ad_module.ADClient(server="down,up", domain="x.com", ssl_context=object()) as client:
        assert client.server == "up:636 (LDAPS, TLSv1.3)"
    assert "down:636 failed: connection refused" in caplog.text


def test_client_search_sends_time_limit_below_client_timeout(monkeypatch):
    seen = {}

    class Conn:
        _sock = object()

        def search(self, base, f, attrs, **kw):
            seen.update(kw)
            return iter(())

    client = ad_module.ADClient(server="dc", domain="x.com", timeout=90, connection=Conn())
    list(client.search("(cn=x)"))
    assert seen["time_limit"] == 89
    client = ad_module.ADClient(server="dc", domain="x.com", timeout=1.5, connection=Conn())
    list(client.search("(cn=x)"))
    assert seen["time_limit"] == 0
