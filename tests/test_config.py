import pytest

from adtools import config
from adtools.config import ConfigError, Settings, domain_to_dn, find_env_file, load_settings, parse_env_file


@pytest.fixture
def env_file(tmp_path):
    path = tmp_path / ".env"
    path.write_text(
        "# comment\n"
        "AD_SERVER=dc1.corp.example.com, dc2.corp.example.com\n"
        "export AD_DOMAIN=corp.example.com\n"
        'AD_BIND_USER="svc-ldap@corp.example.com"   # inline\n'
        "AD_PORT=3269  # global catalog\n"
        "AD_GLOBAL_CATALOG=true\n"
        "AD_PAGE_SIZE='250'\n"
        "AD_TIMEOUT=2.5\n"
        "AD_EMPTY=   # unset\n"
        "not a line\n"
        "\n"
    )
    return path


def test_parse_env_file(env_file):
    values = parse_env_file(env_file)
    assert values["AD_SERVER"] == "dc1.corp.example.com, dc2.corp.example.com"
    assert values["AD_DOMAIN"] == "corp.example.com"
    assert values["AD_BIND_USER"] == "svc-ldap@corp.example.com"
    assert values["AD_PORT"] == "3269"
    assert values["AD_PAGE_SIZE"] == "250"
    assert values["AD_EMPTY"] == ""


def test_env_example_parses():
    from pathlib import Path

    values = parse_env_file(Path(__file__).parent.parent / ".env.example")
    assert values["AD_SERVER"] == "dc1.corp.example.com,dc2.corp.example.com"
    assert values["AD_TRUST"] == "auto" and "AD_PASSWORD" not in values
    s = load_settings(env_file=Path(__file__).parent.parent / ".env.example", environ={}).validate()
    assert s.search_base == "DC=corp,DC=example,DC=com" and s.effective_port == 636


def test_parse_double_quote_escapes(tmp_path):
    p = tmp_path / ".env"
    p.write_text('A="x\\"y\\\\z"\nB=\'raw\\n\'\n')
    assert parse_env_file(p) == {"A": 'x"y\\z', "B": "raw\\n"}


def test_precedence_kwargs_env_file_defaults(env_file):
    environ = {"AD_DOMAIN": "env.example.com"}
    s = load_settings(env_file=env_file, environ=environ, page_size=10)
    assert s.page_size == 10  # kwarg
    assert s.domain == "env.example.com"  # process environment beats .env
    assert s.servers == ["dc1.corp.example.com", "dc2.corp.example.com"]  # .env
    assert s.port == 3269 and s.global_catalog is True and s.timeout == 2.5
    assert s.tls_mode == "ldaps" and s.reports_dir == "reports"  # defaults


def test_none_kwargs_fall_through(env_file):
    s = load_settings(env_file=env_file, environ={}, server=None)
    assert s.servers[0] == "dc1.corp.example.com"


def test_env_file_from_environment(env_file):
    assert find_env_file(environ={"AD_ENV_FILE": str(env_file)}) == env_file


def test_missing_explicit_env_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        find_env_file(tmp_path / "nope.env", environ={})


def test_env_file_discovered_in_parent(tmp_path, monkeypatch, env_file):
    child = tmp_path / "a" / "b"
    child.mkdir(parents=True)
    monkeypatch.chdir(child)
    assert find_env_file(environ={}) == env_file


def test_no_env_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(config, "__file__", str(tmp_path / "pkg" / "config.py"))
    assert find_env_file(environ={}) is None


def test_unknown_kwarg():
    with pytest.raises(TypeError, match="unknown setting"):
        load_settings(environ={}, env_file=None, servr="x")


def test_bad_number(tmp_path):
    with pytest.raises(ConfigError, match="AD_PORT"):
        load_settings(environ={"AD_PORT": "abc", "AD_ENV_FILE": ""}, env_file=None)


def test_domain_and_base():
    assert domain_to_dn("corp.example.com.") == "DC=corp,DC=example,DC=com"
    assert Settings(domain="corp.example.com").search_base == "DC=corp,DC=example,DC=com"
    assert Settings(base_dn="OU=x,DC=y", domain="z.com").search_base == "OU=x,DC=y"
    assert Settings(global_catalog=True).search_base == ""
    with pytest.raises(ConfigError):
        _ = Settings().search_base


@pytest.mark.parametrize(
    ("kwargs", "port"),
    [
        ({}, 636),
        ({"tls_mode": "starttls"}, 389),
        ({"global_catalog": True}, 3269),
        ({"global_catalog": True, "tls_mode": "starttls"}, 3268),
        ({"port": 1636}, 1636),
    ],
)
def test_effective_port(kwargs, port):
    assert Settings(**kwargs).effective_port == port


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"server": "dc", "tls_mode": "plain"},
        {"server": "dc", "trust": "none"},
        {"server": "dc", "port": 70000},
        {"server": "dc", "timeout": 0},
        {"server": "dc", "page_size": -1},
    ],
)
def test_validate(kwargs):
    with pytest.raises(ConfigError):
        Settings(**kwargs).validate()


def test_password_is_never_a_setting(tmp_path):
    with pytest.raises(ConfigError, match="never stored"):
        load_settings(environ={"AD_PASSWORD": "hunter2"})
    p = tmp_path / ".env"
    p.write_text("AD_SERVER=dc\nAD_PASSWORD=hunter2\n")
    with pytest.raises(ConfigError, match="never stored") as excinfo:
        load_settings(env_file=p, environ={})
    assert "hunter2" not in str(excinfo.value)
    with pytest.raises(TypeError, match="unknown setting"):
        load_settings(environ={}, password="hunter2")


@pytest.mark.parametrize(
    ("bind_user", "bind_domain", "expected"),
    [
        ("", "", ""),
        ("svc@corp.example.com", "", "svc@corp.example.com"),
        ("svc@corp.example.com", "CORP", "svc@corp.example.com"),  # already qualified: UPN
        ("OTHER\\svc", "CORP", "OTHER\\svc"),  # already qualified: down-level
        ("CN=svc,OU=Svc,DC=corp", "CORP", "CN=svc,OU=Svc,DC=corp"),  # already qualified: DN
        ("svc", "CORP", "CORP\\svc"),  # bare name gets the prefix
        ("svc", "CORP\\", "CORP\\svc"),  # trailing backslash tolerated
        ("", "CORP", "CORP\\posixuser"),  # local login name
    ],
)
def test_effective_bind_user(monkeypatch, bind_user, bind_domain, expected):
    monkeypatch.setattr(config.getpass, "getuser", lambda: "posixuser")
    assert Settings(bind_user=bind_user, bind_domain=bind_domain).effective_bind_user == expected


def test_bind_domain_from_env_file(tmp_path, monkeypatch):
    monkeypatch.setattr(config.getpass, "getuser", lambda: "jdoe")
    p = tmp_path / ".env"
    p.write_text("AD_SERVER=dc\nAD_BIND_DOMAIN=CORP\n")
    assert load_settings(env_file=p, environ={}).validate().effective_bind_user == "CORP\\jdoe"


def test_bind_domain_unknown_local_user(monkeypatch):
    def fail():
        raise OSError("No username set in the environment")

    monkeypatch.setattr(config.getpass, "getuser", fail)
    with pytest.raises(ConfigError, match="local user name is unknown"):
        _ = Settings(bind_domain="CORP").effective_bind_user


@pytest.mark.parametrize("domain", ["corp.example.com@x", "A\\B", "CORP CO", "DC=corp"])
def test_bind_domain_validation(domain):
    with pytest.raises(ConfigError, match="NetBIOS"):
        Settings(server="dc", bind_domain=domain).validate()
