"""Settings resolution: keyword arguments, then environment, then a ``.env`` file, then defaults.

The ``.env`` file is found by, in order: an explicit ``env_file`` argument, the
``AD_ENV_FILE`` environment variable, then the first ``.env`` in the current
directory or any parent, then the first ``.env`` in this package's directory or any
parent (such as the repository root). The ``.env`` file never overrides variables
already set in the process environment, and it is never written to ``os.environ``.

Passwords are deliberately not a setting: ``AD_PASSWORD`` in the environment or the
``.env`` file is rejected, and ``ADClient`` prompts for the password when it connects.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, fields
from pathlib import Path

from .ldap import TLS_MODES
from .tls import TRUST_MODES

ENV_PREFIX = "AD_"

# Passwords are never read from configuration; they are always prompted for.
FORBIDDEN_PASSWORD_KEY = "AD_PASSWORD"  # noqa: S105  # nosec B105

_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


class ConfigError(ValueError):
    """Raised for missing or invalid settings."""


@dataclass
class Settings:
    """Connection settings. Each field maps to an ``AD_<FIELD>`` variable."""

    server: str = ""  # one host or a comma-separated list, tried in order
    port: int = 0  # 0 = default for the TLS mode (636 LDAPS / 389 StartTLS, or 3269 / 3268 with gc)
    tls_mode: str = "ldaps"
    global_catalog: bool = False
    domain: str = ""  # DNS domain, e.g. corp.example.com; derives base_dn when that is unset
    base_dn: str = ""
    bind_user: str = ""  # DN, UPN (user@corp.example.com) or CORP\\user; empty = anonymous
    trust: str = "auto"
    ca_file: str = ""
    ca_path: str = ""
    client_cert: str = ""
    client_key: str = ""
    timeout: float = 10.0
    page_size: int = 500
    reports_dir: str = "reports"

    @property
    def servers(self) -> list[str]:
        return [s.strip() for s in self.server.split(",") if s.strip()]

    @property
    def effective_port(self) -> int:
        if self.port:
            return self.port
        if self.global_catalog:
            return 3269 if self.tls_mode == "ldaps" else 3268
        return 636 if self.tls_mode == "ldaps" else 389

    @property
    def search_base(self) -> str:
        if self.base_dn:
            return self.base_dn
        if self.domain:
            return domain_to_dn(self.domain)
        if self.global_catalog:
            return ""  # the GC root covers the whole forest
        raise ConfigError("set AD_BASE_DN or AD_DOMAIN")

    def validate(self) -> Settings:
        if not self.servers:
            raise ConfigError("no server configured; set AD_SERVER or pass server=")
        if self.tls_mode not in TLS_MODES:
            raise ConfigError(f"AD_TLS_MODE must be one of {', '.join(TLS_MODES)}")
        if self.trust.lower() not in TRUST_MODES:
            raise ConfigError(f"AD_TRUST must be one of {', '.join(TRUST_MODES)}")
        if not 0 <= self.port <= 65535:
            raise ConfigError("AD_PORT must be between 0 and 65535")
        if self.timeout <= 0:
            raise ConfigError("AD_TIMEOUT must be positive")
        if self.page_size < 0:
            raise ConfigError("AD_PAGE_SIZE must not be negative")
        return self


def domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={label}" for label in domain.strip(".").split(".") if label)


def parse_env_file(path: str | os.PathLike[str]) -> dict[str, str]:
    """Parse a ``.env`` file: ``KEY=value`` lines, ``#`` comments, optional quotes and ``export``."""
    values: dict[str, str] = {}
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        match = _LINE.match(raw)
        if not match:
            continue
        key, value = match.groups()
        quoted = re.match(r"""^(["'])(.*)\1(?:\s+#.*)?$""", value)
        if quoted:
            quote, value = quoted.groups()
            if quote == '"':
                value = value.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")
        else:
            value = "" if value.startswith("#") else re.split(r"\s+#", value, maxsplit=1)[0].rstrip()  # inline comment
        values[key] = value
    return values


def find_env_file(env_file: str | os.PathLike[str] | None = None, environ: Mapping[str, str] | None = None) -> Path | None:
    environ = os.environ if environ is None else environ
    explicit = env_file or environ.get("AD_ENV_FILE")
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise ConfigError(f".env file not found: {path}")
        return path
    for start in (Path.cwd(), Path(__file__).resolve().parent):
        for directory in (start, *start.parents):
            candidate = directory / ".env"
            if candidate.is_file():
                return candidate
    return None


def load_settings(
    env_file: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
    **overrides: object,
) -> Settings:
    """Build ``Settings``; keyword arguments that are not ``None`` win over everything else."""
    environ = os.environ if environ is None else environ
    path = find_env_file(env_file, environ)
    file_values = parse_env_file(path) if path else {}
    for source, values in (("the environment", environ), (str(path), file_values)):
        if FORBIDDEN_PASSWORD_KEY in values:
            raise ConfigError(
                f"{FORBIDDEN_PASSWORD_KEY} found in {source}: LDAP passwords are never stored; "
                "remove it, you will be prompted at connect time"
            )

    settings = Settings()
    known = {f.name: f for f in fields(Settings)}
    unknown = set(overrides) - set(known)
    if unknown:
        raise TypeError(f"unknown setting(s): {', '.join(sorted(unknown))}")
    for name, f in known.items():
        key = ENV_PREFIX + name.upper()
        if overrides.get(name) is not None:
            value: object = overrides[name]
        elif key in environ:
            value = environ[key]
        elif key in file_values:
            value = file_values[key]
        else:
            continue
        setattr(settings, name, _coerce(name, f.type, value))
    return settings


def _coerce(name: str, type_name: object, value: object) -> object:
    if not isinstance(value, str):
        return value
    try:
        if type_name in (int, "int"):
            return int(value) if value.strip() else 0
        if type_name in (float, "float"):
            return float(value)
        if type_name in (bool, "bool"):
            return value.strip().lower() in ("1", "true", "yes", "on")
    except ValueError:
        raise ConfigError(f"invalid value for AD_{name.upper()}: {value!r}") from None
    return value
