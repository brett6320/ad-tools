"""Active Directory queries: principals, group memberships (direct and nested) and comparisons."""

from __future__ import annotations

import base64
import getpass
import logging
import ssl
import struct
import sys
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .config import ConfigError, Settings, load_settings
from .filters import escape_filter_value
from .ldap import Entry, LDAPConnection, LDAPError
from .tls import build_ssl_context

log = logging.getLogger(__name__)

# LDAP_MATCHING_RULE_IN_CHAIN: walks the member/memberOf chain transitively on the DC.
IN_CHAIN = "1.2.840.113556.1.4.1941"

UF_ACCOUNTDISABLE = 0x2

GROUP_TYPE_SYSTEM = 0x1
GROUP_TYPE_GLOBAL = 0x2
GROUP_TYPE_DOMAIN_LOCAL = 0x4
GROUP_TYPE_UNIVERSAL = 0x8
GROUP_TYPE_SECURITY = 0x80000000

GROUP_ATTRS = ("cn", "sAMAccountName", "description", "groupType", "mail", "objectSid")
PRINCIPAL_ATTRS = (
    "cn",
    "sAMAccountName",
    "userPrincipalName",
    "mail",
    "displayName",
    "objectClass",
    "objectSid",
    "primaryGroupID",
    "userAccountControl",
    "description",
    "groupType",
)

FILETIME_ATTRS = {"lastlogon", "lastlogontimestamp", "pwdlastset", "accountexpires", "badpasswordtime", "lockouttime"}
GENERALIZED_TIME_ATTRS = {"whencreated", "whenchanged"}
SID_ATTRS = {"objectsid", "sidhistory", "securityidentifier"}
GUID_ATTRS = {"objectguid"}


class NotFoundError(LookupError):
    """No directory object matched the identity."""


class AmbiguousError(LookupError):
    """More than one directory object matched the identity."""


# --- value decoding -----------------------------------------------------------


def sid_to_str(raw: bytes) -> str:
    if len(raw) < 8:
        raise ValueError("SID too short")
    revision, count = raw[0], raw[1]
    if len(raw) != 8 + 4 * count:
        raise ValueError("SID length does not match sub-authority count")
    authority = int.from_bytes(raw[2:8], "big")
    subs = struct.unpack(f"<{count}I", raw[8:])
    return f"S-{revision}-{authority}" + "".join(f"-{s}" for s in subs)


def sid_to_bytes(sid: str) -> bytes:
    parts = sid.split("-")
    if len(parts) < 3 or parts[0].upper() != "S":
        raise ValueError(f"invalid SID {sid!r}")
    revision, authority, subs = int(parts[1]), int(parts[2]), [int(p) for p in parts[3:]]
    return bytes([revision, len(subs)]) + authority.to_bytes(6, "big") + struct.pack(f"<{len(subs)}I", *subs)


def filetime_to_datetime(value: int) -> datetime | None:
    """Convert a Windows FILETIME (100 ns ticks since 1601). 0 and 'never' return None."""
    if value <= 0 or value >= 0x7FFFFFFFFFFFFFFF:
        return None
    return datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=value // 10)


def generalized_time_to_datetime(value: str) -> datetime:
    return datetime.strptime(value.split(".")[0].rstrip("Z"), "%Y%m%d%H%M%S").replace(tzinfo=UTC)


def decode_value(attribute: str, raw: bytes) -> Any:
    name = attribute.lower().split(";")[0]
    try:
        if name in SID_ATTRS:
            return sid_to_str(raw)
        if name in GUID_ATTRS:
            return str(uuid.UUID(bytes_le=raw))
        if name in FILETIME_ATTRS:
            when = filetime_to_datetime(int(raw))
            return when.isoformat() if when else None
        if name in GENERALIZED_TIME_ATTRS:
            return generalized_time_to_datetime(raw.decode("ascii")).isoformat()
    except (ValueError, UnicodeDecodeError):
        pass
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return "base64:" + base64.b64encode(raw).decode("ascii")


def decode_entry(entry: Entry) -> dict[str, list[Any]]:
    return {name: [decode_value(name, v) for v in values] for name, values in entry.attributes.items()}


def group_type_names(group_type: int) -> tuple[str, str]:
    """Return ``(scope, kind)`` such as ``("Global", "Security")``."""
    group_type &= 0xFFFFFFFF
    if group_type & GROUP_TYPE_UNIVERSAL:
        scope = "Universal"
    elif group_type & GROUP_TYPE_DOMAIN_LOCAL:
        scope = "Domain local" if not group_type & GROUP_TYPE_SYSTEM else "Builtin local"
    elif group_type & GROUP_TYPE_GLOBAL:
        scope = "Global"
    else:
        scope = "Unknown"
    return scope, "Security" if group_type & GROUP_TYPE_SECURITY else "Distribution"


# --- result types ---------------------------------------------------------------


@dataclass
class DirectoryObject:
    dn: str
    attributes: dict[str, list[Any]] = field(default_factory=dict)

    @classmethod
    def from_entry(cls, entry: Entry) -> DirectoryObject:
        return cls(entry.dn, decode_entry(entry))

    def get(self, name: str, default: Any = "") -> Any:
        for key, values in self.attributes.items():
            if key.lower() == name.lower():
                return values[0] if values else default
        return default

    def get_all(self, name: str) -> list[Any]:
        for key, values in self.attributes.items():
            if key.lower() == name.lower():
                return values
        return []

    @property
    def name(self) -> str:
        return self.get("sAMAccountName") or self.get("cn") or self.dn

    @property
    def object_class(self) -> str:
        classes = [c.lower() for c in self.get_all("objectClass")]
        for kind in ("computer", "user", "group", "contact", "foreignsecurityprincipal"):
            if kind in classes:
                return {"foreignsecurityprincipal": "foreignSecurityPrincipal"}.get(kind, kind)
        return classes[-1] if classes else ""

    @property
    def disabled(self) -> bool:
        try:
            return bool(int(self.get("userAccountControl", 0) or 0) & UF_ACCOUNTDISABLE)
        except ValueError:
            return False


@dataclass
class Membership:
    """A group (for user lookups) or a member (for group lookups) and how it is connected."""

    obj: DirectoryObject
    direct: bool
    primary: bool = False

    @property
    def via(self) -> str:
        if self.primary:
            return "primary group"
        return "direct" if self.direct else "nested"

    def as_dict(self) -> dict[str, Any]:
        o = self.obj
        row: dict[str, Any] = {
            "name": o.name,
            "cn": o.get("cn"),
            "type": o.object_class,
            "membership": self.via,
            "mail": o.get("mail"),
            "description": o.get("description"),
            "dn": o.dn,
        }
        if o.get("groupType") != "":
            scope, kind = group_type_names(int(o.get("groupType")))
            row["scope"], row["kind"] = scope, kind
        if o.object_class in ("user", "computer"):
            row["disabled"] = o.disabled
        return row


@dataclass
class GroupsResult:
    principal: DirectoryObject
    groups: list[Membership]
    nested: bool


@dataclass
class MembersResult:
    group: DirectoryObject
    members: list[Membership]
    nested: bool


@dataclass
class CompareResult:
    first: GroupsResult
    second: GroupsResult

    def _by_dn(self, result: GroupsResult) -> dict[str, Membership]:
        return {m.obj.dn.lower(): m for m in result.groups}

    @property
    def common(self) -> list[tuple[Membership, Membership]]:
        a, b = self._by_dn(self.first), self._by_dn(self.second)
        return [(a[k], b[k]) for k in sorted(a.keys() & b.keys(), key=lambda k: a[k].obj.name.lower())]

    @property
    def only_first(self) -> list[Membership]:
        b = self._by_dn(self.second)
        return [m for m in self.first.groups if m.obj.dn.lower() not in b]

    @property
    def only_second(self) -> list[Membership]:
        a = self._by_dn(self.first)
        return [m for m in self.second.groups if m.obj.dn.lower() not in a]


# --- client ---------------------------------------------------------------------


class ADClient:
    """Query Active Directory over LDAPS or StartTLS.

    Any setting not passed as a keyword argument is read from the environment or the
    ``.env`` file (see ``adtools.config``). The bind password is never stored or
    accepted as a setting: it is prompted for on each ``connect()`` (with ``getpass``
    on an interactive terminal, or by the ``password_prompt`` callable you pass, for
    example a GUI dialog), used for the bind and then discarded. Example::

        with ADClient(server="dc1.corp.example.com", domain="corp.example.com") as ad:
            result = ad.user_groups("jdoe")
    """

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        env_file: str | None = None,
        ssl_context: ssl.SSLContext | None = None,
        connection: LDAPConnection | None = None,
        password_prompt: Callable[[str], str] | None = None,
        **kwargs: Any,
    ) -> None:
        self.settings = (settings or load_settings(env_file=env_file, **kwargs)).validate()
        self._ssl_context = ssl_context
        self._password_prompt = password_prompt
        self._conn = connection

    # connection management

    def connect(self) -> ADClient:
        if self._conn is not None and self._conn._sock is not None:
            return self
        s = self.settings
        ctx = self._ssl_context or build_ssl_context(s.trust, s.ca_file, s.ca_path, s.client_cert, s.client_key)
        user = s.effective_bind_user
        password = self._prompt_password(user) if user else ""
        try:
            return self._connect_any(ctx, user, password)
        finally:
            del password

    def _prompt_password(self, user: str) -> str:
        prompt = f"Password for {user}: "
        if self._password_prompt is not None:
            password = self._password_prompt(prompt)
        elif sys.stdin is not None and sys.stdin.isatty():
            password = getpass.getpass(prompt)
        else:
            raise ConfigError("a password prompt needs an interactive terminal (or pass password_prompt=)")
        if not password:
            raise ConfigError("no password entered")
        return password

    def _connect_any(self, ctx: ssl.SSLContext, user: str, password: str) -> ADClient:
        s = self.settings
        errors = []
        for host in s.servers:
            conn = LDAPConnection(host, s.effective_port, s.tls_mode, ctx, s.timeout)
            try:
                conn.open()
                conn.bind(user, password)
            except LDAPError as exc:
                conn.close()
                if exc.code is not None:  # the server answered: credentials or policy, not reachability
                    raise
                errors.append(f"{host}: {exc}")
            except (OSError, ssl.SSLError) as exc:
                conn.close()
                errors.append(f"{host}: {exc}")
            else:
                self._conn = conn
                return self
        raise LDAPError("could not connect to any server: " + "; ".join(errors))

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> ADClient:
        return self.connect()

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def connection(self) -> LDAPConnection:
        if self._conn is None:
            self.connect()
        if self._conn is None:  # pragma: no cover - connect() either sets it or raises
            raise LDAPError("not connected")
        return self._conn

    # generic search

    def search(
        self,
        search_filter: str,
        attributes: list[str] | tuple[str, ...] = (),
        base: str | None = None,
        scope: str = "sub",
        size_limit: int = 0,
    ) -> Iterator[DirectoryObject]:
        base = self.settings.search_base if base is None else base
        for entry in self.connection.search(
            base, search_filter, attributes, scope=scope, size_limit=size_limit, page_size=self.settings.page_size
        ):
            yield DirectoryObject.from_entry(entry)

    # lookups

    def find_principal(
        self, identity: str, object_filter: str = "(|(objectCategory=person)(objectClass=computer))"
    ) -> DirectoryObject:
        """Find one user (or computer) by sAMAccountName, email address, UPN, DOMAIN\\name or DN."""
        return self._find_one(identity, object_filter, by_mail=True)

    def find_group(self, identity: str) -> DirectoryObject:
        """Find one group by sAMAccountName, cn, email address or DN."""
        return self._find_one(identity, "(objectClass=group)", by_mail=True, by_cn=True)

    def _find_one(self, identity: str, object_filter: str, by_mail: bool = False, by_cn: bool = False) -> DirectoryObject:
        identity = identity.strip()
        if not identity:
            raise ValueError("identity must not be empty")
        if _looks_like_dn(identity):
            try:
                matches = list(self.search(object_filter, PRINCIPAL_ATTRS, base=identity, scope="base"))
            except LDAPError as exc:
                if exc.code == 32:  # noSuchObject
                    raise NotFoundError(f"no object with DN {identity!r}") from None
                raise
        else:
            value = escape_filter_value(identity.split("\\", 1)[-1])
            clauses = [f"(sAMAccountName={value})"]
            if "@" in identity and by_mail:
                clauses += [f"(mail={value})", f"(userPrincipalName={value})", f"(proxyAddresses=smtp:{value})"]
            if by_cn:
                clauses.append(f"(cn={value})")
            matches = list(self.search(f"(&{object_filter}(|{''.join(clauses)}))", PRINCIPAL_ATTRS, size_limit=0))
        if not matches:
            raise NotFoundError(f"no match for {identity!r}")
        unique = {m.dn.lower(): m for m in matches}
        if len(unique) > 1:
            names = ", ".join(sorted(m.dn for m in unique.values()))
            raise AmbiguousError(f"{identity!r} matches {len(unique)} objects: {names}")
        return next(iter(unique.values()))

    def _primary_group(self, principal: DirectoryObject) -> DirectoryObject | None:
        rid, sid = principal.get("primaryGroupID"), principal.get("objectSid")
        if not rid or not sid or not str(sid).startswith("S-"):
            return None
        domain_sid = sid.rsplit("-", 1)[0]
        value = escape_filter_value(sid_to_bytes(f"{domain_sid}-{int(rid)}"))
        found = list(self.search(f"(&(objectClass=group)(objectSid={value}))", GROUP_ATTRS))
        return found[0] if found else None

    # memberships

    def user_groups(self, identity: str, nested: bool = True) -> GroupsResult:
        """Groups a user is a member of: direct, nested (transitive) and the primary group."""
        principal = self.find_principal(identity)
        dn = escape_filter_value(principal.dn)
        direct = {g.dn.lower(): g for g in self.search(f"(&(objectClass=group)(member={dn}))", GROUP_ATTRS)}
        primary = self._primary_group(principal)
        groups = [Membership(g, direct=True) for g in direct.values()]
        if primary is not None and primary.dn.lower() not in direct:
            groups.append(Membership(primary, direct=True, primary=True))
        if nested:
            seen = {m.obj.dn.lower() for m in groups}
            chains = [f"(member:{IN_CHAIN}:={dn})"]
            if primary is not None:
                chains.append(f"(member:{IN_CHAIN}:={escape_filter_value(primary.dn)})")
            for g in self.search(f"(&(objectClass=group)(|{''.join(chains)}))", GROUP_ATTRS):
                if g.dn.lower() not in seen:
                    seen.add(g.dn.lower())
                    groups.append(Membership(g, direct=False))
        groups.sort(key=_sort_key)
        return GroupsResult(principal, groups, nested)

    def group_members(self, identity: str, nested: bool = True) -> MembersResult:
        """Members of a group: direct, nested (transitive) and accounts using it as their primary group."""
        group = self.find_group(identity)
        dn = escape_filter_value(group.dn)
        members = {m.dn.lower(): Membership(m, direct=True) for m in self.search(f"(memberOf={dn})", PRINCIPAL_ATTRS)}
        sid = group.get("objectSid")
        if sid and str(sid).startswith("S-"):
            rid = int(str(sid).rsplit("-", 1)[1])
            for m in self.search(f"(primaryGroupID={rid})", PRINCIPAL_ATTRS):
                members.setdefault(m.dn.lower(), Membership(m, direct=True, primary=True))
        if nested:
            for m in self.search(f"(memberOf:{IN_CHAIN}:={dn})", PRINCIPAL_ATTRS):
                members.setdefault(m.dn.lower(), Membership(m, direct=False))
        ordered = sorted(members.values(), key=_sort_key)
        return MembersResult(group, ordered, nested)

    def compare_users(self, first: str, second: str, nested: bool = True) -> CompareResult:
        return CompareResult(self.user_groups(first, nested), self.user_groups(second, nested))


def _sort_key(m: Membership) -> tuple[int, str]:
    return (0 if m.direct else 1, m.obj.name.lower())


def _looks_like_dn(identity: str) -> bool:
    head = identity.split(",", 1)[0]
    return "," in identity and "=" in head and head.split("=", 1)[0].strip().lower() in ("cn", "ou", "uid", "dc")
