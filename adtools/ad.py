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
from .dns import discover_domain_controllers
from .filters import escape_filter_value
from .ldap import Entry, LDAPConnection, LDAPError
from .tls import build_ssl_context

log = logging.getLogger(__name__)

# LDAP_MATCHING_RULE_IN_CHAIN walks the member/memberOf chain on the DC. It is not used for membership
# lookups: on large domains it can run for minutes before returning anything. Nesting is expanded
# client-side instead, one level at a time, with batched queries on indexed attributes.
IN_CHAIN = "1.2.840.113556.1.4.1941"

# Clauses per OR filter when expanding nesting; keeps each request small.
BATCH_SIZE = 50
# Nesting depth guard (AD itself has no limit; real directories rarely exceed 10).
MAX_NESTING_DEPTH = 100

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
    parents: list[str] = field(default_factory=list)  # nested only: the group(s) it is reached through

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
            "via groups": "; ".join(self.parents),
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
        log.info("binding as %s", user or "anonymous")
        password = self._prompt_password(user) if user else ""
        try:
            return self._connect_any(ctx, user, password)
        finally:
            del password

    def server_candidates(self) -> list[str]:
        """``AD_SERVER`` if set, else the domain controllers found through DNS for ``AD_DOMAIN``."""
        s = self.settings
        if s.servers:
            return s.servers
        return discover_domain_controllers(
            s.domain, site=s.site, global_catalog=s.global_catalog, nameservers=s.dns_servers, timeout=min(s.timeout, 5.0)
        )

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
        for host in self.server_candidates():
            conn = LDAPConnection(host, s.effective_port, s.tls_mode, ctx, s.timeout)
            try:
                conn.open()
                conn.bind(user, password)
            except LDAPError as exc:
                conn.close()
                if exc.code is not None:  # the server answered: credentials or policy, not reachability
                    raise
                errors.append(f"{host}: {exc}")
                log.warning("%s:%s failed: %s", host, s.effective_port, exc)
            except (OSError, ssl.SSLError) as exc:
                conn.close()
                errors.append(f"{host}: {exc}")
                log.warning("%s:%s failed: %s", host, s.effective_port, exc)
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
    def server(self) -> str:
        """The server this client is connected to, e.g. ``dc1.corp.example.com:636 (LDAPS, TLSv1.3)``."""
        conn = self.connection
        details = ", ".join(filter(None, ["LDAPS" if conn.tls_mode == "ldaps" else "StartTLS", conn.tls_version]))
        return f"{conn.host}:{conn.port} ({details})"

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
        # Ask the DC to give up just before the client would, so a slow query ends with a clear
        # timeLimitExceeded instead of a silent socket timeout.
        time_limit = max(1, int(self.settings.timeout) - 1) if self.settings.timeout >= 2 else 0
        for entry in self.connection.search(
            base,
            search_filter,
            attributes,
            scope=scope,
            size_limit=size_limit,
            time_limit=time_limit,
            page_size=self.settings.page_size,
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
        found = list(self.search(f"(&(objectClass=group)(objectSid={value}))", (*GROUP_ATTRS, "memberOf")))
        return found[0] if found else None

    def _groups_by_dn(self, dns: list[str]) -> Iterator[DirectoryObject]:
        for chunk in _batched(dns):
            clauses = "".join(f"(distinguishedName={escape_filter_value(dn)})" for dn in chunk)
            yield from self.search(f"(&(objectClass=group)(|{clauses}))", (*GROUP_ATTRS, "memberOf"))

    # memberships

    def user_groups(self, identity: str, nested: bool = True) -> GroupsResult:
        """Groups a user is a member of: direct, nested (transitive) and the primary group.

        Nesting is followed upward through each group's ``memberOf``, one level per
        round trip, so every nested group records the group(s) it is reached through.
        """
        principal = self.find_principal(identity)
        dn = escape_filter_value(principal.dn)
        found: dict[str, Membership] = {}
        for g in self.search(f"(&(objectClass=group)(member={dn}))", (*GROUP_ATTRS, "memberOf")):
            found[g.dn.lower()] = Membership(g, direct=True)
        primary = self._primary_group(principal)
        if primary is not None and primary.dn.lower() not in found:
            found[primary.dn.lower()] = Membership(primary, direct=True, primary=True)
        frontier = list(found.values())
        depth = 0
        while nested and frontier and depth < MAX_NESTING_DEPTH:
            depth += 1
            wanted: dict[str, tuple[str, list[str]]] = {}
            for child in frontier:
                for parent_dn in child.obj.get_all("memberOf"):
                    key = parent_dn.lower()
                    if key in found:
                        _add_parent(found[key], child.obj.name)
                    else:
                        wanted.setdefault(key, (parent_dn, []))[1].append(child.obj.name)
            frontier = []
            for g in self._groups_by_dn([dn for dn, _ in wanted.values()]):
                key = g.dn.lower()
                if key not in found:
                    found[key] = Membership(g, direct=False, parents=sorted(set(wanted.get(key, ("", []))[1])))
                    frontier.append(found[key])
        if frontier and depth >= MAX_NESTING_DEPTH:
            log.warning("stopped expanding nested groups at depth %s", MAX_NESTING_DEPTH)
        groups = sorted(found.values(), key=_sort_key)
        return GroupsResult(principal, groups, nested)

    def group_members(self, identity: str, nested: bool = True) -> MembersResult:
        """Members of a group: direct, nested (transitive) and accounts using a group as their primary group.

        Nesting is followed downward with batched ``memberOf`` queries, one level per
        round trip, so every nested member records the group(s) it is reached through.
        """
        group = self.find_group(identity)
        attrs = (*PRINCIPAL_ATTRS, "memberOf")
        members: dict[str, Membership] = {}
        for m in self.search(f"(memberOf={escape_filter_value(group.dn)})", attrs):
            members[m.dn.lower()] = Membership(m, direct=True)
        rid = _rid(group)
        if rid is not None:
            for m in self.search(f"(primaryGroupID={rid})", attrs):
                members.setdefault(m.dn.lower(), Membership(m, direct=True, primary=True))
        frontier = [m for m in members.values() if m.obj.object_class == "group"]
        seen_groups = {group.dn.lower()} | {m.obj.dn.lower() for m in frontier}
        depth = 0
        while nested and frontier and depth < MAX_NESTING_DEPTH:
            depth += 1
            names = {m.obj.dn.lower(): m.obj.name for m in frontier}
            next_frontier: list[Membership] = []

            def record(obj: DirectoryObject, parents: list[str], next_frontier: list[Membership] = next_frontier) -> None:
                key = obj.dn.lower()
                if key in members:
                    for p in parents:
                        _add_parent(members[key], p)
                    return
                members[key] = Membership(obj, direct=False, parents=sorted(set(parents)))
                if obj.object_class == "group" and key not in seen_groups:
                    seen_groups.add(key)
                    next_frontier.append(members[key])

            for chunk in _batched(list(names)):
                clauses = "".join(f"(memberOf={escape_filter_value(m.obj.dn)})" for m in frontier if m.obj.dn.lower() in chunk)
                for obj in self.search(f"(|{clauses})", attrs):
                    record(obj, [names[p.lower()] for p in obj.get_all("memberOf") if p.lower() in names])
            rids = {r: m.obj.name for m in frontier if (r := _rid(m.obj)) is not None}
            for chunk in _batched(sorted(rids)):
                clauses = "".join(f"(primaryGroupID={r})" for r in chunk)
                for obj in self.search(f"(|{clauses})", attrs):
                    pgid = int(obj.get("primaryGroupID") or 0)
                    record(obj, [rids[pgid]] if pgid in rids else [])
            frontier = next_frontier
        if frontier and depth >= MAX_NESTING_DEPTH:
            log.warning("stopped expanding nested members at depth %s", MAX_NESTING_DEPTH)
        ordered = sorted(members.values(), key=_sort_key)
        return MembersResult(group, ordered, nested)

    def compare_users(self, first: str, second: str, nested: bool = True) -> CompareResult:
        return CompareResult(self.user_groups(first, nested), self.user_groups(second, nested))


def _batched(items: list[str], size: int = BATCH_SIZE) -> Iterator[list[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _add_parent(membership: Membership, parent: str) -> None:
    if not membership.direct and parent not in membership.parents:
        membership.parents.append(parent)
        membership.parents.sort()


def _rid(obj: DirectoryObject) -> int | None:
    sid = str(obj.get("objectSid") or "")
    return int(sid.rsplit("-", 1)[1]) if sid.startswith("S-") else None


def _sort_key(m: Membership) -> tuple[int, str]:
    return (0 if m.direct else 1, m.obj.name.lower())


def _looks_like_dn(identity: str) -> bool:
    head = identity.split(",", 1)[0]
    return "," in identity and "=" in head and head.split("=", 1)[0].strip().lower() in ("cn", "ou", "uid", "dc")
