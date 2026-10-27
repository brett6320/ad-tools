"""An in-memory directory that evaluates compiled (BER) filters, for testing ADClient logic."""

from __future__ import annotations

from collections.abc import Iterator

from adtools import ber
from adtools.ad import IN_CHAIN, ADClient, DirectoryObject, sid_to_bytes
from adtools.config import Settings
from adtools.filters import compile_filter
from adtools.ldap import Entry, LDAPError

DOMAIN_SID = "S-1-5-21-1111-2222-3333"
BASE = "DC=corp,DC=example,DC=com"


class FakeDirectory:
    def __init__(self) -> None:
        self.objects: dict[str, dict[str, list[bytes]]] = {}
        self.queries: list[str] = []

    def add(self, dn: str, classes: list[str], rid: int | None = None, **attrs: object) -> str:
        record: dict[str, list[bytes]] = {"objectclass": [c.encode() for c in ["top", *classes]]}
        if "person" in classes or "computer" in classes:
            record["objectcategory"] = [b"person" if "computer" not in classes else b"computer"]
        if rid is not None:
            record["objectsid"] = [sid_to_bytes(f"{DOMAIN_SID}-{rid}")]
        for key, value in attrs.items():
            values = value if isinstance(value, list) else [value]
            record[key.lower()] = [v if isinstance(v, bytes) else str(v).encode() for v in values]
        record.setdefault("cn", [dn.split(",")[0].split("=", 1)[1].encode()])
        self.objects[dn] = record
        return dn

    def user(self, sam: str, rid: int, primary: int = 513, **attrs: object) -> str:
        dn = f"CN={sam},OU=Users,{BASE}"
        attrs.setdefault("userAccountControl", 512)
        return self.add(dn, ["person", "user"], rid, sAMAccountName=sam, primaryGroupID=primary, **attrs)

    def group(self, sam: str, rid: int, members: list[str] = (), group_type: int = -2147483646, **attrs: object) -> str:
        dn = f"CN={sam},OU=Groups,{BASE}"
        return self.add(dn, ["group"], rid, sAMAccountName=sam, groupType=group_type, member=list(members), **attrs)

    # --- membership graph ---

    def _member_of(self, dn: str) -> set[str]:
        return {g.lower() for g, rec in self.objects.items() if dn.lower() in {m.decode().lower() for m in rec.get("member", [])}}

    def _closure(self, start: str, step) -> set[str]:
        seen: set[str] = set()
        todo = [start.lower()]
        while todo:
            for nxt in step(todo.pop()):
                if nxt not in seen:
                    seen.add(nxt)
                    todo.append(nxt)
        return seen

    def _values(self, dn: str, attr: str) -> list[bytes]:
        attr = attr.lower()
        if attr == "memberof":
            return [g.encode() for g in self._member_of(dn)]
        if attr == "distinguishedname":
            return [dn.encode()]
        return self.objects[dn].get(attr, [])

    # --- filter evaluation ---

    def matches(self, dn: str, f: ber.TLV) -> bool:
        tag = f.tag
        if tag == 0xA0:
            return all(self.matches(dn, c) for c in f.children())
        if tag == 0xA1:
            return any(self.matches(dn, c) for c in f.children())
        if tag == 0xA2:
            return not self.matches(dn, ber.decode(f.value)[0])
        if tag == 0x87:
            return bool(self._values(dn, f.value.decode()))
        if tag == 0xA3:
            attr, value = (c.value for c in f.children())
            return any(v.lower() == value.lower() for v in self._values(dn, attr.decode()))
        if tag == 0xA4:
            attr, subs = f.children()
            pieces = [p.value.lower() for p in subs.children()]
            return any(all(p in v.lower() for p in pieces) for v in self._values(dn, attr.value.decode()))
        if tag == 0xA9:
            parts = {c.tag: c.value for c in f.children()}
            rule, attr, value = parts[0x81].decode(), parts[0x82].decode().lower(), parts[0x83].decode().lower()
            assert rule == IN_CHAIN, rule
            if attr == "member":  # dn is a group that transitively contains value
                return dn.lower() in self._closure(value, self._member_of)
            if attr == "memberof":  # dn transitively belongs to group value
                return value in self._closure(dn, self._member_of)
        raise AssertionError(f"unsupported filter tag 0x{tag:02x}")

    def search(self, base: str, filter_text: str, scope: str) -> Iterator[Entry]:
        self.queries.append(filter_text)
        compiled, _ = ber.decode(compile_filter(filter_text))
        if scope == "base":
            if base not in self.objects:
                raise LDAPError("no such object", 32)
            candidates = [base]
        else:
            candidates = [dn for dn in self.objects if dn.lower().endswith(base.lower())]
        for dn in candidates:
            if self.matches(dn, compiled):
                attrs = {k: v for k, v in self.objects[dn].items() if v}
                attrs["memberOf"] = self._values(dn, "memberof")
                yield Entry(dn, {k: v for k, v in attrs.items() if v})


class FakeADClient(ADClient):
    def __init__(self, directory: FakeDirectory) -> None:
        super().__init__(Settings(server="dc.test", base_dn=BASE))
        self.directory = directory

    def search(self, search_filter, attributes=(), base=None, scope="sub", size_limit=0):
        base = self.settings.search_base if base is None else base
        for e in self.directory.search(base, search_filter, scope):
            yield DirectoryObject.from_entry(e)


def sample_directory() -> FakeDirectory:
    """jdoe and asmith with direct, nested and primary group memberships.

    VPN Users  <- jdoe, Engineering
    Engineering <- jdoe, asmith, Platform
    Platform    <- (empty)
    All Staff   <- Engineering, Finance
    Finance     <- asmith
    Domain Users (rid 513) is everyone's primary group; Remote Access <- Domain Users
    """
    d = FakeDirectory()
    jdoe = d.user(
        "jdoe", 1101, mail="John.Doe@corp.example.com", userPrincipalName="jdoe@corp.example.com", displayName="John Doe"
    )
    asmith = d.user(
        "asmith",
        1102,
        mail="asmith@corp.example.com",
        proxyAddresses=["SMTP:asmith@corp.example.com", "smtp:alice@corp.example.com"],
    )
    disabled = d.user("olduser", 1103, userAccountControl=514)
    domain_users = d.group("Domain Users", 513)
    d.group("Remote Access", 1201, members=[domain_users])
    platform = d.group("Platform", 1202)
    engineering = d.group("Engineering", 1203, members=[jdoe, asmith, platform, disabled])
    d.group("VPN Users", 1204, members=[jdoe, engineering], mail="vpn@corp.example.com")
    finance = d.group("Finance", 1205, members=[asmith])
    d.group("All Staff", 1206, members=[engineering, finance], group_type=8)
    return d
