from datetime import UTC, datetime

import pytest

from adtools.ad import (
    AmbiguousError,
    DirectoryObject,
    NotFoundError,
    decode_value,
    filetime_to_datetime,
    group_type_names,
    sid_to_bytes,
    sid_to_str,
)

from .fakedir import BASE, FakeADClient, sample_directory


@pytest.fixture
def ad():
    return FakeADClient(sample_directory())


def names(memberships):
    return {m.obj.name: m.via for m in memberships}


def test_user_groups_by_sam_nested(ad):
    result = ad.user_groups("jdoe")
    assert names(result.groups) == {
        "VPN Users": "direct",
        "Engineering": "direct",
        "Domain Users": "primary group",
        "All Staff": "nested",
        "Remote Access": "nested",
    }
    assert [m.direct for m in result.groups][:3] == [True, True, True]  # direct first


def test_user_groups_by_email(ad):
    assert ad.user_groups("john.doe@corp.example.com").principal.name == "jdoe"
    assert ad.user_groups("jdoe@corp.example.com").principal.name == "jdoe"  # UPN
    assert ad.user_groups("alice@corp.example.com").principal.name == "asmith"  # proxyAddresses alias


def test_user_groups_other_forms(ad):
    assert ad.user_groups("CORP\\jdoe").principal.name == "jdoe"
    assert ad.user_groups(f"CN=jdoe,OU=Users,{BASE}").principal.name == "jdoe"


def test_user_groups_direct_only(ad):
    result = ad.user_groups("asmith", nested=False)
    assert names(result.groups) == {"Engineering": "direct", "Finance": "direct", "Domain Users": "primary group"}


def test_lookup_escapes_input(ad):
    with pytest.raises(NotFoundError):
        ad.user_groups("*")
    with pytest.raises(NotFoundError):
        ad.user_groups("x)(sAMAccountName=*")
    assert any("\\2a" in q for q in ad.directory.queries)


def test_not_found_and_ambiguous(ad):
    with pytest.raises(NotFoundError):
        ad.user_groups("nobody")
    with pytest.raises(NotFoundError):
        ad.user_groups(f"CN=nobody,OU=Users,{BASE}")
    ad.directory.user("dup1", 2001, mail="shared@corp.example.com")
    ad.directory.user("dup2", 2002, mail="shared@corp.example.com")
    with pytest.raises(AmbiguousError, match="2 objects"):
        ad.user_groups("shared@corp.example.com")
    with pytest.raises(ValueError):
        ad.user_groups("  ")


def test_group_members_nested(ad):
    result = ad.group_members("VPN Users")
    assert names(result.members) == {
        "jdoe": "direct",
        "Engineering": "direct",
        "asmith": "nested",
        "Platform": "nested",
        "olduser": "nested",
    }
    olduser = next(m for m in result.members if m.obj.name == "olduser")
    assert olduser.as_dict()["disabled"] is True


def test_group_members_direct_only_and_by_mail(ad):
    result = ad.group_members("vpn@corp.example.com", nested=False)
    assert names(result.members) == {"jdoe": "direct", "Engineering": "direct"}


def test_group_members_primary_group(ad):
    result = ad.group_members("Domain Users")
    assert set(names(result.members).values()) == {"primary group"}
    assert {"jdoe", "asmith", "olduser"} <= set(names(result.members))


def test_compare_users(ad):
    result = ad.compare_users("jdoe", "asmith@corp.example.com")
    assert {a.obj.name for a, b in result.common} == {"Engineering", "Domain Users", "All Staff", "Remote Access", "VPN Users"}
    assert result.only_first == []
    assert {m.obj.name for m in result.only_second} == {"Finance"}
    staff = next((a, b) for a, b in result.common if a.obj.name == "All Staff")
    assert (staff[0].via, staff[1].via) == ("nested", "nested")
    vpn = next((a, b) for a, b in result.common if a.obj.name == "VPN Users")
    assert (vpn[0].via, vpn[1].via) == ("direct", "nested")  # asmith via Engineering
    direct_only = ad.compare_users("jdoe", "asmith", nested=False)
    assert {m.obj.name for m in direct_only.only_first} == {"VPN Users"}


def test_membership_row(ad):
    row = ad.user_groups("jdoe").groups[0].as_dict()
    assert row["scope"] == "Global" and row["kind"] == "Security"


def test_sid_roundtrip():
    sid = "S-1-5-21-1004336348-1177238915-682003330-512"
    assert sid_to_str(sid_to_bytes(sid)) == sid
    with pytest.raises(ValueError):
        sid_to_str(b"\x01\x05")
    with pytest.raises(ValueError):
        sid_to_str(sid_to_bytes(sid)[:-1])
    with pytest.raises(ValueError):
        sid_to_bytes("X-1-5")


def test_filetime():
    assert filetime_to_datetime(0) is None
    assert filetime_to_datetime(0x7FFFFFFFFFFFFFFF) is None
    assert filetime_to_datetime(133000000000000000) == datetime(2022, 6, 18, 4, 26, 40, tzinfo=UTC)


def test_decode_value():
    assert decode_value("objectGUID", bytes(range(16))) == "03020100-0504-0706-0809-0a0b0c0d0e0f"
    assert decode_value("pwdLastSet", b"0") is None
    assert decode_value("whenCreated", b"20240102030405.0Z") == "2024-01-02T03:04:05+00:00"
    assert decode_value("cn", "José".encode()) == "José"
    assert decode_value("thumbnailPhoto", b"\xff\xfe") == "base64://4="
    assert decode_value("objectSid", b"bad") == "bad"


def test_group_type_names():
    assert group_type_names(-2147483646) == ("Global", "Security")
    assert group_type_names(-2147483644) == ("Domain local", "Security")
    assert group_type_names(-2147483643) == ("Builtin local", "Security")
    assert group_type_names(8) == ("Universal", "Distribution")
    assert group_type_names(0) == ("Unknown", "Distribution")


def test_directory_object_helpers():
    o = DirectoryObject("CN=x", {"objectClass": ["top", "foreignSecurityPrincipal"], "userAccountControl": ["junk"]})
    assert o.object_class == "foreignSecurityPrincipal"
    assert o.disabled is False
    assert o.name == "CN=x"
    assert DirectoryObject("CN=y", {"objectClass": ["top", "msDS-Thing"]}).object_class == "msds-thing"
