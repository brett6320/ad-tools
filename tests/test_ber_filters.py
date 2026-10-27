import pytest

from adtools import ber
from adtools.filters import FilterError, compile_filter, escape_filter_value


@pytest.mark.parametrize("value", [0, 1, 127, 128, 255, 256, -1, -128, -129, 2**31, 2**40])
def test_integer_roundtrip(value):
    element, end = ber.decode(ber.integer(value))
    assert element.tag == ber.INTEGER
    assert ber.to_int(element.value) == value


@pytest.mark.parametrize("size", [0, 1, 127, 128, 255, 256, 70000])
def test_long_lengths(size):
    payload = b"x" * size
    element, end = ber.decode(ber.octet_string(payload))
    assert element.value == payload
    assert end == len(ber.octet_string(payload))


def test_nested_sequence():
    data = ber.sequence(ber.integer(5), ber.sequence(ber.octet_string("a"), ber.boolean(True)))
    outer, _ = ber.decode(data)
    first, inner = outer.children()
    assert ber.to_int(first.value) == 5
    s, b = inner.children()
    assert s.value == b"a" and ber.to_bool(b.value)


@pytest.mark.parametrize(
    "data",
    [b"", b"\x04", b"\x04\x05abc", b"\x04\x80", b"\x04\x85\x00\x00\x00\x00\x01", b"\x1f\x01\x00", b"\x04\x82\x01"],
)
def test_decode_rejects_bad_input(data):
    with pytest.raises(ber.BERError):
        ber.decode(data)


def test_length_limit():
    with pytest.raises(ber.BERError, match="exceeds"):
        ber.decode_header(b"\x04\x84\x7f\xff\xff\xff")


def test_escape_filter_value():
    assert escape_filter_value("a*b(c)d\\e\x00") == "a\\2ab\\28c\\29d\\5ce\\00"
    assert escape_filter_value(b"\x01\xff") == "\\01\\ff"
    assert escape_filter_value("José") == "José"


def test_equality_filter():
    assert compile_filter("(cn=John)") == ber.sequence(ber.octet_string("cn"), ber.octet_string("John"), tag=0xA3)
    assert compile_filter("cn=John") == compile_filter("(cn=John)")


def test_present_and_substrings():
    assert compile_filter("(mail=*)") == ber.octet_string("mail", tag=0x87)
    sub, _ = ber.decode(compile_filter("(cn=ab*cd*ef)"))
    attr, pieces = sub.children()
    assert [(p.tag, p.value) for p in pieces.children()] == [(0x80, b"ab"), (0x81, b"cd"), (0x82, b"ef")]
    sub, _ = ber.decode(compile_filter("(cn=*x*)"))
    assert [(p.tag, p.value) for p in sub.children()[1].children()] == [(0x81, b"x")]


def test_boolean_operators():
    f, _ = ber.decode(compile_filter("(&(objectClass=user)(|(cn=a)(cn=b))(!(cn=c)))"))
    assert f.tag == 0xA0
    a, o, n = f.children()
    assert a.tag == 0xA3 and o.tag == 0xA1 and len(o.children()) == 2 and n.tag == 0xA2


def test_comparisons():
    assert ber.decode(compile_filter("(uSNChanged>=100)"))[0].tag == 0xA5
    assert ber.decode(compile_filter("(uSNChanged<=100)"))[0].tag == 0xA6
    assert ber.decode(compile_filter("(cn~=jon)"))[0].tag == 0xA8


def test_extensible_match():
    f, _ = ber.decode(compile_filter("(member:1.2.840.113556.1.4.1941:=CN=x\\2cy,DC=z)"))
    parts = {c.tag: c.value for c in f.children()}
    assert parts == {0x81: b"1.2.840.113556.1.4.1941", 0x82: b"member", 0x83: b"CN=x,y,DC=z"}
    f, _ = ber.decode(compile_filter("(cn:dn:2.5.13.5:=John)"))
    assert {c.tag for c in f.children()} == {0x81, 0x82, 0x83, 0x84}


def test_escaped_values_decode():
    f, _ = ber.decode(compile_filter("(cn=a\\2a\\28b\\29)"))
    assert f.children()[1].value == b"a*(b)"


def test_injection_is_neutralized():
    hostile = "x)(objectClass=*"
    f, _ = ber.decode(compile_filter(f"(sAMAccountName={escape_filter_value(hostile)})"))
    assert f.tag == 0xA3 and f.children()[1].value == hostile.encode()


@pytest.mark.parametrize(
    "text",
    ["", "(", "(cn=a", "(cn=a))", "(&)", "(=a)", "(cn)", "(cn=a\\zz)", "(cn=a\\2)", "(c n=a)", "(:=a)", "(cn::=a)", "(cn=a(b)"],
)
def test_bad_filters(text):
    with pytest.raises(FilterError):
        compile_filter(text)


def test_depth_limit():
    with pytest.raises(FilterError, match="deeply"):
        compile_filter("(!" * 100 + "(cn=a)" + ")" * 100)
