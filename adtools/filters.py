"""LDAP search filters: RFC 4515 string parsing, BER encoding and value escaping."""

from __future__ import annotations

from . import ber

# Filter CHOICE tags (RFC 4511 section 4.5.1)
_AND = 0xA0
_OR = 0xA1
_NOT = 0xA2
_EQUALITY = 0xA3
_SUBSTRINGS = 0xA4
_GREATER_OR_EQUAL = 0xA5
_LESS_OR_EQUAL = 0xA6
_PRESENT = 0x87
_APPROX = 0xA8
_EXTENSIBLE = 0xA9

_SUB_INITIAL = 0x80
_SUB_ANY = 0x81
_SUB_FINAL = 0x82

_MAX_DEPTH = 64


class FilterError(ValueError):
    """Raised for a malformed LDAP filter string."""


def escape_filter_value(value: str | bytes) -> str:
    """Escape a value for safe use inside an LDAP filter (RFC 4515 section 3).

    Always use this for any user-supplied value placed in a filter, to prevent
    LDAP filter injection. Bytes (such as an objectGUID or objectSid) are escaped
    byte for byte.
    """
    if isinstance(value, bytes):
        return "".join(f"\\{b:02x}" for b in value)
    out = []
    for ch in value:
        if ch in "*()\\\x00":
            out.append(f"\\{ord(ch):02x}")
        else:
            out.append(ch)
    return "".join(out)


def compile_filter(text: str) -> bytes:
    """Parse an RFC 4515 filter string and return its BER encoding."""
    text = text.strip()
    if not text:
        raise FilterError("empty filter")
    if not text.startswith("("):
        text = f"({text})"
    parser = _Parser(text)
    encoded = parser.parse_filter(0)
    if parser.pos != len(text):
        raise FilterError(f"unexpected trailing characters at position {parser.pos}")
    return encoded


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0

    def _peek(self) -> str:
        if self.pos >= len(self.text):
            raise FilterError("unexpected end of filter")
        return self.text[self.pos]

    def _expect(self, ch: str) -> None:
        if self._peek() != ch:
            raise FilterError(f"expected {ch!r} at position {self.pos}")
        self.pos += 1

    def parse_filter(self, depth: int) -> bytes:
        if depth > _MAX_DEPTH:
            raise FilterError("filter nested too deeply")
        self._expect("(")
        ch = self._peek()
        if ch in "&|":
            self.pos += 1
            items = []
            while self._peek() == "(":
                items.append(self.parse_filter(depth + 1))
            if not items:
                raise FilterError(f"empty {'AND' if ch == '&' else 'OR'} at position {self.pos}")
            encoded = ber.set_of(*items, tag=_AND if ch == "&" else _OR)
        elif ch == "!":
            self.pos += 1
            encoded = ber.tlv(_NOT, self.parse_filter(depth + 1))
        else:
            encoded = self._parse_item()
        self._expect(")")
        return encoded

    def _parse_item(self) -> bytes:
        end = self.text.find(")", self.pos)
        if end < 0:
            raise FilterError("unterminated filter item")
        item = self.text[self.pos : end]
        self.pos = end
        eq = item.find("=")
        if eq <= 0:
            raise FilterError(f"missing attribute or '=' in filter item {item!r}")
        prev = item[eq - 1]
        if prev == ":":
            return _extensible(item)
        comparisons = {">": _GREATER_OR_EQUAL, "<": _LESS_OR_EQUAL, "~": _APPROX}
        if prev in comparisons:
            attr, value = item[: eq - 1], item[eq + 1 :]
            return ber.sequence(ber.octet_string(_attr(attr)), ber.octet_string(_unescape(value)), tag=comparisons[prev])
        attr, value = _attr(item[:eq]), item[eq + 1 :]
        if value == "*":
            return ber.octet_string(attr, tag=_PRESENT)
        if "*" in value:
            return _substrings(attr, value)
        return ber.sequence(ber.octet_string(attr), ber.octet_string(_unescape(value)), tag=_EQUALITY)


def _attr(name: str) -> str:
    name = name.strip()
    if not name or not all(c.isalnum() or c in "-;." for c in name):
        raise FilterError(f"invalid attribute description {name!r}")
    return name


def _substrings(attr: str, value: str) -> bytes:
    parts = value.split("*")
    pieces = []
    if parts[0]:
        pieces.append(ber.octet_string(_unescape(parts[0]), tag=_SUB_INITIAL))
    for middle in parts[1:-1]:
        if middle:
            pieces.append(ber.octet_string(_unescape(middle), tag=_SUB_ANY))
    if parts[-1]:
        pieces.append(ber.octet_string(_unescape(parts[-1]), tag=_SUB_FINAL))
    return ber.sequence(ber.octet_string(attr), ber.sequence(*pieces), tag=_SUBSTRINGS)


def _extensible(item: str) -> bytes:
    """Encode ``attr[:dn][:rule]:=value`` or ``[:dn]:rule:=value``."""
    left, value = item.split(":=", 1)
    parts = left.split(":")
    attr = parts[0]
    dn_attrs = False
    rule = None
    for extra in parts[1:]:
        if extra.lower() == "dn":
            dn_attrs = True
        elif extra:
            rule = extra
        else:
            raise FilterError(f"invalid extensible match {item!r}")
    if not attr and not rule:
        raise FilterError(f"extensible match needs an attribute or matching rule: {item!r}")
    body = b""
    if rule:
        body += ber.octet_string(_attr(rule), tag=0x81)
    if attr:
        body += ber.octet_string(_attr(attr), tag=0x82)
    body += ber.octet_string(_unescape(value), tag=0x83)
    if dn_attrs:
        body += ber.boolean(True, tag=0x84)
    return ber.tlv(_EXTENSIBLE, body)


def _unescape(value: str) -> bytes:
    out = bytearray()
    i = 0
    raw = value.encode("utf-8")
    while i < len(raw):
        b = raw[i]
        if b == 0x5C:  # backslash
            hex_pair = raw[i + 1 : i + 3]
            if len(hex_pair) != 2 or not all(c in b"0123456789abcdefABCDEF" for c in hex_pair):
                raise FilterError(f"invalid escape in value {value!r}")
            out.append(int(hex_pair, 16))
            i += 3
        elif b in (0x28, 0x29, 0x2A, 0x00):  # ( ) * NUL must be escaped
            raise FilterError(f"unescaped special character in value {value!r}")
        else:
            out.append(b)
            i += 1
    return bytes(out)
