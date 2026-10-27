"""Minimal BER (Basic Encoding Rules) encoder and decoder for LDAPv3.

Only the subset of ASN.1 that LDAP (RFC 4511) uses is supported: definite-length
encodings of INTEGER, ENUMERATED, BOOLEAN, OCTET STRING, NULL, SEQUENCE, SET and
context/application tagged values.
"""

from __future__ import annotations

from dataclasses import dataclass

# Universal tags
BOOLEAN = 0x01
INTEGER = 0x02
OCTET_STRING = 0x04
NULL = 0x05
ENUMERATED = 0x0A
SEQUENCE = 0x30
SET = 0x31

CONSTRUCTED = 0x20
CLASS_APPLICATION = 0x40
CLASS_CONTEXT = 0x80

# Guard against hostile or corrupt length fields (an LDAP PDU is never this big in practice).
MAX_LENGTH = 64 * 1024 * 1024


class BERError(ValueError):
    """Raised when data is not valid BER for the subset supported here."""


@dataclass(frozen=True)
class TLV:
    """A decoded tag-length-value element."""

    tag: int
    value: bytes

    @property
    def constructed(self) -> bool:
        return bool(self.tag & CONSTRUCTED)

    def children(self) -> list[TLV]:
        return decode_all(self.value)


# --- encoding ---------------------------------------------------------------


def encode_length(length: int) -> bytes:
    if length < 0:
        raise BERError("negative length")
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + encode_length(len(value)) + value


def integer(value: int, tag: int = INTEGER) -> bytes:
    length = max(1, (value.bit_length() + 8) // 8)  # room for the sign bit
    return tlv(tag, value.to_bytes(length, "big", signed=True))


def enumerated(value: int) -> bytes:
    return integer(value, ENUMERATED)


def boolean(value: bool, tag: int = BOOLEAN) -> bytes:
    return tlv(tag, b"\xff" if value else b"\x00")


def octet_string(value: bytes | str, tag: int = OCTET_STRING) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return tlv(tag, value)


def null(tag: int = NULL) -> bytes:
    return tlv(tag, b"")


def sequence(*items: bytes, tag: int = SEQUENCE) -> bytes:
    return tlv(tag, b"".join(items))


def set_of(*items: bytes, tag: int = SET) -> bytes:
    return tlv(tag, b"".join(items))


# --- decoding ---------------------------------------------------------------


def decode_header(data: bytes, offset: int = 0) -> tuple[int, int, int]:
    """Return ``(tag, length, value_offset)`` for the element at ``offset``.

    Raises ``BERError`` when the header itself is truncated or malformed.
    """
    if offset >= len(data):
        raise BERError("truncated tag")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise BERError("multi-byte tags are not supported")
    if offset + 1 >= len(data):
        raise BERError("truncated length")
    first = data[offset + 1]
    pos = offset + 2
    if first < 0x80:
        return tag, first, pos
    count = first & 0x7F
    if count == 0:
        raise BERError("indefinite lengths are not supported")
    if count > 4:
        raise BERError("length field too large")
    if pos + count > len(data):
        raise BERError("truncated length")
    length = int.from_bytes(data[pos : pos + count], "big")
    if length > MAX_LENGTH:
        raise BERError(f"element length {length} exceeds limit")
    return tag, length, pos + count


def decode(data: bytes, offset: int = 0) -> tuple[TLV, int]:
    """Decode one element and return it with the offset just past it."""
    tag, length, start = decode_header(data, offset)
    end = start + length
    if end > len(data):
        raise BERError("truncated value")
    return TLV(tag, data[start:end]), end


def decode_all(data: bytes) -> list[TLV]:
    items: list[TLV] = []
    offset = 0
    while offset < len(data):
        item, offset = decode(data, offset)
        items.append(item)
    return items


def to_int(value: bytes) -> int:
    if not value:
        raise BERError("empty integer")
    return int.from_bytes(value, "big", signed=True)


def to_bool(value: bytes) -> bool:
    if len(value) != 1:
        raise BERError("invalid boolean")
    return value != b"\x00"
