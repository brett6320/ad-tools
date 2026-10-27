"""A small LDAPv3 client (RFC 4511) built on the standard library.

Supports LDAPS (implicit TLS, port 636/3269) and StartTLS (port 389/3268), simple
bind, paged search (RFC 2696) and unbind. Plaintext binds are never sent: the
connection is always encrypted before any credentials leave the host.
"""

from __future__ import annotations

import logging
import socket
import ssl
from collections.abc import Iterator
from dataclasses import dataclass, field

from . import ber
from .filters import compile_filter

log = logging.getLogger(__name__)

# Protocol op tags
BIND_REQUEST = 0x60
BIND_RESPONSE = 0x61
UNBIND_REQUEST = 0x42
SEARCH_REQUEST = 0x63
SEARCH_RESULT_ENTRY = 0x64
SEARCH_RESULT_DONE = 0x65
SEARCH_RESULT_REFERENCE = 0x73
EXTENDED_REQUEST = 0x77
EXTENDED_RESPONSE = 0x78
CONTROLS = 0xA0

STARTTLS_OID = "1.3.6.1.4.1.1466.20037"
PAGED_RESULTS_OID = "1.2.840.113556.1.4.319"

SCOPES = {"base": 0, "one": 1, "onelevel": 1, "sub": 2, "subtree": 2}

RESULT_CODES = {
    0: "success",
    1: "operationsError",
    2: "protocolError",
    3: "timeLimitExceeded",
    4: "sizeLimitExceeded",
    8: "strongerAuthRequired",
    10: "referral",
    11: "adminLimitExceeded",
    12: "unavailableCriticalExtension",
    13: "confidentialityRequired",
    32: "noSuchObject",
    34: "invalidDNSyntax",
    48: "inappropriateAuthentication",
    49: "invalidCredentials",
    50: "insufficientAccessRights",
    51: "busy",
    52: "unavailable",
    53: "unwillingToPerform",
}

TLS_MODES = ("ldaps", "starttls")


class LDAPError(Exception):
    """An LDAP operation failed."""

    def __init__(self, message: str, code: int | None = None, diagnostic: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.diagnostic = diagnostic


@dataclass
class LDAPResult:
    code: int
    matched_dn: str
    diagnostic: str

    @property
    def name(self) -> str:
        return RESULT_CODES.get(self.code, f"code {self.code}")


@dataclass
class Entry:
    """A search result entry. ``attributes`` maps attribute name to raw byte values."""

    dn: str
    attributes: dict[str, list[bytes]] = field(default_factory=dict)


class LDAPConnection:
    """One encrypted connection to one directory server.

    ``sock`` lets tests supply an already-connected socket-like object; it is
    used as-is and no TLS is applied, so it must never be used in production.
    """

    def __init__(
        self,
        host: str,
        port: int | None = None,
        tls_mode: str = "ldaps",
        ssl_context: ssl.SSLContext | None = None,
        timeout: float = 10.0,
        sock: socket.socket | None = None,
    ) -> None:
        if tls_mode not in TLS_MODES:
            raise ValueError(f"tls_mode must be one of {', '.join(TLS_MODES)}")
        self.host = host
        self.tls_mode = tls_mode
        self.port = port or (636 if tls_mode == "ldaps" else 389)
        self.timeout = timeout
        self._ctx = ssl_context
        self._sock = sock
        self._buffer = b""
        self._message_id = 0
        self._encrypted = sock is not None

    # --- connection lifecycle --------------------------------------------

    def open(self) -> LDAPConnection:
        if self._sock is not None:
            return self
        if self._ctx is None:
            raise ValueError("an ssl_context is required")
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        try:
            if self.tls_mode == "ldaps":
                self._sock = self._ctx.wrap_socket(raw, server_hostname=self.host)
            else:
                self._sock = raw
                self._start_tls()
        except BaseException:
            raw.close()
            self._sock = None
            raise
        self._encrypted = True
        log.debug("connected to %s:%s (%s)", self.host, self.port, self.tls_mode)
        return self

    def _start_tls(self) -> None:
        op = ber.sequence(ber.octet_string(STARTTLS_OID, tag=0x80), tag=EXTENDED_REQUEST)
        msg_id = self._send(op)
        tag, body, _ = self._receive(msg_id)
        if tag != EXTENDED_RESPONSE:
            raise LDAPError(f"unexpected response 0x{tag:02x} to StartTLS")
        result = _parse_result(body)
        if result.code != 0:
            raise LDAPError(f"StartTLS failed: {result.name} {result.diagnostic}".strip(), result.code, result.diagnostic)
        if self._buffer:
            raise LDAPError("unexpected data received before the TLS handshake")
        if self._ctx is None or self._sock is None:  # pragma: no cover - open() guarantees both
            raise LDAPError("connection is not open")
        self._sock = self._ctx.wrap_socket(self._sock, server_hostname=self.host)

    def close(self) -> None:
        if self._sock is None:
            return
        try:
            self._send(ber.null(tag=UNBIND_REQUEST))
        except OSError:
            pass
        finally:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def __enter__(self) -> LDAPConnection:
        return self.open()

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- operations -------------------------------------------------------

    def bind(self, user: str = "", password: str = "") -> None:  # nosec B107
        """Simple bind. ``user`` may be a DN, a UPN (user@domain) or DOMAIN\\user."""
        if not self._encrypted:
            raise LDAPError("refusing to bind over an unencrypted connection")
        if user and not password:
            # An empty password makes AD perform an *unauthenticated* bind that "succeeds".
            raise LDAPError("a password is required for a simple bind")
        op = ber.sequence(
            ber.integer(3),
            ber.octet_string(user),
            ber.octet_string(password, tag=0x80),
            tag=BIND_REQUEST,
        )
        msg_id = self._send(op)
        tag, body, _ = self._receive(msg_id)
        if tag != BIND_RESPONSE:
            raise LDAPError(f"unexpected response 0x{tag:02x} to bind")
        result = _parse_result(body)
        if result.code != 0:
            raise LDAPError(f"bind failed: {result.name} {result.diagnostic}".strip(), result.code, result.diagnostic)

    def search(
        self,
        base: str,
        search_filter: str = "(objectClass=*)",
        attributes: list[str] | tuple[str, ...] = (),
        scope: str = "sub",
        size_limit: int = 0,
        time_limit: int = 0,
        page_size: int = 500,
    ) -> Iterator[Entry]:
        """Yield matching entries, following paged-results cookies until done."""
        if scope not in SCOPES:
            raise ValueError(f"scope must be one of {', '.join(SCOPES)}")
        encoded_filter = compile_filter(search_filter)
        cookie = b""
        returned = 0
        while True:
            op = ber.sequence(
                ber.octet_string(base),
                ber.enumerated(SCOPES[scope]),
                ber.enumerated(0),  # neverDerefAliases
                ber.integer(size_limit),
                ber.integer(time_limit),
                ber.boolean(False),
                encoded_filter,
                ber.sequence(*(ber.octet_string(a) for a in attributes)),
                tag=SEARCH_REQUEST,
            )
            controls = None
            if page_size:
                value = ber.sequence(ber.integer(page_size), ber.octet_string(cookie))
                controls = ber.sequence(
                    ber.sequence(ber.octet_string(PAGED_RESULTS_OID), ber.octet_string(value)),
                    tag=CONTROLS,
                )
            msg_id = self._send(op, controls)
            while True:
                tag, body, response_controls = self._receive(msg_id)
                if tag == SEARCH_RESULT_ENTRY:
                    returned += 1
                    yield _parse_entry(body)
                elif tag == SEARCH_RESULT_REFERENCE:
                    continue  # referrals to other naming contexts are not chased
                elif tag == SEARCH_RESULT_DONE:
                    break
                else:
                    raise LDAPError(f"unexpected response 0x{tag:02x} to search")
            result = _parse_result(body)
            if result.code == 4 and size_limit and returned >= size_limit:
                return
            if result.code != 0:
                raise LDAPError(f"search failed: {result.name} {result.diagnostic}".strip(), result.code, result.diagnostic)
            cookie = _paged_cookie(response_controls) if page_size else b""
            if not cookie:
                return

    # --- wire helpers -----------------------------------------------------

    def _send(self, op: bytes, controls: bytes | None = None) -> int:
        if self._sock is None:
            raise LDAPError("connection is not open")
        self._message_id += 1
        message = ber.sequence(ber.integer(self._message_id), op, controls or b"")
        self._sock.sendall(message)
        return self._message_id

    def _receive(self, msg_id: int) -> tuple[int, bytes, list[ber.TLV]]:
        """Return ``(op_tag, op_body, controls)`` of the next message for ``msg_id``."""
        while True:
            message = self._read_message()
            parts = message.children()
            if len(parts) < 2 or parts[0].tag != ber.INTEGER:
                raise LDAPError("malformed LDAP message")
            received_id = ber.to_int(parts[0].value)
            op = parts[1]
            controls = parts[2].children() if len(parts) > 2 and parts[2].tag == CONTROLS else []
            if received_id == 0 and op.tag == EXTENDED_RESPONSE:
                result = _parse_result(op.value)
                raise LDAPError(f"server disconnected: {result.name} {result.diagnostic}".strip(), result.code)
            if received_id != msg_id:
                log.debug("ignoring message for id %s", received_id)
                continue
            return op.tag, op.value, controls

    def _read_message(self) -> ber.TLV:
        while True:
            try:
                tag, length, start = ber.decode_header(self._buffer)
            except ber.BERError as exc:
                if "truncated" not in str(exc):
                    raise LDAPError(f"malformed response: {exc}") from exc
            else:
                if tag != ber.SEQUENCE:
                    raise LDAPError(f"malformed response: tag 0x{tag:02x}")
                if len(self._buffer) >= start + length:
                    element, end = ber.decode(self._buffer)
                    self._buffer = self._buffer[end:]
                    return element
            if self._sock is None:
                raise LDAPError("connection is not open")
            chunk = self._sock.recv(65536)
            if not chunk:
                raise LDAPError("connection closed by server")
            self._buffer += chunk


def _parse_result(body: bytes) -> LDAPResult:
    parts = ber.decode_all(body)
    if len(parts) < 3:
        raise LDAPError("malformed LDAPResult")
    return LDAPResult(
        code=ber.to_int(parts[0].value),
        matched_dn=parts[1].value.decode("utf-8", "replace"),
        diagnostic=parts[2].value.decode("utf-8", "replace").strip("\x00 \n"),
    )


def _parse_entry(body: bytes) -> Entry:
    parts = ber.decode_all(body)
    if len(parts) != 2:
        raise LDAPError("malformed SearchResultEntry")
    entry = Entry(dn=parts[0].value.decode("utf-8", "replace"))
    for attribute in parts[1].children():
        type_tlv, values_tlv = attribute.children()
        entry.attributes[type_tlv.value.decode("utf-8", "replace")] = [v.value for v in values_tlv.children()]
    return entry


def _paged_cookie(controls: list[ber.TLV]) -> bytes:
    for control in controls:
        parts = control.children()
        if not parts or parts[0].value.decode("ascii", "replace") != PAGED_RESULTS_OID:
            continue
        value = parts[-1]
        if value.tag != ber.OCTET_STRING:
            return b""
        _size, cookie = ber.decode(value.value)[0].children()
        return cookie.value
    return b""
