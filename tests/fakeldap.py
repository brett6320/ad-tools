"""A scripted in-process LDAP server for protocol tests."""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable

from adtools import ber
from adtools.ldap import (
    BIND_RESPONSE,
    EXTENDED_RESPONSE,
    PAGED_RESULTS_OID,
    SEARCH_RESULT_DONE,
    SEARCH_RESULT_ENTRY,
)

# handler(op_tag, op_tlv, controls) -> list of (op_bytes, controls_bytes | None)
Handler = Callable[[int, ber.TLV, list[ber.TLV]], list[tuple[bytes, bytes | None]]]


def result(tag: int, code: int = 0, diagnostic: str = "", extra: bytes = b"") -> bytes:
    return ber.sequence(ber.enumerated(code), ber.octet_string(""), ber.octet_string(diagnostic), extra, tag=tag)


def bind_ok() -> bytes:
    return result(BIND_RESPONSE)


def done(code: int = 0, diagnostic: str = "") -> bytes:
    return result(SEARCH_RESULT_DONE, code, diagnostic)


def extended(code: int = 0) -> bytes:
    return result(EXTENDED_RESPONSE, code)


def entry(dn: str, **attrs: list[bytes | str]) -> bytes:
    encoded = []
    for name, values in attrs.items():
        vals = [ber.octet_string(v) for v in values]
        encoded.append(ber.sequence(ber.octet_string(name), ber.set_of(*vals)))
    return ber.sequence(ber.octet_string(dn), ber.sequence(*encoded), tag=SEARCH_RESULT_ENTRY)


def paged_control(cookie: bytes) -> bytes:
    value = ber.sequence(ber.integer(0), ber.octet_string(cookie))
    return ber.sequence(ber.sequence(ber.octet_string(PAGED_RESULTS_OID), ber.octet_string(value)), tag=0xA0)


def request_cookie(controls: list[ber.TLV]) -> bytes:
    for control in controls:
        parts = control.children()
        if parts[0].value.decode() == PAGED_RESULTS_OID:
            return ber.decode(parts[-1].value)[0].children()[1].value
    return b""


class FakeServer:
    """Serve one client over a socket pair; record every request received."""

    def __init__(self, handler: Handler, chunk: int = 0) -> None:
        self.client, self._server = socket.socketpair()
        self.client.settimeout(5)
        self._server.settimeout(5)
        self.handler = handler
        self.chunk = chunk  # >0 sends responses in small pieces to exercise buffering
        self.requests: list[tuple[int, ber.TLV, list[ber.TLV]]] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        buffer = b""
        try:
            while True:
                data = self._server.recv(65536)
                if not data:
                    return
                buffer += data
                while True:
                    try:
                        message, end = ber.decode(buffer)
                    except ber.BERError:
                        break
                    buffer = buffer[end:]
                    parts = message.children()
                    msg_id = ber.to_int(parts[0].value)
                    op = parts[1]
                    controls = parts[2].children() if len(parts) > 2 else []
                    self.requests.append((op.tag, op, controls))
                    if op.tag == 0x42:  # unbind
                        return
                    for response, response_controls in self.handler(op.tag, op, controls):
                        out = ber.sequence(ber.integer(msg_id), response, response_controls or b"")
                        if self.chunk:
                            for i in range(0, len(out), self.chunk):
                                self._server.sendall(out[i : i + self.chunk])
                        else:
                            self._server.sendall(out)
        except OSError:
            return
        finally:
            self._server.close()

    def join(self) -> None:
        self._thread.join(timeout=5)
