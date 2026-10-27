import socket

import pytest

from adtools import ber
from adtools.ldap import (
    BIND_REQUEST,
    SEARCH_REQUEST,
    SEARCH_RESULT_REFERENCE,
    LDAPConnection,
    LDAPError,
)

from .fakeldap import FakeServer, bind_ok, done, entry, extended, paged_control, request_cookie, result


def connect(handler, **kwargs):
    server = FakeServer(handler, **kwargs)
    return server, LDAPConnection("dc.test", sock=server.client).open()


def test_bind_sends_simple_credentials():
    server, conn = connect(lambda tag, op, c: [(bind_ok(), None)])
    conn.bind("jdoe@corp.example.com", "s3cret")
    conn.close()
    server.join()
    tag, op, _ = server.requests[0]
    assert tag == BIND_REQUEST
    version, name, auth = op.children()
    assert ber.to_int(version.value) == 3
    assert name.value == b"jdoe@corp.example.com"
    assert (auth.tag, auth.value) == (0x80, b"s3cret")
    assert server.requests[-1][0] == 0x42  # unbind


def test_bind_failure_reports_code_and_diagnostic():
    diag = "80090308: LdapErr: DSID-0C09041C, comment: AcceptSecurityContext error, data 52e, v4563"
    server, conn = connect(lambda tag, op, c: [(result(0x61, 49, diag), None)])
    with pytest.raises(LDAPError) as excinfo:
        conn.bind("jdoe", "wrong")
    assert excinfo.value.code == 49
    assert "invalidCredentials" in str(excinfo.value) and "data 52e" in str(excinfo.value)


def test_bind_requires_password_for_named_user():
    server, conn = connect(lambda tag, op, c: [(bind_ok(), None)])
    with pytest.raises(LDAPError, match="password is required"):
        conn.bind("jdoe", "")
    assert server.requests == []


def test_bind_refused_on_unencrypted_connection():
    conn = LDAPConnection("dc.test")
    with pytest.raises(LDAPError, match="unencrypted"):
        conn.bind("jdoe", "pw")


def test_open_requires_context():
    with pytest.raises(ValueError, match="ssl_context"):
        LDAPConnection("dc.test").open()


def test_invalid_tls_mode():
    with pytest.raises(ValueError):
        LDAPConnection("dc.test", tls_mode="plain")


def test_default_ports():
    assert LDAPConnection("h").port == 636
    assert LDAPConnection("h", tls_mode="starttls").port == 389
    assert LDAPConnection("h", 3269).port == 3269


def test_search_paging_and_references():
    pages = {b"": (b"page2", ["CN=a", "CN=b"]), b"page2": (b"", ["CN=c"])}

    def handler(tag, op, controls):
        assert tag == SEARCH_REQUEST
        nxt, dns = pages[request_cookie(controls)]
        out = [(entry(dn, cn=[dn[3:]], objectSid=[b"\x01\x00"]), None) for dn in dns]
        out.append((ber.sequence(ber.octet_string("ldap://other/DC=x"), tag=SEARCH_RESULT_REFERENCE), None))
        out.append((done(), paged_control(nxt)))
        return out

    server, conn = connect(handler, chunk=7)
    entries = list(conn.search("DC=corp", "(objectClass=user)", ["cn"], page_size=2))
    assert [e.dn for e in entries] == ["CN=a", "CN=b", "CN=c"]
    assert entries[0].attributes == {"cn": [b"a"], "objectSid": [b"\x01\x00"]}
    _, op, _ = server.requests[0]
    base, scope, deref, size, time, types_only, flt, attrs = op.children()
    assert base.value == b"DC=corp" and ber.to_int(scope.value) == 2
    assert [a.value for a in attrs.children()] == [b"cn"]


def test_search_without_paging():
    server, conn = connect(lambda tag, op, c: [(entry("CN=a"), None), (done(), None)])
    assert [e.dn for e in conn.search("DC=x", page_size=0)] == ["CN=a"]
    assert server.requests[0][2] == []


def test_search_error():
    server, conn = connect(lambda tag, op, c: [(done(32, "0000208D: NameErr"), None)])
    with pytest.raises(LDAPError) as excinfo:
        list(conn.search("OU=missing,DC=x"))
    assert excinfo.value.code == 32


def test_size_limit_exceeded_is_not_an_error():
    server, conn = connect(lambda tag, op, c: [(entry("CN=a"), None), (done(4), None)])
    assert len(list(conn.search("DC=x", size_limit=1))) == 1


def test_search_bad_scope():
    conn = LDAPConnection("h")
    with pytest.raises(ValueError):
        list(conn.search("DC=x", scope="everything"))


def test_notice_of_disconnection():
    def handler(tag, op, c):
        return []

    server, conn = connect(handler)
    # Message ID 0 unsolicited notification
    server._server.sendall(ber.sequence(ber.integer(0), extended(52)))
    with pytest.raises(LDAPError, match="disconnected"):
        conn._receive(1)


def test_connection_closed_by_server():
    server, conn = connect(lambda tag, op, c: [])
    server._server.shutdown(socket.SHUT_RDWR)  # close() alone doesn't wake the server thread's recv on Linux
    with pytest.raises(LDAPError, match="closed"):
        conn._receive(1)


def test_malformed_response():
    server, conn = connect(lambda tag, op, c: [])
    server._server.sendall(b"\x04\x01x")
    with pytest.raises(LDAPError, match="malformed"):
        conn._receive(1)


def test_operations_need_open_connection():
    conn = LDAPConnection("h")
    conn._encrypted = True
    with pytest.raises(LDAPError, match="not open"):
        conn.bind("u", "p")


def test_debug_trace_of_search(caplog):
    caplog.set_level("DEBUG", logger="adtools")

    def handler(tag, op, c):
        if tag == BIND_REQUEST:
            return [(bind_ok(), None)]
        return [(entry("CN=a"), None), (entry("CN=b"), None), (done(), None)]

    server, conn = connect(handler)
    conn.bind("svc", "hunter2")
    assert len(list(conn.search("DC=x", "(cn=*)", ["cn"]))) == 2
    assert "> search #2 base='DC=x' scope=sub filter=(cn=*) attrs=['cn'] page_size=500" in caplog.text
    assert "< search #2 done: success, 2 entries" in caplog.text
    assert "hunter2" not in caplog.text
    assert conn.tls_version == ""  # a plain test socket has no TLS


def test_timeout_names_the_operation():
    server, conn = connect(lambda tag, op, c: [(bind_ok(), None)] if tag == BIND_REQUEST else [])
    conn.timeout = 0.2
    server.client.settimeout(0.2)
    conn.bind("u", "p")
    with pytest.raises(LDAPError, match=r"no response from dc\.test:636 within 0\.2s \(waiting for search #2\)"):
        list(conn.search("DC=x"))


def test_server_time_limit_is_sent_and_reported():
    server, conn = connect(lambda tag, op, c: [(done(3), None)])
    with pytest.raises(LDAPError, match="89s time limit") as excinfo:
        list(conn.search("DC=x", time_limit=89))
    assert excinfo.value.code == 3
    time_limit = server.requests[0][1].children()[4]
    assert ber.to_int(time_limit.value) == 89
