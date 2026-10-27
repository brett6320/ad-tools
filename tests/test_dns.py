import socket
import struct
import threading

import pytest

from adtools import dns
from adtools.dns import (
    DNSError,
    SRVRecord,
    build_query,
    decode_name,
    discover_domain_controllers,
    encode_name,
    in_domain,
    order_srv,
    parse_scutil,
    parse_srv_response,
    resolv_conf_nameservers,
    srv_names,
)


def srv_response(query: bytes, records, rcode=0, truncated=False, compress=True) -> bytes:
    """Build a response to ``query`` with SRV answers (target names compressed against the question)."""
    qid = struct.unpack("!H", query[:2])[0]
    question = query[12:]
    flags = dns.FLAG_QR | dns.FLAG_RD | rcode | (dns.FLAG_TC if truncated else 0)
    answers = b""
    for priority, weight, port, target in records:
        rdata = struct.pack("!HHH", priority, weight, port) + (b"\x00" if target == "." else encode_name(target))
        name = b"\xc0\x0c" if compress else question[:-4]
        answers += name + struct.pack("!HHIH", dns.TYPE_SRV, dns.CLASS_IN, 600, len(rdata)) + rdata
    return struct.pack("!HHHHHH", qid, flags, 1, len(records), 0, 0) + question + answers


def test_encode_and_decode_name():
    wire = encode_name("_ldap._tcp.dc._msdcs.corp.example.com.")
    assert wire.startswith(b"\x05_ldap\x04_tcp")
    assert decode_name(wire, 0) == ("_ldap._tcp.dc._msdcs.corp.example.com", len(wire))
    for bad in ("", "a..b", "x" * 64 + ".com", ".".join(["abcdefgh"] * 40)):
        with pytest.raises(ValueError):
            encode_name(bad)


def test_decode_name_rejects_loops_and_truncation():
    with pytest.raises(DNSError, match="loop"):
        decode_name(b"\xc0\x00", 0)
    with pytest.raises(DNSError):
        decode_name(b"\x05ab", 0)
    with pytest.raises(DNSError):
        decode_name(b"\x40", 0)


def test_parse_srv_response():
    qid, query = build_query("_ldap._tcp.dc._msdcs.corp.example.com")
    response = srv_response(query, [(0, 100, 389, "DC1.corp.example.com"), (0, 0, 389, ".")])
    records, truncated = parse_srv_response(response, qid)
    assert records == [SRVRecord(0, 100, 389, "dc1.corp.example.com")]  # "." target dropped
    assert truncated is False


def test_parse_srv_response_errors():
    qid, query = build_query("x.example.com")
    assert parse_srv_response(srv_response(query, [], rcode=3), qid) == ([], False)  # NXDOMAIN
    assert parse_srv_response(srv_response(query, [], truncated=True), qid) == ([], True)
    with pytest.raises(DNSError, match="rcode 2"):
        parse_srv_response(srv_response(query, [], rcode=2), qid)
    with pytest.raises(DNSError, match="match"):
        parse_srv_response(srv_response(query, []), (qid + 1) & 0xFFFF)
    with pytest.raises(DNSError, match="short"):
        parse_srv_response(b"\x00", qid)
    with pytest.raises(DNSError):
        parse_srv_response(srv_response(query, [(0, 0, 389, "dc1.example.com")])[:-5], qid)


def test_order_srv():
    records = [SRVRecord(10, 0, 389, "c"), SRVRecord(0, 50, 389, "a"), SRVRecord(0, 50, 389, "b"), SRVRecord(0, 0, 389, "z")]
    ordered = order_srv(records)
    assert {r.target for r in ordered[:3]} == {"a", "b", "z"} and ordered[-1].target == "c"
    assert order_srv([]) == []


def test_srv_names():
    assert srv_names("Corp.Example.com.") == ["_ldap._tcp.dc._msdcs.corp.example.com"]
    assert srv_names("corp.example.com", site="HQ") == [
        "_ldap._tcp.HQ._sites.dc._msdcs.corp.example.com",
        "_ldap._tcp.dc._msdcs.corp.example.com",
    ]
    assert srv_names("corp.example.com", site="HQ", global_catalog=True) == [
        "_gc._tcp.HQ._sites.corp.example.com",
        "_gc._tcp.corp.example.com",
    ]


def test_in_domain():
    assert in_domain("DC1.corp.example.com.", "corp.example.com")
    assert in_domain("corp.example.com", "corp.example.com")
    assert not in_domain("evilcorp.example.com", "corp.example.com")
    assert not in_domain("dc1.attacker.net", "corp.example.com")


def test_resolv_conf(tmp_path):
    p = tmp_path / "resolv.conf"
    p.write_text("# comment\nsearch corp.example.com\nnameserver 10.0.0.10\nnameserver fe80::1%en0  # v6\nnameserver bogus\n")
    assert resolv_conf_nameservers(str(p)) == ["10.0.0.10", "fe80::1%en0"]
    assert resolv_conf_nameservers(str(tmp_path / "missing")) == []


SCUTIL_OUTPUT = """DNS configuration

resolver #1
  search domain[0] : home.example
  nameserver[0] : 192.168.1.1
  flags    : Request A records

resolver #2
  domain   : example.com
  nameserver[0] : 10.9.0.1
  flags    : Supplemental, Request A records

resolver #3
  domain   : corp.example.com
  nameserver[0] : 10.0.0.10
  nameserver[1] : 10.0.0.11

resolver #4
  domain   : local
  options  : mdns

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 172.16.0.1
"""


def test_parse_scutil_prefers_most_specific_domain():
    assert parse_scutil(SCUTIL_OUTPUT, "corp.example.com") == ["10.0.0.10", "10.0.0.11", "10.9.0.1", "192.168.1.1"]
    assert parse_scutil(SCUTIL_OUTPUT, "other.org") == ["192.168.1.1"]


def test_macos_nameservers(monkeypatch):
    class Done:
        returncode = 0
        stdout = SCUTIL_OUTPUT

    monkeypatch.setattr(dns.os.path, "exists", lambda p: True)
    monkeypatch.setattr(dns.subprocess, "run", lambda cmd, **kw: Done())
    assert dns.macos_nameservers("corp.example.com")[0] == "10.0.0.10"
    Done.returncode = 1
    assert dns.macos_nameservers("corp.example.com") == []

    def boom(cmd, **kw):
        raise OSError("nope")

    monkeypatch.setattr(dns.subprocess, "run", boom)
    assert dns.macos_nameservers("corp.example.com") == []
    monkeypatch.setattr(dns.os.path, "exists", lambda p: False)
    assert dns.macos_nameservers("corp.example.com") == []


def test_system_nameservers_by_platform(monkeypatch):
    monkeypatch.setattr(dns, "macos_nameservers", lambda d: [])
    monkeypatch.setattr(dns, "resolv_conf_nameservers", lambda: ["10.0.0.1", "10.0.0.1"])
    monkeypatch.setattr(dns, "windows_nameservers", lambda: ["10.0.0.2"])
    assert dns.system_nameservers("x", "darwin") == ["10.0.0.1"]  # scutil empty -> resolv.conf
    assert dns.system_nameservers("x", "linux") == ["10.0.0.1"]
    assert dns.system_nameservers("x", "win32") == ["10.0.0.2"]


class FakeDNSServer:
    """Answer SRV queries on localhost over UDP (and TCP when ``truncate`` is set)."""

    def __init__(self, zones, truncate=False):
        self.zones = zones
        self.truncate = truncate
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.create_server(("127.0.0.1", self.port))
        self.queries = []
        threading.Thread(target=self._serve_udp, daemon=True).start()
        threading.Thread(target=self._serve_tcp, daemon=True).start()

    def _answer(self, query, allow_truncate):
        name, _ = decode_name(query, 12)
        self.queries.append(name)
        if name not in self.zones:
            return srv_response(query, [], rcode=3)
        return srv_response(query, self.zones[name], truncated=allow_truncate and self.truncate)

    def _serve_udp(self):
        while True:
            try:
                query, addr = self.udp.recvfrom(512)
            except OSError:
                return
            self.udp.sendto(self._answer(query, True), addr)

    def _serve_tcp(self):
        while True:
            try:
                conn, _ = self.tcp.accept()
            except OSError:
                return
            with conn:
                length = struct.unpack("!H", conn.recv(2))[0]
                answer = self._answer(conn.recv(length), False)
                conn.sendall(struct.pack("!H", len(answer)) + answer)

    def close(self):
        self.udp.close()
        self.tcp.close()


@pytest.fixture
def fake_dns(monkeypatch):
    servers = []

    def start(zones, truncate=False):
        server = FakeDNSServer(zones, truncate)
        servers.append(server)
        monkeypatch.setattr(dns, "_address", lambda ns: (socket.AF_INET, ("127.0.0.1", server.port)))
        return server

    yield start
    for s in servers:
        s.close()


ZONE = {
    "_ldap._tcp.HQ._sites.dc._msdcs.corp.example.com": [(0, 100, 389, "dc-hq.corp.example.com")],
    "_ldap._tcp.dc._msdcs.corp.example.com": [
        (0, 100, 389, "dc1.corp.example.com"),
        (0, 100, 389, "dc-hq.corp.example.com"),
        (10, 100, 389, "dc-dr.corp.example.com"),
        (0, 100, 389, "dc.attacker.net"),
    ],
}


def test_discover_over_udp_with_site_first_and_foreign_targets_dropped(fake_dns, caplog):
    fake_dns(ZONE)
    hosts = discover_domain_controllers("corp.example.com", site="HQ", nameservers=["10.0.0.10"])
    assert hosts[0] == "dc-hq.corp.example.com"
    assert set(hosts) == {"dc-hq.corp.example.com", "dc1.corp.example.com", "dc-dr.corp.example.com"}
    assert hosts[-1] == "dc-dr.corp.example.com"  # higher priority value = later
    assert "dc.attacker.net" in caplog.text and "outside" in caplog.text


def test_discover_retries_over_tcp_when_truncated(fake_dns):
    server = fake_dns(ZONE, truncate=True)
    hosts = discover_domain_controllers("corp.example.com", nameservers=["10.0.0.10"])
    assert "dc1.corp.example.com" in hosts
    assert server.queries.count("_ldap._tcp.dc._msdcs.corp.example.com") == 2  # UDP then TCP


def test_discover_falls_back_to_domain_name(fake_dns, caplog):
    fake_dns({})
    caplog.set_level("INFO")
    assert discover_domain_controllers("corp.example.com", nameservers=["10.0.0.10"]) == ["corp.example.com"]
    assert "connecting to the domain name itself" in caplog.text


def test_discover_without_nameservers(monkeypatch):
    monkeypatch.setattr(dns, "system_nameservers", lambda domain: [])
    assert discover_domain_controllers("corp.example.com") == ["corp.example.com"]


def test_resolve_srv_tries_next_nameserver(monkeypatch):
    calls = []

    def fake_query(name, ns, timeout):
        calls.append(ns)
        if ns == "10.0.0.1":
            raise TimeoutError("timed out")
        return [SRVRecord(0, 0, 389, "dc1.corp.example.com")]

    monkeypatch.setattr(dns, "query_srv", fake_query)
    assert dns.resolve_srv("x", ["10.0.0.1", "10.0.0.2"])[0].target == "dc1.corp.example.com"
    assert calls == ["10.0.0.1", "10.0.0.2"]
    monkeypatch.setattr(dns, "query_srv", lambda *a: (_ for _ in ()).throw(OSError("down")))
    assert dns.resolve_srv("x", ["10.0.0.1"]) == []
