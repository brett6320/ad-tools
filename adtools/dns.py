"""Domain controller discovery through DNS SRV records, using only the standard library.

Active Directory registers its domain controllers in DNS (MS-ADTS 6.3.2.3):

``_ldap._tcp.<site>._sites.dc._msdcs.<domain>``
    DCs in one AD site (tried first when a site is configured)
``_ldap._tcp.dc._msdcs.<domain>``
    every DC in the domain
``_gc._tcp.<forest>``
    global catalog servers

The standard library cannot query SRV records, so this module has a minimal DNS
client (RFC 1035 over UDP, retrying over TCP when a response is truncated). Name
servers come from ``AD_DNS_SERVER``, or from the operating system:

- macOS: ``scutil --dns``, so per-domain resolvers (VPN split DNS) are honored
- Linux/BSD: ``/etc/resolv.conf``
- Windows: the TCP/IP interface settings in the registry

If no SRV records are found, the domain name itself is used: AD publishes an A
record for every DC at the domain apex, and DC certificates include the domain
name, so TLS verification still works.

Plain DNS is not authenticated, so discovered DC names are only accepted when they
are inside the AD domain. That stops a spoofed response from steering the bind to
some unrelated host that happens to hold a publicly trusted certificate.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import secrets
import socket
import struct

# subprocess runs only the fixed macOS `scutil --dns` command in macos_nameservers().
import subprocess  # nosec B404
import sys
from dataclasses import dataclass

log = logging.getLogger(__name__)

TYPE_SRV = 33
CLASS_IN = 1
RCODE_NXDOMAIN = 3
FLAG_QR = 0x8000
FLAG_TC = 0x0200
FLAG_RD = 0x0100

RESOLV_CONF = "/etc/resolv.conf"
SCUTIL = "/usr/sbin/scutil"
WINDOWS_TCPIP_KEY = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

_RANDOM = secrets.SystemRandom()


class DNSError(Exception):
    """A DNS query failed (as opposed to returning no records)."""


@dataclass(frozen=True)
class SRVRecord:
    priority: int
    weight: int
    port: int
    target: str


# --- wire format ---------------------------------------------------------------


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if label else b""
        if not raw or len(raw) > 63:
            raise ValueError(f"invalid DNS name {name!r}")
        out += bytes([len(raw)]) + raw
    if len(out) + 1 > 255:
        raise ValueError(f"DNS name too long: {name!r}")
    return out + b"\x00"


def build_query(name: str, qtype: int = TYPE_SRV, query_id: int | None = None) -> tuple[int, bytes]:
    query_id = secrets.randbits(16) if query_id is None else query_id
    header = struct.pack("!HHHHHH", query_id, FLAG_RD, 1, 0, 0, 0)
    return query_id, header + encode_name(name) + struct.pack("!HH", qtype, CLASS_IN)


def decode_name(message: bytes, offset: int) -> tuple[str, int]:
    """Decode a possibly compressed name; return it and the offset after it in the original position."""
    labels: list[str] = []
    end = None
    jumps = 0
    while True:
        if offset >= len(message):
            raise DNSError("truncated name")
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise DNSError("truncated compression pointer")
            if end is None:
                end = offset + 2
            jumps += 1
            if jumps > 64:
                raise DNSError("compression loop")
            offset = ((length & 0x3F) << 8) | message[offset + 1]
            continue
        if length & 0xC0:
            raise DNSError("unsupported label type")
        offset += 1
        if length == 0:
            break
        if offset + length > len(message):
            raise DNSError("truncated label")
        labels.append(message[offset : offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), (end if end is not None else offset)


def parse_srv_response(message: bytes, query_id: int) -> tuple[list[SRVRecord], bool]:
    """Return ``(records, truncated)``. NXDOMAIN gives no records; other errors raise."""
    if len(message) < 12:
        raise DNSError("short DNS response")
    rid, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", message[:12])
    if rid != query_id or not flags & FLAG_QR:
        raise DNSError("response does not match the query")
    if flags & FLAG_TC:
        return [], True
    rcode = flags & 0x000F
    if rcode == RCODE_NXDOMAIN:
        return [], False
    if rcode:
        raise DNSError(f"DNS server returned rcode {rcode}")
    offset = 12
    for _ in range(qdcount):
        _name, offset = decode_name(message, offset)
        offset += 4
    records = []
    for _ in range(ancount):
        _name, offset = decode_name(message, offset)
        if offset + 10 > len(message):
            raise DNSError("truncated answer")
        rtype, rclass, _ttl, rdlength = struct.unpack("!HHIH", message[offset : offset + 10])
        offset += 10
        rdata_end = offset + rdlength
        if rdata_end > len(message):
            raise DNSError("truncated record data")
        if rtype == TYPE_SRV and rclass == CLASS_IN and rdlength >= 7:
            priority, weight, port = struct.unpack("!HHH", message[offset : offset + 6])
            target, _ = decode_name(message, offset + 6)
            if target:  # "." means the service is decidedly not available
                records.append(SRVRecord(priority, weight, port, target.lower()))
        offset = rdata_end
    return records, False


# --- transport -----------------------------------------------------------------


def _address(nameserver: str) -> tuple[int, tuple]:
    info = socket.getaddrinfo(nameserver, 53, type=socket.SOCK_DGRAM, flags=socket.AI_NUMERICHOST)
    return info[0][0], info[0][4]


def query_srv(name: str, nameserver: str, timeout: float = 3.0) -> list[SRVRecord]:
    family, address = _address(nameserver)
    query_id, query = build_query(name)
    log.debug("> DNS SRV %s @%s", name, nameserver)
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect(address)  # only accept datagrams from the server we asked
        sock.send(query)
        records, truncated = parse_srv_response(sock.recv(65535), query_id)
    if not truncated:
        log.debug(
            "< DNS %s: %s", name, ", ".join(f"{r.target} (prio {r.priority}, weight {r.weight})" for r in records) or "no records"
        )
        return records
    log.debug("< DNS response truncated; retrying %s over TCP", name)
    with socket.create_connection(address[:2], timeout=timeout) as sock:
        sock.sendall(struct.pack("!H", len(query)) + query)
        length = struct.unpack("!H", _recv_exact(sock, 2))[0]
        records, _ = parse_srv_response(_recv_exact(sock, length), query_id)
    log.debug("< DNS %s (TCP): %s records", name, len(records))
    return records


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise DNSError("DNS server closed the TCP connection")
        data += chunk
    return data


def resolve_srv(name: str, nameservers: list[str], timeout: float = 3.0) -> list[SRVRecord]:
    """Ask each name server in turn; the first one that answers (even with nothing) wins."""
    errors = []
    for ns in nameservers:
        try:
            return query_srv(name, ns, timeout)
        except (OSError, DNSError, ValueError) as exc:
            errors.append(f"{ns}: {exc}")
    if errors:
        log.debug("SRV lookup of %s failed: %s", name, "; ".join(errors))
    return []


def order_srv(records: list[SRVRecord]) -> list[SRVRecord]:
    """RFC 2782 order: lowest priority first, weighted-random within a priority."""
    ordered = []
    for priority in sorted({r.priority for r in records}):
        pool = [r for r in records if r.priority == priority]
        while pool:
            total = sum(r.weight for r in pool)
            if total == 0:
                pick = _RANDOM.choice(pool)
            else:
                point, running = _RANDOM.uniform(0, total), 0
                pick = pool[-1]
                for r in pool:
                    running += r.weight
                    if point <= running:
                        pick = r
                        break
            ordered.append(pick)
            pool.remove(pick)
    return ordered


# --- name server discovery -----------------------------------------------------


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    return True


def resolv_conf_nameservers(path: str = RESOLV_CONF) -> list[str]:
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    servers = []
    for line in lines:
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2 and parts[0] == "nameserver" and _valid_ip(parts[1]):
            servers.append(parts[1])
    return servers


def parse_scutil(output: str, domain: str) -> list[str]:
    """Name servers from ``scutil --dns``: resolvers for ``domain`` first, then the default ones."""
    output = output.split("DNS configuration (for scoped queries)", 1)[0]
    domain = domain.lower().rstrip(".")
    scoped: list[tuple[int, list[str]]] = []
    default: list[str] = []
    for block in re.split(r"\n(?=resolver #)", output):
        servers = [s for s in re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", block) if _valid_ip(s)]
        if not servers or "mdns" in block:
            continue
        match = re.search(r"^\s*domain\s*:\s*(\S+)", block, re.MULTILINE)
        if match is None:
            default += servers
            continue
        suffix = match.group(1).lower().rstrip(".")
        if domain == suffix or domain.endswith("." + suffix):
            scoped.append((len(suffix), servers))
    ordered = [s for _, group in sorted(scoped, key=lambda g: -g[0]) for s in group] + default
    return list(dict.fromkeys(ordered))


def macos_nameservers(domain: str) -> list[str]:
    if not os.path.exists(SCUTIL):
        return []
    try:
        # Fixed absolute path, no shell, no user-controlled arguments.
        result = subprocess.run(  # noqa: S603  # nosec B603
            [SCUTIL, "--dns"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("scutil --dns failed: %s", exc)
        return []
    return parse_scutil(result.stdout, domain) if result.returncode == 0 else []


def windows_nameservers() -> list[str]:  # pragma: no cover - exercised on Windows CI only
    import winreg

    servers: list[str] = []

    def read(key, name):
        try:
            value, _ = winreg.QueryValueEx(key, name)
        except OSError:
            return
        servers.extend(s for s in re.split(r"[,\s]+", value or "") if _valid_ip(s))

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WINDOWS_TCPIP_KEY) as params:
            read(params, "NameServer")
            with winreg.OpenKey(params, "Interfaces") as interfaces:
                for i in range(winreg.QueryInfoKey(interfaces)[0]):
                    with winreg.OpenKey(interfaces, winreg.EnumKey(interfaces, i)) as iface:
                        read(iface, "NameServer")
                        read(iface, "DhcpNameServer")
    except OSError as exc:
        log.debug("could not read DNS servers from the registry: %s", exc)
    return list(dict.fromkeys(servers))


def system_nameservers(domain: str, platform: str | None = None) -> list[str]:
    platform = platform or sys.platform
    if platform == "darwin":
        servers = macos_nameservers(domain) or resolv_conf_nameservers()
    elif platform.startswith("win"):
        servers = windows_nameservers()
    else:
        servers = resolv_conf_nameservers()
    return list(dict.fromkeys(servers))


# --- discovery -----------------------------------------------------------------


def srv_names(domain: str, site: str = "", global_catalog: bool = False) -> list[str]:
    domain = domain.strip().rstrip(".").lower()
    if global_catalog:
        names = [f"_gc._tcp.{site}._sites.{domain}"] if site else []
        return [*names, f"_gc._tcp.{domain}"]
    names = [f"_ldap._tcp.{site}._sites.dc._msdcs.{domain}"] if site else []
    return [*names, f"_ldap._tcp.dc._msdcs.{domain}"]


def in_domain(host: str, domain: str) -> bool:
    host, domain = host.lower().rstrip("."), domain.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def discover_domain_controllers(
    domain: str,
    site: str = "",
    global_catalog: bool = False,
    nameservers: list[str] | None = None,
    timeout: float = 3.0,
) -> list[str]:
    """Return DC host names for ``domain`` in connection order, falling back to the domain name itself."""
    domain = domain.strip().rstrip(".").lower()
    servers = nameservers or system_nameservers(domain)
    log.debug("DNS servers for %s: %s", domain, ", ".join(servers) or "none")
    hosts: list[str] = []
    if servers:
        for name in srv_names(domain, site, global_catalog):
            for record in order_srv(resolve_srv(name, servers, timeout)):
                if not in_domain(record.target, domain):
                    log.warning("ignoring DC %s from %s: it is outside %s", record.target, name, domain)
                elif record.target not in hosts:
                    hosts.append(record.target)
    else:
        log.debug("no DNS servers found for SRV lookups")
    if hosts:
        log.info("domain controllers for %s from DNS: %s", domain, ", ".join(hosts))
        return hosts
    log.info("no DC SRV records found for %s; connecting to the domain name itself", domain)
    return [domain]
