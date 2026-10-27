import shutil
import socket
import ssl
import subprocess
import threading

import pytest

from adtools import ber, tls
from adtools.ldap import EXTENDED_REQUEST, LDAPConnection, LDAPError

from .fakeldap import bind_ok, extended

OPENSSL = shutil.which("openssl")
needs_openssl = pytest.mark.skipif(OPENSSL is None, reason="openssl CLI not available")

CA_EXT = """[req]
distinguished_name=dn
[dn]
[v3_ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
"""
SERVER_EXT = """basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
"""


def _run(*args, cwd):
    subprocess.run([OPENSSL, *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture(scope="session")
def pki(tmp_path_factory):
    if OPENSSL is None:
        pytest.skip("openssl CLI not available")
    d = tmp_path_factory.mktemp("pki")
    (d / "ca.cnf").write_text(CA_EXT)
    (d / "server.ext").write_text(SERVER_EXT)
    _run(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-days",
        "2",
        "-subj",
        "/CN=adtools test CA",
        "-config",
        "ca.cnf",
        "-extensions",
        "v3_ca",
        cwd=d,
    )
    _run(
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "server.key",
        "-out",
        "server.csr",
        "-subj",
        "/CN=localhost",
        "-config",
        "ca.cnf",
        cwd=d,
    )
    _run(
        "x509",
        "-req",
        "-in",
        "server.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-out",
        "server.pem",
        "-days",
        "2",
        "-extfile",
        "server.ext",
        cwd=d,
    )
    return d


class TLSLDAPServer:
    """Accept one connection on localhost: LDAPS (implicit TLS) or StartTLS, then answer binds."""

    def __init__(self, pki, starttls=False, starttls_code=0):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(pki / "server.pem", pki / "server.key")
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.starttls = starttls
        self.starttls_code = starttls_code
        self.error = None
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _recv_message(self, sock, buffer=b""):
        while True:
            try:
                msg, end = ber.decode(buffer)
                return msg, buffer[end:]
            except ber.BERError:
                data = sock.recv(65536)
                if not data:
                    return None, b""
                buffer += data

    def _reply(self, sock, msg, op):
        msg_id = ber.to_int(msg.children()[0].value)
        sock.sendall(ber.sequence(ber.integer(msg_id), op))

    def _serve(self):
        try:
            raw, _ = self.listener.accept()
            raw.settimeout(5)
            sock = raw
            if self.starttls:
                msg, _ = self._recv_message(raw)
                assert msg.children()[1].tag == EXTENDED_REQUEST
                self._reply(raw, msg, extended(self.starttls_code))
                if self.starttls_code:
                    return
            try:
                sock = self.ctx.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError) as exc:
                self.error = exc
                return
            while True:
                msg, _ = self._recv_message(sock)
                if msg is None or msg.children()[1].tag == 0x42:
                    return
                self._reply(sock, msg, bind_ok())
        except OSError as exc:
            self.error = exc
        finally:
            self.listener.close()


def _connect(port, ctx, mode="ldaps", host="localhost"):
    return LDAPConnection(host, port, mode, ctx, timeout=5).open()


@needs_openssl
def test_ldaps_with_bundle(pki):
    server = TLSLDAPServer(pki)
    ctx = tls.build_ssl_context("bundle", ca_file=pki / "ca.pem")
    with _connect(server.port, ctx) as conn:
        conn.bind("jdoe@corp.example.com", "pw")


@needs_openssl
def test_starttls_with_bundle(pki):
    server = TLSLDAPServer(pki, starttls=True)
    ctx = tls.build_ssl_context(ca_file=pki / "ca.pem")  # auto -> bundle
    with _connect(server.port, ctx, "starttls") as conn:
        conn.bind("jdoe", "pw")


@needs_openssl
def test_starttls_refused(pki):
    server = TLSLDAPServer(pki, starttls=True, starttls_code=52)
    ctx = tls.build_ssl_context(ca_file=pki / "ca.pem")
    with pytest.raises(LDAPError, match="StartTLS failed"):
        _connect(server.port, ctx, "starttls")


@needs_openssl
def test_hostname_mismatch_rejected(pki):
    server = TLSLDAPServer(pki)
    ctx = tls.build_ssl_context("bundle", ca_file=pki / "ca.pem")
    with pytest.raises(ssl.SSLCertVerificationError):
        _connect(server.port, ctx, host="127.0.0.1")


@needs_openssl
def test_untrusted_ca_rejected(pki, monkeypatch):
    server = TLSLDAPServer(pki)
    monkeypatch.setattr(tls, "macos_keychain_pem", lambda: "")
    ctx = tls.build_ssl_context("system")
    with pytest.raises(ssl.SSLCertVerificationError):
        _connect(server.port, ctx)


def test_context_is_strict(tmp_path):
    ctx = tls.build_ssl_context("system")
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_resolve_trust_mode(monkeypatch):
    assert tls.resolve_trust_mode("auto", ca_file="x.pem") == "bundle"
    assert tls.resolve_trust_mode(None, ca_path="/certs") == "bundle"
    monkeypatch.setattr(tls, "truststore_available", lambda: True)
    assert tls.resolve_trust_mode("auto") == "truststore"
    monkeypatch.setattr(tls, "truststore_available", lambda: False)
    assert tls.resolve_trust_mode("AUTO") == "system"
    assert tls.resolve_trust_mode("system", ca_file="x.pem") == "system"
    with pytest.raises(tls.TLSConfigError):
        tls.resolve_trust_mode("insecure")


def test_bundle_errors(tmp_path):
    with pytest.raises(tls.TLSConfigError, match="needs ca_file"):
        tls.build_ssl_context("bundle")
    with pytest.raises(tls.TLSConfigError, match="not found"):
        tls.build_ssl_context("bundle", ca_file=tmp_path / "missing.pem")


@pytest.mark.skipif(not tls.truststore_available(), reason="truststore not installed")
def test_truststore_context():
    import truststore

    ctx = tls.build_ssl_context("truststore")
    assert isinstance(ctx, truststore.SSLContext)


def test_truststore_missing(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "truststore":
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert tls.truststore_available() is False
    with pytest.raises(tls.TLSConfigError, match="pip install truststore"):
        tls.build_ssl_context("truststore")


@needs_openssl
def test_system_trust_darwin_uses_keychain(pki, monkeypatch):
    pem = (pki / "ca.pem").read_text()
    monkeypatch.setattr(tls, "macos_keychain_pem", lambda: pem)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.load_system_trust(ctx, platform="darwin")
    assert any(c["subject"] == ((("commonName", "adtools test CA"),),) for c in ctx.get_ca_certs())


@needs_openssl
def test_system_trust_linux_fallback_bundle(pki, monkeypatch):
    monkeypatch.setattr(tls, "LINUX_BUNDLES", ("/nonexistent/bundle.pem", str(pki / "ca.pem")))
    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", lambda self, purpose=None: None)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.load_system_trust(ctx, platform="linux")
    assert len(ctx.get_ca_certs()) == 1


def test_system_trust_warns_when_empty(monkeypatch, caplog):
    monkeypatch.setattr(tls, "LINUX_BUNDLES", ())
    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", lambda self, purpose=None: None)
    tls.load_system_trust(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), platform="linux")
    assert "no CA certificates" in caplog.text


def test_macos_keychain_pem(monkeypatch):
    calls = []

    class Done:
        returncode = 0
        stdout = "-----BEGIN CERTIFICATE-----\n"

    monkeypatch.setattr(tls.os.path, "exists", lambda p: True)
    monkeypatch.setattr(tls.subprocess, "run", lambda cmd, **kw: calls.append(cmd) or Done())
    assert tls.macos_keychain_pem().startswith("-----BEGIN")
    assert calls[0][:4] == ["/usr/bin/security", "find-certificate", "-a", "-p"]

    Done.returncode = 1
    assert tls.macos_keychain_pem() == ""

    def boom(cmd, **kw):
        raise OSError("nope")

    monkeypatch.setattr(tls.subprocess, "run", boom)
    assert tls.macos_keychain_pem() == ""

    monkeypatch.setattr(tls.os.path, "exists", lambda p: False)
    assert tls.macos_keychain_pem() == ""


@needs_openssl
def test_debug_trace_shows_tls_and_certificate_but_never_the_password(pki, caplog):
    caplog.set_level("DEBUG", logger="adtools")
    server = TLSLDAPServer(pki)
    ctx = tls.build_ssl_context("bundle", ca_file=pki / "ca.pem")
    with _connect(server.port, ctx) as conn:
        assert conn.tls_version.startswith("TLSv1.")
        conn.bind("jdoe@corp.example.com", "s3cret-pw")
    text = caplog.text
    assert "server certificate: subject commonName=localhost; issuer commonName=adtools test CA; SAN localhost" in text
    assert "> bind as 'jdoe@corp.example.com' (simple)" in text and "< bind: success" in text
    assert "s3cret-pw" not in text
