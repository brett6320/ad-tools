"""TLS context construction for LDAPS and StartTLS.

Trust modes:

``truststore``
    Verify with the operating system's native trust store via the third-party
    ``truststore`` package (macOS Keychain / Security.framework, Windows CryptoAPI,
    OpenSSL default paths on Linux). Honors OS trust settings and enterprise roots.

``system``
    Standard library only. Loads the platform's built-in trust store:
    Windows certificate stores (``ROOT`` and ``CA``) via ``ssl.enum_certificates``,
    OpenSSL default paths and common distro bundles on Linux/BSD, and on macOS the
    System Roots and System keychains exported with ``/usr/bin/security``.

``bundle``
    Trust only the PEM bundle given as ``ca_file`` (and/or a hashed ``ca_path``
    directory). Use this for a private AD CS root.

``auto`` (default)
    ``bundle`` when a ``ca_file``/``ca_path`` is given, else ``truststore`` when it is
    installed, else ``system``.

Certificate verification and hostname checking are always on, and TLS 1.2 is the
minimum version. There is deliberately no way to disable verification.
"""

from __future__ import annotations

import logging
import os
import ssl

# subprocess runs only the fixed macOS `security` command in macos_keychain_pem().
import subprocess  # nosec B404
import sys
from pathlib import Path

log = logging.getLogger(__name__)

TRUST_MODES = ("auto", "truststore", "system", "bundle")

# Common CA bundle locations, checked when OpenSSL's compiled-in defaults find nothing.
LINUX_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu, Alpine, Arch
    "/etc/pki/tls/certs/ca-bundle.crt",  # RHEL, Fedora, CentOS
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # RHEL 7+
    "/etc/ssl/ca-bundle.pem",  # openSUSE
    "/etc/ssl/cert.pem",  # Alpine, BSDs, macOS
    "/usr/local/share/certs/ca-root-nss.crt",  # FreeBSD
)

MACOS_SECURITY = "/usr/bin/security"
MACOS_KEYCHAINS = (
    "/System/Library/Keychains/SystemRootCertificates.keychain",
    "/Library/Keychains/System.keychain",
)


class TLSConfigError(ValueError):
    """Raised for an invalid or unusable TLS configuration."""


def truststore_available() -> bool:
    try:
        import truststore  # noqa: F401
    except ImportError:
        return False
    return True


def resolve_trust_mode(trust: str | None, ca_file: str | None = None, ca_path: str | None = None) -> str:
    mode = (trust or "auto").strip().lower()
    if mode not in TRUST_MODES:
        raise TLSConfigError(f"unknown trust mode {trust!r}; expected one of {', '.join(TRUST_MODES)}")
    if mode == "auto":
        if ca_file or ca_path:
            return "bundle"
        return "truststore" if truststore_available() else "system"
    return mode


def build_ssl_context(
    trust: str | None = "auto",
    ca_file: str | os.PathLike[str] | None = None,
    ca_path: str | os.PathLike[str] | None = None,
    client_cert: str | os.PathLike[str] | None = None,
    client_key: str | os.PathLike[str] | None = None,
) -> ssl.SSLContext:
    """Return a verifying client ``SSLContext`` for the chosen trust mode."""
    ca_file = os.fspath(ca_file) if ca_file else None
    ca_path = os.fspath(ca_path) if ca_path else None
    mode = resolve_trust_mode(trust, ca_file, ca_path)

    if mode == "bundle":
        if not ca_file and not ca_path:
            raise TLSConfigError("trust mode 'bundle' needs ca_file or ca_path")
        for path in filter(None, (ca_file, ca_path)):
            if not Path(path).exists():
                raise TLSConfigError(f"CA bundle not found: {path}")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile=ca_file, capath=ca_path)
    elif mode == "truststore":
        try:
            import truststore
        except ImportError:
            raise TLSConfigError("trust mode 'truststore' needs the truststore package (pip install truststore)") from None
        ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        load_system_trust(ctx)

    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if client_cert:
        ctx.load_cert_chain(os.fspath(client_cert), os.fspath(client_key) if client_key else None)
    log.debug("TLS trust mode: %s", mode)
    return ctx


def load_system_trust(ctx: ssl.SSLContext, platform: str | None = None) -> None:
    """Load the platform's built-in trust store into ``ctx`` using only the standard library."""
    platform = platform or sys.platform
    ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)  # Windows: ROOT and CA stores
    if platform == "darwin":
        pem = macos_keychain_pem()
        if pem:
            ctx.load_verify_locations(cadata=pem)
    elif not platform.startswith("win") and not ctx.get_ca_certs():
        for bundle in LINUX_BUNDLES:
            if os.path.isfile(bundle):
                ctx.load_verify_locations(cafile=bundle)
                break
    if not ctx.get_ca_certs():
        log.warning("no CA certificates found in the system trust store; set AD_CA_FILE or use truststore")


def macos_keychain_pem() -> str:
    """Export the macOS system root and System keychain certificates as PEM.

    Note: this exports certificates, not their trust settings, so a certificate the
    administrator has explicitly distrusted in Keychain Access is still trusted here.
    Prefer the ``truststore`` mode on macOS where that matters.
    """
    keychains = [k for k in MACOS_KEYCHAINS if os.path.exists(k)]
    if not keychains or not os.path.exists(MACOS_SECURITY):
        return ""
    try:
        # Fixed absolute path, no shell, no user-controlled arguments.
        result = subprocess.run(  # noqa: S603  # nosec B603
            [MACOS_SECURITY, "find-certificate", "-a", "-p", *keychains],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("could not read the macOS keychains: %s", exc)
        return ""
    if result.returncode != 0:
        log.warning("security find-certificate failed with exit code %s", result.returncode)
        return ""
    return result.stdout
