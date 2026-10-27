# TLS and certificate trust

Every connection is encrypted before credentials are sent, and there is no way to turn verification off:

- `CERT_REQUIRED`: the server certificate must chain to a trusted CA.
- `check_hostname`: the certificate must name the host in `AD_SERVER`. Connect by FQDN, not by IP address.
- TLS 1.2 or later.

## LDAPS or StartTLS

| `AD_TLS_MODE` | Port | How it works |
|---|---|---|
| `ldaps` (default) | 636 (GC 3269) | TLS from the first byte, like HTTPS |
| `starttls` | 389 (GC 3268) | Plain connection, then the StartTLS extended operation (`1.3.6.1.4.1.1466.20037`), then the TLS handshake. Nothing else is sent until TLS is up. If the server refuses StartTLS, the connection is dropped and is never used unencrypted |

Both use the same certificate on a domain controller. Use `starttls` when only 389 is open through a
firewall.

## Trust modes

Set `AD_TRUST` (or `--trust`) to choose where trusted CA certificates come from.

### `auto` (default)

1. `bundle` if `AD_CA_FILE` or `AD_CA_PATH` is set.
2. Otherwise `truststore`, if the package is installed.
3. Otherwise `system`.

Run with `-v` to log which mode was used, or `--debug` to see the certificate the DC presented.

### `truststore`: the operating system verifies the certificate

Needs `pip install truststore` (installed by the `[truststore]` extra). Certificate checking is handed to
the OS's own TLS trust machinery:

| Platform | Verifier | Honours |
|---|---|---|
| macOS | Security.framework (`SecTrust`) | System and login keychains, MDM-pushed roots, **trust settings** (including roots marked "Never Trust"), revocation as the OS does it |
| Windows | CryptoAPI (`CertGetCertificateChain`) | Machine and user stores, roots pushed by Group Policy (your AD CS root usually arrives this way on domain-joined PCs), automatic root updates |
| Linux | OpenSSL with the system CA paths | The distro bundle, including CAs added with `update-ca-certificates` / `update-ca-trust` |

This is the best choice on managed corporate machines: if your browser trusts the DC's CA, this will too.

### `system`: built-in trust stores, standard library only

No third-party packages. What gets loaded depends on the platform:

| Platform | Source |
|---|---|
| Windows | `SSLContext.load_default_certs()`, which reads the Windows **ROOT** and **CA** certificate stores (`ssl.enum_certificates`) |
| Linux / BSD | OpenSSL's built-in default paths. If those are empty, the first of these that exists: `/etc/ssl/certs/ca-certificates.crt` (Debian/Ubuntu/Alpine/Arch), `/etc/pki/tls/certs/ca-bundle.crt` (RHEL/Fedora), `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`, `/etc/ssl/ca-bundle.pem` (openSUSE), `/etc/ssl/cert.pem`, `/usr/local/share/certs/ca-root-nss.crt` (FreeBSD) |
| macOS | OpenSSL default paths, plus the certificates exported by `/usr/bin/security find-certificate -a -p` from the **System Roots** and **System** keychains (where MDM and admins install corporate roots) |

macOS caveat: exporting the keychains gives you certificates, **not their trust settings**. A root an
administrator has explicitly distrusted is still trusted in this mode, and roots that exist only in your
login keychain aren't included. Use `truststore` on macOS when that matters.

If no CA certificates are found at all, a warning is logged and every connection fails verification.

### `bundle`: only the CAs you name

```dotenv
AD_TRUST=bundle
AD_CA_FILE=/etc/ad-tools/corp-ca-chain.pem      # one or more PEM certificates
# AD_CA_PATH=/etc/ad-tools/certs                # or a c_rehash'd directory
```

Only these CAs are trusted, and the OS store is ignored. Use this mode for a lab domain, a private AD CS
hierarchy on a machine that doesn't trust it, or to pin trust to your own PKI. With `auto`, setting
`AD_CA_FILE` already selects `bundle`.

#### Exporting your AD CS root as PEM

On a domain-joined Windows machine (PowerShell):

```powershell
Get-ChildItem Cert:\LocalMachine\Root | Where-Object Subject -like "*Corp Root CA*" |
  ForEach-Object { "-----BEGIN CERTIFICATE-----"; [Convert]::ToBase64String($_.RawData, 'InsertLineBreaks'); "-----END CERTIFICATE-----" } |
  Set-Content -Encoding ascii corp-root-ca.pem
```

Or from any machine that can reach the DC, look at the chain it presents (the last certificate is closest
to the root; check it with your PKI team before trusting it):

```bash
openssl s_client -connect dc1.corp.example.com:636 -showcerts </dev/null
```

Or convert a DER `.cer` file: `openssl x509 -inform der -in corp-root-ca.cer -out corp-root-ca.pem`.

Include any intermediate (issuing) CAs as well if the DC doesn't send them.

## Client certificates (optional)

`AD_CLIENT_CERT` and `AD_CLIENT_KEY` load a client certificate for mutual TLS, for directories or proxies
that require one. The simple bind with a password still happens.

## Fixing certificate errors

| Message | Fix |
|---|---|
| `unable to get local issuer certificate` / `self-signed certificate in certificate chain` | The issuing CA isn't trusted. Install it in the OS store (then use `truststore`/`system`), or point `AD_CA_FILE` at it |
| `Hostname mismatch, certificate is not valid for '10.0.0.5'` | Use the DC's FQDN in `AD_SERVER`. If you must use an alias, the certificate needs that name in its SAN |
| `certificate has expired` | Renew the DC certificate (check auto-enrollment) |
| Works in `truststore` but not in `system` on macOS | The root is in your login keychain, or depends on trust settings. Use `truststore`, or export it to a bundle |
| `connection reset` straight after connecting on 636 | No certificate is bound to LDAPS on that DC. Check with `openssl s_client -connect host:636` |
