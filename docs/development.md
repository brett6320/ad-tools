# Development

## Environment

```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m pip install -e .
```

## Checks

Run these before opening a pull request. CI runs the same ones.

```bash
python -m pytest                                   # unit + protocol + TLS tests
python -m pytest --cov --cov-report=term-missing   # with coverage
ruff check .                                       # lint (pyflakes, pycodestyle, bugbear, bandit rules, ...)
ruff format --check .                              # formatting
bandit -c pyproject.toml -r adtools                # security static analysis
pip-audit -r requirements.txt -r requirements-dev.txt   # known-vulnerable dependencies
```

## How the tests work

No real directory is needed:

| File | Covers |
|---|---|
| `tests/test_ber_filters.py` | BER encoding/decoding limits, the RFC 4515 filter parser and escaping (including injection attempts) |
| `tests/test_ldap.py` | The LDAP wire protocol against `tests/fakeldap.py`, a scripted server on a socket pair: bind, result codes, paging cookies, referrals, chunked reads, disconnects |
| `tests/test_tls.py` | Real TLS handshakes against a local server, with a throwaway CA and certificate made by the `openssl` CLI. Covers LDAPS and StartTLS, hostname mismatch, untrusted CA, and each trust mode's loading logic (macOS keychain export and the Linux bundle fallback are mocked). The handshake tests are skipped if `openssl` isn't installed |
| `tests/test_config.py` | `.env` parsing, discovery and precedence, rejection of `AD_PASSWORD`, and how the bind name is built from `AD_BIND_DOMAIN` |
| `tests/test_dns.py` | DC discovery: DNS wire format (name compression, loops, truncation), a local UDP/TCP DNS server, SRV ordering, site-first lookup, rejection of DCs outside the domain, the fallback to the domain name, and name server discovery from `resolv.conf` / `scutil` |
| `tests/test_report_browser.py` | Loads real HTML reports in headless Chrome (when installed; skipped otherwise) and drives the column filters, sorting, quick search and the tree's Expand/Collapse with `tests/fixtures/report_harness.js` |
| `tests/test_entrypoints.py` | Every tracked script with a `#!` line has the execute bit in git, and `./ad-query` and `python -m adtools` both run |
| `tests/test_ad.py` | User/group lookups, direct, nested and primary-group membership, and comparisons, run against `tests/fakedir.py`. That in-memory directory evaluates the compiled BER filters. Also covers level-by-level nesting with the "via" paths, loops, diamonds, batching, and a guard that no in-chain queries are sent |
| `tests/test_report_cli.py` | HTML/JSON/CSV output (escaping, CSV formula neutralization), the CLI end to end, failover and password prompting |

`tests/conftest.py` clears `AD_*` variables and points `AD_ENV_FILE` at an empty file, so your own `.env`
never leaks into the tests.

## CI (GitHub Actions)

| Workflow | Runs |
|---|---|
| `tests.yml` | pytest with coverage on Ubuntu, macOS and Windows × Python 3.11, 3.12 and 3.13; a run without `truststore` (standard library only); and a smoke test that does `pip install .` and runs `ad-query`. Each job writes a results table to the job summary. On `main`, the Ubuntu / Python 3.13 numbers are published to the `badges` branch (`.github/scripts/test_report.py`), which is where the README's test-count and coverage badges come from |
| `lint.yml` | ruff check and format, bandit, pip-audit. Also runs weekly |
| `codeql.yml` | CodeQL `security-extended` analysis of the Python code. Runs on pushes, PRs and weekly |
| `dependabot.yml` | Weekly update PRs for pip packages and GitHub Actions |

## Conventions

- **The runtime uses only the standard library.** `truststore` stays optional. Ask before adding a
  dependency.
- **The LDAP client is read-only.** Don't add modify, add, delete or modDN operations.
- **TLS is never optional, and no password setting is ever added.**
- Any user input that goes into a filter must go through `escape_filter_value`.
- Scripts with a `#!` line must be executable in git: `chmod +x FILE && git update-index --chmod=+x FILE`.
  `tests/test_entrypoints.py` enforces this.
- Work on a branch and open a pull request. Don't commit to `main`.
