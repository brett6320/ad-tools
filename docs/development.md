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
| `tests/test_config.py` | `.env` parsing, discovery and precedence, and rejection of `AD_PASSWORD` |
| `tests/test_ad.py` | User/group lookups, direct, nested and primary-group membership, and comparisons, run against `tests/fakedir.py`. That in-memory directory evaluates the compiled BER filters, including `LDAP_MATCHING_RULE_IN_CHAIN` |
| `tests/test_report_cli.py` | HTML/JSON/CSV output (escaping, CSV formula neutralization), the CLI end to end, failover and password prompting |

`tests/conftest.py` clears `AD_*` variables and points `AD_ENV_FILE` at an empty file, so your own `.env`
never leaks into the tests.

## CI (GitHub Actions)

| Workflow | Runs |
|---|---|
| `tests.yml` | pytest with coverage on Ubuntu, macOS and Windows × Python 3.11, 3.12 and 3.13; a run without `truststore` (standard library only); and a smoke test that does `pip install .` and runs `ad-query` |
| `lint.yml` | ruff check and format, bandit, pip-audit. Also runs weekly |
| `codeql.yml` | CodeQL `security-extended` analysis of the Python code. Runs on pushes, PRs and weekly |
| `dependabot.yml` | Weekly update PRs for pip packages and GitHub Actions |

## Conventions

- **The runtime uses only the standard library.** `truststore` stays optional. Ask before adding a
  dependency.
- **The LDAP client is read-only.** Don't add modify, add, delete or modDN operations.
- **TLS is never optional, and no password setting is ever added.**
- Any user input that goes into a filter must go through `escape_filter_value`.
- Work on a branch and open a pull request. Don't commit to `main`.
