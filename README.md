# AD Tools

[![CodeQL](https://github.com/brett6320/ad-tools/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/brett6320/ad-tools/actions/workflows/codeql.yml) [![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Fad-tools%2Fbadges%2Ftotal-tests.json)](https://github.com/brett6320/ad-tools/actions/workflows/tests.yml) [![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Fad-tools%2Fbadges%2Ftotal-coverage.json)](https://github.com/brett6320/ad-tools/actions/workflows/tests.yml) [![Lint and security](https://github.com/brett6320/ad-tools/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/brett6320/ad-tools/actions/workflows/lint.yml) ![Python 3.11 | 3.12 | 3.13](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-3776AB?logo=python&logoColor=white) [![License: custom](https://img.shields.io/badge/license-custom-lightgrey)](LICENSE) ![Dependabot](https://img.shields.io/badge/dependabot-enabled-025E8C?logo=dependabot)

Command-line tools and a small Python library for querying Active Directory over **LDAPS** or **StartTLS**.
The LDAP client is written on the Python standard library (`ssl`, `socket`), so nothing else is needed.
[`truststore`](https://pypi.org/project/truststore/) is optional and recommended, for checking certificates
against the operating system's own trust store.

| Command | What it does |
|---|---|
| `groups USER` | Groups a user belongs to: direct, nested (transitive) and their primary group. Look the user up by sAMAccountName or email address (also UPN, `DOMAIN\user` or DN) |
| `members GROUP` | Members of a group: direct, nested, and accounts that have it as their primary group |
| `compare USER1 USER2` | Compare two users' group memberships: groups only the first is in, groups only the second is in, and groups they share (showing how each one is a member) |
| `search FILTER` | Run any RFC 4515 LDAP filter |

By default every command writes a self-contained **HTML report** under `reports/<command>/`. You can sort
and filter its tables in the browser. JSON and CSV are also available.

```
reports/
├── user-groups/20261027-142233_jdoe.html
├── group-members/20261027-142301_VPN-Users.html
├── compare/20261027-142410_jdoe_vs_asmith.html
└── search/20261027-142502_search.html
```

## Quick start

```bash
git clone https://github.com/brett6320/ad-tools.git && cd ad-tools
python3 -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[truststore]"

cp .env.example .env               # then set AD_DOMAIN and AD_BIND_USER (or AD_BIND_DOMAIN); DCs are found via DNS
ad-query groups jdoe               # you are prompted for the bind password
ad-query groups john.doe@corp.example.com
ad-query members "VPN Users"
ad-query compare jdoe asmith
./ad-query groups jdoe             # or run straight from the checkout, without installing
```

## Documentation

- [Setup](docs/setup.md): Python and venv on macOS, Linux and Windows, installing, the `.env` file,
  service accounts, and checking the connection
- [Usage](docs/usage.md): each command, how users and groups are looked up, nested membership, reports,
  and the Python API
- [TLS and certificate trust](docs/tls.md): LDAPS vs StartTLS, the `truststore`, `system` and `bundle` trust
  modes on each platform, and fixing certificate errors
- [Development](docs/development.md): tests, linting, CodeQL and the other CI checks

## Security

- **Encryption is required.** A bind never goes over plain LDAP. Certificate verification and hostname checks
  are always on, and the minimum version is TLS 1.2. Nothing can turn verification off.
- **Passwords are never stored.** You are prompted for the bind password every time a connection is made.
  `AD_PASSWORD` is rejected wherever it is set, and the password is never kept on the settings or client objects.
- **Read-only.** The tools only send bind, search and unbind requests.
- **Injection-safe.** Any value used in a filter is escaped (RFC 4515), and HTML reports escape all
  directory content. CSV cells that start with a formula character get a leading quote, so spreadsheets
  don't run them.

## License

Custom license, see [LICENSE](LICENSE). Personal, educational, research, non-profit and internal use is free.
Using the tools commercially to support clients needs a separate written agreement.
