# Setup

## 1. Requirements

- **Python 3.11 or newer** with the standard `venv` module.
- Network access to at least one domain controller on **636/tcp** (LDAPS), or on **389/tcp** for StartTLS.
  The global catalog uses **3269/tcp** (LDAPS) or **3268/tcp** (StartTLS).
- Domain controllers with a **server certificate** whose subject alternative names include the DC host
  name you connect to. AD CS auto-enrollment ("Domain Controller" / "Kerberos Authentication" templates)
  usually takes care of this.
- An account that can read the users and groups you query. Any ordinary domain user can read group
  membership by default, so use a dedicated, low-privilege service or admin account.

Check your Python:

| Platform | Command | Notes |
|---|---|---|
| macOS | `python3 --version` | Use Homebrew (`brew install python@3.13`) or the python.org installer. Apple's Command Line Tools `python3` may be too old |
| Debian/Ubuntu | `python3 --version` | `venv` is packaged separately: `sudo apt install python3-venv` |
| RHEL/Fedora | `python3 --version` | `sudo dnf install python3` (includes `venv`) |
| Windows | `py -3 --version` | Install from python.org or `winget install Python.Python.3.13`. The `py` launcher picks the newest version |

## 2. Get the code

```bash
git clone https://github.com/brett6320/ad-tools.git
cd ad-tools
```

## 3. Create and activate a virtual environment

A virtual environment keeps this project's packages apart from the system Python. Create it once in the
repository folder:

**macOS / Linux (bash, zsh)**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell)**

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
```

If PowerShell refuses to run the activation script, allow local scripts for your user once:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

**Windows (cmd.exe)**

```bat
py -3 -m venv .venv
.venv\Scripts\activate.bat
```

Once it's active, your prompt starts with `(.venv)` and `python` points at the venv's interpreter. Run
`deactivate` to leave it. Activate it again in each new shell, or call the interpreter directly without
activating: `.venv/bin/python` (or `.venv\Scripts\python.exe` on Windows).

Upgrade pip inside the venv:

```bash
python -m pip install --upgrade pip
```

## 4. Install

Pick one:

| Command | Gives you |
|---|---|
| `python -m pip install -e ".[truststore]"` | **Recommended.** The `ad-query` command and the `adtools` package (editable), plus `truststore` for OS-native certificate checks |
| `python -m pip install -e .` | Standard library only. Uses the `system` or `bundle` trust mode (see [TLS](tls.md)) |
| `python -m pip install -r requirements.txt` | Only `truststore`. Run the tools with `python -m adtools ...` from the repository folder |
| `python -m pip install -r requirements-dev.txt` | Everything for development: pytest, coverage, ruff, bandit, pip-audit |

Check it worked:

```bash
ad-query --version
python -m adtools --help     # works too, with or without the console script
```

## 5. Configure with `.env`

Copy the example file and edit it:

```bash
cp .env.example .env             # Windows: copy .env.example .env
```

| Variable | Default | Meaning |
|---|---|---|
| `AD_SERVER` | (required) | DC host name, or a comma-separated list tried in order. Use names that match the certificates, not IP addresses |
| `AD_DOMAIN` | | DNS domain (`corp.example.com`). Sets the search base to `DC=corp,DC=example,DC=com` when `AD_BASE_DN` is unset |
| `AD_BASE_DN` | from `AD_DOMAIN` | Search base, for example a single OU |
| `AD_TLS_MODE` | `ldaps` | `ldaps` (implicit TLS) or `starttls` (upgrade a 389 connection) |
| `AD_PORT` | by mode | `636` / `389`, or `3269` / `3268` with the global catalog |
| `AD_GLOBAL_CATALOG` | `false` | Query the forest-wide global catalog. With no base DN set, searches the whole forest |
| `AD_BIND_USER` | (anonymous) | `user@corp.example.com` (UPN), `CORP\user`, or a full DN |
| `AD_TRUST` | `auto` | `auto`, `truststore`, `system` or `bundle`. See [TLS](tls.md) |
| `AD_CA_FILE` / `AD_CA_PATH` | | PEM CA bundle, or a directory of hashed certificates, for the `bundle` mode |
| `AD_CLIENT_CERT` / `AD_CLIENT_KEY` | | Optional client certificate for mutual TLS |
| `AD_TIMEOUT` | `10` | Connect and read timeout, in seconds |
| `AD_PAGE_SIZE` | `500` | Paged-results page size. `0` turns paging off. AD's default MaxPageSize is 1000 |
| `AD_REPORTS_DIR` | `reports` | Where reports are written (relative to the current directory) |
| `AD_ENV_FILE` | | Path to a different `.env` file |

**Precedence:** CLI flags and Python keyword arguments override process environment variables, which
override the `.env` file, which overrides the defaults.

**Which `.env` is used:** the one named by `--env-file` or `AD_ENV_FILE` if set. Otherwise the nearest
`.env` in the current directory or a parent folder, then the nearest one in a parent of the installed
package (the repository root, for an editable install). The file is parsed with the standard library. It
supports `KEY=value`, `export KEY=value`, single or double quotes, and `#` comments. It never changes
`os.environ`.

You can keep several environments as separate files and pick one per run:

```bash
ad-query groups jdoe --env-file ~/.config/ad-tools/prod.env   # options go after the command
AD_ENV_FILE=lab.env ad-query members "Domain Admins"
```

### Passwords

**Passwords are never stored.** No setting holds a password. You are prompted for it (without it being
shown on screen) whenever a connection is made:

```
$ ad-query groups jdoe
Password for svc-ldap-ro@corp.example.com:
reports/user-groups/20261027-142233_jdoe.html
```

If `AD_PASSWORD` turns up in the environment or in a `.env` file, the tools refuse to run and tell you to
remove it. A run with no interactive terminal (cron, CI, a pipe on stdin) fails rather than reading a
password from anywhere else. Python callers can pass their own `password_prompt` callable, such as a GUI
dialog (see [Usage](usage.md#python-api)).

The `.env` file is in `.gitignore`. It holds no secrets, but it does name your servers and account.

## 6. Check the connection

```bash
ad-query search "(objectClass=domain)" --scope base --stdout
```

This binds, reads the domain object at the base DN, writes `reports/search/…_search.html` and prints a
text summary. If it fails:

| Error | Likely cause |
|---|---|
| `could not connect to any server: … timed out` | Firewall, wrong host, or wrong port. Test with `nc -vz dc1.corp.example.com 636` (or `Test-NetConnection dc1 -Port 636` in PowerShell) |
| `certificate verify failed: unable to get local issuer certificate` | The DC's CA isn't trusted. See [TLS: fixing certificate errors](tls.md#fixing-certificate-errors) |
| `certificate verify failed: Hostname mismatch` | `AD_SERVER` doesn't match the certificate. Use the DC's FQDN, not an IP address or alias |
| `bind failed: invalidCredentials … data 52e` | Wrong user name or password (`data 775` = locked out, `533` = disabled, `701`/`532` = expired) |
| `bind failed: strongerAuthRequired` | You connected without TLS, or channel binding is enforced. Use `ldaps` |
| `search failed: noSuchObject` | Wrong `AD_BASE_DN` / `AD_DOMAIN` |
| `a password prompt needs an interactive terminal` | Run it from a terminal. Passwords are never read from files or variables |

Add `-v` to any command for debug logging (the trust mode used, the server connected to).

## 7. Updating

```bash
cd ad-tools
git pull
source .venv/bin/activate
python -m pip install -e ".[truststore]"
```

To start over with a fresh environment, delete `.venv` and repeat steps 3 and 4.
