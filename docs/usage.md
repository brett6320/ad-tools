# Usage

Activate the virtual environment first (`source .venv/bin/activate`, or `.venv\Scripts\Activate.ps1` on
Windows). Run commands as `ad-query <command> …`, or as `python -m adtools <command> …`.

Options go **after** the command (`ad-query groups jdoe --format json`). Every command takes the connection
options (`--server`, `--domain`, `--base-dn`, `--bind-user`, `--bind-domain`, `--tls-mode`, `--gc`, `--port`, `--trust`,
`--ca-file`, `--timeout`, `--env-file`) and the output options below. For anything you don't pass, the
value comes from the environment or `.env` (see [Setup](setup.md#5-configure-with-env)).

## Output

| Option | Default | Meaning |
|---|---|---|
| `--format` | `html` | Comma-separated: `html`, `json`, `csv`, for example `--format html,csv` |
| `--reports-dir` | `reports` (`AD_REPORTS_DIR`) | Base folder for reports |
| `--stdout` | off | Also print a plain-text summary to the terminal |
| `-v` | off | Debug logging |

Reports are written to `<reports-dir>/<report type>/<UTC timestamp>_<subject>.<format>`, and each path is
printed:

| Command | Folder | Example file |
|---|---|---|
| `groups` | `user-groups/` | `20261027-142233_jdoe.html` |
| `members` | `group-members/` | `20261027-142301_VPN-Users.html` |
| `compare` | `compare/` | `20261027-142410_jdoe_vs_asmith.html` |
| `search` | `search/` | `20261027-142502_search.html` |

- **HTML** is one self-contained file with no external requests, so you can open it offline, email it or
  attach it to a ticket. It has a summary panel, and tables you can click to sort and filter as you type.
  It follows the light or dark setting of the system. A coloured pill shows how each row is connected:
  *direct*, *nested* or *primary group*. Disabled accounts are highlighted.
- **JSON** has `report`, `title`, `generated`, `summary` and `sections[].rows[]`, for scripting.
- **CSV** has one row per table row, with a `section` column (for example `Only jdoe`, `In common`).

Reports contain directory data. The `reports/` folder is in `.gitignore`.

## How users and groups are looked up

`USER` can be any of the following. Exactly one object must match: no match exits with "no match", and
more than one lists the DNs that matched.

| Form | Example | Matched against |
|---|---|---|
| sAMAccountName | `jdoe` | `sAMAccountName` |
| Email address | `john.doe@corp.example.com` | `mail`, `userPrincipalName` and any `proxyAddresses` alias (`smtp:`), as well as `sAMAccountName` |
| UPN | `jdoe@corp.example.com` | Same as an email address |
| Down-level name | `CORP\jdoe` | The part after `\` as `sAMAccountName` |
| Distinguished name | `CN=John Doe,OU=Users,DC=corp,DC=example,DC=com` | Read directly |

Users are matched among `objectCategory=person` and computer objects. `GROUP` takes a sAMAccountName,
`cn`, email address or DN, matched among `objectClass=group`. Matching is case-insensitive (AD's rule).
Quote names that contain spaces, and on Windows quote `CORP\jdoe` too.

## `groups`: which groups is a user in?

```bash
ad-query groups jdoe
ad-query groups john.doe@corp.example.com --stdout
ad-query groups jdoe --direct-only --format html,csv
```

Each group is listed with its membership:

- **direct**: the user is in the group's `member` attribute.
- **primary group**: the user's `primaryGroupID` (usually *Domain Users*). AD doesn't record this in
  `member`/`memberOf`, so most tools miss it. Here it's resolved from the user's SID.
- **nested**: membership through other groups, at any depth. The domain controller works this out with
  `LDAP_MATCHING_RULE_IN_CHAIN` (`1.2.840.113556.1.4.1941`), which also covers groups the primary group
  is nested in.

`--direct-only` lists the direct groups and the primary group only. The table also shows each group's
scope (Global / Domain local / Universal), its type (Security / Distribution), email and description.

## `members`: who is in a group?

```bash
ad-query members "VPN Users"
ad-query members vpn-users@corp.example.com --format csv
ad-query members "Domain Admins" --direct-only
```

Lists users, groups, computers, contacts and foreign security principals:

- **direct**: listed in the group's `member` attribute (including nested groups themselves).
- **primary group**: accounts whose `primaryGroupID` is this group (for example everyone in *Domain Users*).
- **nested**: members of member groups, at any depth.

The summary counts direct, nested-only, users, groups and total. Disabled user and computer accounts are
flagged in the `disabled` column.

Large groups are fine: members are found by searching `memberOf` with paged results, rather than reading
the group's `member` attribute. That avoids AD's 1,500-value range limit on the attribute.

## `compare`: how do two users' groups differ?

```bash
ad-query compare jdoe asmith
ad-query compare john.doe@corp.example.com alice@corp.example.com
ad-query compare jdoe asmith --direct-only
```

The report has three tables:

1. **Only USER1**: groups the first user is in and the second isn't. Useful for "give B the same access as A".
2. **Only USER2**: the reverse.
3. **In common**: groups both are in, with a column for each user showing how they're a member. A group can
   be *direct* for one user and *nested* for the other.

Nested groups are included by default, so the comparison reflects effective group membership.
`--direct-only` compares only explicit memberships (plus primary groups). That's what you'd change in
ADUC to make the two users match.

## `search`: any LDAP filter

```bash
ad-query search "(&(objectCategory=person)(department=Finance))" --attrs cn,mail,title
ad-query search "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" --attrs sAMAccountName
ad-query search "(objectClass=organizationalUnit)" --scope one --attrs ou,description
ad-query search "(cn=*)" --base "OU=Servers,DC=corp,DC=example,DC=com" --limit 50 --attrs "*"
```

| Option | Default | Meaning |
|---|---|---|
| `--attrs` | `cn,sAMAccountName,mail,objectClass` | Attributes to return. `*` returns all of them, and the columns are worked out from the results |
| `--base` | the configured base DN | Search base |
| `--scope` | `sub` | `base`, `one` or `sub` |
| `--limit` | `0` (no limit) | Maximum number of entries |

Filters follow RFC 4515: `&`, `|`, `!`, `=`, `>=`, `<=`, `~=`, `=*` (present), substrings (`a*b*c`) and
extensible matches (`attr:rule:=value`, `attr:dn:=value`). Special characters in values must be escaped
as `\2a` (`*`), `\28` (`(`), `\29` (`)`), `\5c` (`\`) and `\00`.

Values are decoded to readable text where that makes sense:

| Attribute | Shown as |
|---|---|
| `objectSid`, `sIDHistory` | `S-1-5-21-…` |
| `objectGUID` | GUID string |
| `pwdLastSet`, `lastLogon`, `lastLogonTimestamp`, `accountExpires`, `badPasswordTime`, `lockoutTime` | ISO 8601 UTC, or empty for "never" |
| `whenCreated`, `whenChanged` | ISO 8601 UTC |
| Other binary values | `base64:…` |

## Global catalog and multi-domain forests

`--gc` (or `AD_GLOBAL_CATALOG=true`) connects to port 3269 (LDAPS) or 3268 (StartTLS). With no base DN set,
it searches the whole forest. The global catalog only holds a partial set of attributes for each object
(`mail`, `member` and `memberOf` are included), and universal-group membership is complete across the
forest. Use a domain controller in the user's own domain for authoritative domain-local groups.

## Python API

```python
from adtools import ADClient

# Anything not passed comes from the environment / .env. You're prompted for the password on connect.
with ADClient(server="dc1.corp.example.com", domain="corp.example.com", bind_user="svc-ldap-ro@corp.example.com") as ad:
    result = ad.user_groups("john.doe@corp.example.com")  # nested=True by default
    for m in result.groups:
        print(m.via, m.obj.name, m.obj.dn)

    members = ad.group_members("VPN Users", nested=True)
    diff = ad.compare_users("jdoe", "asmith")
    print([m.obj.name for m in diff.only_first])

    for obj in ad.search("(&(objectCategory=person)(title=*Engineer*))", ["cn", "mail"]):
        print(obj.dn, obj.get("mail"))
```

Write reports from Python:

```python
from adtools.report import user_groups_report, compare_report, write_report

paths = write_report(user_groups_report(result), "reports", ("html", "json"))
```

To prompt some other way (a GUI, a secrets broker that asks the user), pass a callable. It's called once
per `connect()`, and the value is used only for the bind:

```python
ADClient(password_prompt=lambda prompt: my_dialog(prompt))
```

There's no `password=` argument. Passing one raises `TypeError`.

Other building blocks:

| Name | Use |
|---|---|
| `adtools.escape_filter_value(value)` | Escape untrusted input before putting it in a filter: `f"(cn={escape_filter_value(name)})"` |
| `adtools.load_settings(**kwargs)` | Resolve settings (kwargs, then environment, then `.env`, then defaults) without connecting |
| `adtools.build_ssl_context(trust, ca_file, ...)` | The verifying `SSLContext` the client uses |
| `adtools.LDAPConnection` | Low-level client: `open()`, `bind()`, `search()` (yields raw entries, follows paging), `close()` |

Exceptions: `ConfigError` (settings), `TLSConfigError` (trust setup), `LDAPError` (with `.code` and
`.diagnostic` from the server), `NotFoundError`, `AmbiguousError`, and `FilterError` (invalid filter).
If no server can be reached, `ADClient.connect()` raises `LDAPError("could not connect to any server: …")`,
with the reason for each host. Certificate failures show up there as `CERTIFICATE_VERIFY_FAILED`. Rejected
credentials are raised straight away, without trying the next server, so a bad password can't lock the
account by being tried on every DC.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Report written |
| `2` | Configuration, TLS, LDAP, lookup (not found / ambiguous) or filter error. The message is logged to stderr |
