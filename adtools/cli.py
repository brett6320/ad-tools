"""Command-line interface: ``python -m adtools <command>`` (or the ``ad-query`` script)."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from . import __version__
from .ad import ADClient, AmbiguousError, NotFoundError
from .config import ConfigError, load_settings
from .filters import FilterError
from .ldap import TLS_MODES, LDAPError
from .report import (
    FORMATS,
    Report,
    compare_report,
    group_members_report,
    render_text,
    search_report,
    user_groups_report,
    write_report,
)
from .tls import TRUST_MODES, TLSConfigError

log = logging.getLogger("adtools")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    conn = common.add_argument_group("connection (defaults come from the environment or .env)")
    conn.add_argument("--env-file", help="path to a .env file (default: nearest .env)")
    conn.add_argument("--server", help="DC host name, or a comma-separated list tried in order (AD_SERVER)")
    conn.add_argument("--port", type=int, help="port (AD_PORT; default 636, 389 for StartTLS, 3269/3268 with --gc)")
    conn.add_argument("--tls-mode", choices=TLS_MODES, help="ldaps (implicit TLS) or starttls (AD_TLS_MODE)")
    conn.add_argument("--gc", dest="global_catalog", action="store_const", const=True, help="query the global catalog")
    conn.add_argument("--domain", help="DNS domain, used to derive the base DN (AD_DOMAIN)")
    conn.add_argument("--base-dn", help="search base (AD_BASE_DN)")
    conn.add_argument("--bind-user", help="UPN, DOMAIN\\user or DN to bind as (AD_BIND_USER)")
    conn.add_argument("--trust", choices=TRUST_MODES, help="certificate trust source (AD_TRUST)")
    conn.add_argument("--ca-file", help="PEM CA bundle; implies --trust bundle under auto (AD_CA_FILE)")
    conn.add_argument("--timeout", type=float, help="connect/read timeout in seconds (AD_TIMEOUT)")
    out = common.add_argument_group("output")
    out.add_argument(
        "--format",
        default="html",
        help=f"comma-separated report formats: {', '.join(FORMATS)} (default: html)",
    )
    out.add_argument("--reports-dir", help="where reports are written (AD_REPORTS_DIR; default: reports)")
    out.add_argument("--stdout", action="store_true", help="also print a plain-text summary")
    common.add_argument("-v", "--verbose", action="store_true", help="debug logging")

    parser = argparse.ArgumentParser(
        prog="ad-query",
        description="Query Active Directory over LDAPS or StartTLS and write HTML reports.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("groups", parents=[common], help="groups a user is a member of (direct and nested)")
    p.add_argument("user", help="sAMAccountName, email address, UPN, DOMAIN\\user or DN")
    p.add_argument("--direct-only", action="store_true", help="skip nested (transitive) groups")

    p = sub.add_parser("members", parents=[common], help="members of a group (direct and nested)")
    p.add_argument("group", help="group sAMAccountName, cn, email address or DN")
    p.add_argument("--direct-only", action="store_true", help="skip nested (transitive) members")

    p = sub.add_parser("compare", parents=[common], help="compare the group memberships of two users")
    p.add_argument("first", help="first user: sAMAccountName, email address, UPN or DN")
    p.add_argument("second", help="second user: sAMAccountName, email address, UPN or DN")
    p.add_argument("--direct-only", action="store_true", help="compare direct memberships only")

    p = sub.add_parser("search", parents=[common], help="run a raw LDAP filter")
    p.add_argument("filter", help="RFC 4515 filter, e.g. '(&(objectClass=user)(department=IT))'")
    p.add_argument("--attrs", default="cn,sAMAccountName,mail,objectClass", help="comma-separated attributes ('*' for all)")
    p.add_argument("--base", help="search base (default: the configured base DN)")
    p.add_argument("--scope", choices=("base", "one", "sub"), default="sub")
    p.add_argument("--limit", type=int, default=0, help="maximum entries (0 = no limit)")
    return parser


def _formats(value: str) -> tuple[str, ...]:
    formats = tuple(dict.fromkeys(f.strip().lower() for f in value.split(",") if f.strip()))
    bad = [f for f in formats if f not in FORMATS]
    if bad or not formats:
        raise ConfigError(f"--format must be a comma-separated list of: {', '.join(FORMATS)}")
    return formats


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
    try:
        formats = _formats(args.format)
        settings = load_settings(
            env_file=args.env_file,
            server=args.server,
            port=args.port,
            tls_mode=args.tls_mode,
            global_catalog=args.global_catalog,
            domain=args.domain,
            base_dn=args.base_dn,
            bind_user=args.bind_user,
            trust=args.trust,
            ca_file=args.ca_file,
            timeout=args.timeout,
            reports_dir=args.reports_dir,
        )
        with ADClient(settings) as ad:
            report = _run(ad, args)
    except (ConfigError, TLSConfigError, FilterError, NotFoundError, AmbiguousError, LDAPError, OSError) as exc:
        log.error("%s", exc)
        return 2
    for path in write_report(report, settings.reports_dir, formats):
        print(path)
    if args.stdout:
        print(render_text(report), end="")
    return 0


def _run(ad: ADClient, args: argparse.Namespace) -> Report:
    nested = not getattr(args, "direct_only", False)
    if args.command == "groups":
        return user_groups_report(ad.user_groups(args.user, nested=nested))
    if args.command == "members":
        return group_members_report(ad.group_members(args.group, nested=nested))
    if args.command == "compare":
        return compare_report(ad.compare_users(args.first, args.second, nested=nested))
    attrs = [a.strip() for a in args.attrs.split(",") if a.strip()]
    base = ad.settings.search_base if args.base is None else args.base
    objects = list(ad.search(args.filter, attrs, base=base, scope=args.scope, size_limit=args.limit))
    return search_report(args.filter, base, objects, [] if attrs == ["*"] else attrs)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
