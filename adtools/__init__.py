"""Active Directory query tools over LDAPS/StartTLS, built on the Python standard library."""

from .ad import ADClient, AmbiguousError, CompareResult, GroupsResult, MembersResult, NotFoundError
from .config import ConfigError, Settings, load_settings
from .filters import FilterError, escape_filter_value
from .ldap import LDAPConnection, LDAPError
from .tls import TLSConfigError, build_ssl_context

__version__ = "0.1.0"

__all__ = [
    "ADClient",
    "AmbiguousError",
    "CompareResult",
    "ConfigError",
    "FilterError",
    "GroupsResult",
    "LDAPConnection",
    "LDAPError",
    "MembersResult",
    "NotFoundError",
    "Settings",
    "TLSConfigError",
    "build_ssl_context",
    "escape_filter_value",
    "load_settings",
]
