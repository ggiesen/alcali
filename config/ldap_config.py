import os
import ldap
from django_auth_ldap.config import LDAPGroupQuery, LDAPSearch, GroupOfNamesType

# List of permitted locals for eval()
EVAL_LOCALS = {
    "ldap": ldap,
    "LDAPGroupQuery": LDAPGroupQuery,
    "LDAPSearch": LDAPSearch,
    "GroupOfNamesType": GroupOfNamesType,
}

# Baseline configuration.
AUTH_LDAP_SERVER_URI = os.environ.get("AUTH_LDAP_SERVER_URI", "ldap://localhost")

AUTH_LDAP_BIND_DN = os.environ.get("AUTH_LDAP_BIND_DN", "")
AUTH_LDAP_BIND_PASSWORD = os.environ.get("AUTH_LDAP_BIND_PASSWORD", "")

if os.environ.get("AUTH_LDAP_USER_DN_TEMPLATE"):
    AUTH_LDAP_USER_DN_TEMPLATE = os.environ.get("AUTH_LDAP_USER_DN_TEMPLATE")
else:
    AUTH_LDAP_USER_SEARCH = LDAPSearch(
        os.environ.get("AUTH_LDAP_USER_BASE_CN", ""),
        ldap.SCOPE_SUBTREE,
        os.environ.get("AUTH_LDAP_USER_SEARCH_FILTER", "(objectClass=*)"),
    )

# An LDAPSearch object that finds all LDAP groups that users might belong to.
# If your configuration makes any references to LDAP groups, this and
# AUTH_LDAP_GROUP_TYPE must be set.
if os.environ.get("AUTH_LDAP_GROUP_SEARCH"):
    AUTH_LDAP_GROUP_SEARCH = eval(os.environ.get("AUTH_LDAP_GROUP_SEARCH"), {'__builtins__': None}, EVAL_LOCALS)

# An LDAPGroupType instance describing the type of group returned by AUTH_LDAP_GROUP_SEARCH.
if os.environ.get("AUTH_LDAP_GROUP_TYPE"):
    AUTH_LDAP_GROUP_TYPE = eval(os.environ.get("AUTH_LDAP_GROUP_TYPE"), {'__builtins__': None}, EVAL_LOCALS)

# Simple group restrictions
if os.environ.get("AUTH_LDAP_REQUIRE_GROUP"):
    AUTH_LDAP_REQUIRE_GROUP = eval(os.environ.get("AUTH_LDAP_REQUIRE_GROUP"), {'__builtins__': None}, EVAL_LOCALS)
if os.environ.get("AUTH_LDAP_DENY_GROUP"):
    AUTH_LDAP_DENY_GROUP = eval(os.environ.get("AUTH_LDAP_DENY_GROUP"), {'__builtins__': None}, EVAL_LOCALS)

# Define user flags based on group membership. Currently only "is_active" and "is_staff" are supported.
if os.environ.get("AUTH_LDAP_USER_FLAGS_BY_GROUP"):
    AUTH_LDAP_USER_FLAGS_BY_GROUP = eval(os.environ.get("AUTH_LDAP_USER_FLAGS_BY_GROUP"), {'__builtins__': None}, EVAL_LOCALS)

# Populate the Django user from the LDAP directory.
AUTH_LDAP_USER_ATTR_MAP = {
    "username": os.environ.get("AUTH_LDAP_USER_ATTR_MAP_USERNAME", "sAMAccountName"),
    "first_name": os.environ.get("AUTH_LDAP_USER_ATTR_MAP_FIRST_NAME", "givenName"),
    "last_name": os.environ.get("AUTH_LDAP_USER_ATTR_MAP_LAST_NAME", "sn"),
    "email": os.environ.get("AUTH_LDAP_USER_ATTR_MAP_EMAIL", "mail"),
}

# Use start_tls_s() to enable TLS encryption over the standard LDAP port.
if os.environ.get("AUTH_LDAP_START_TLS"):
    AUTH_LDAP_START_TLS = True

# This is the default.
AUTH_LDAP_ALWAYS_UPDATE_USER = True

# Mirror users' LDAP group membership in the Django database.
if os.environ.get("AUTH_LDAP_MIRROR_GROUPS"):
    AUTH_LDAP_MIRROR_GROUPS = True

# Keep ModelBackend around for per-user permissions and maybe a local
# superuser.
AUTHENTICATION_BACKENDS = (
    "django_auth_ldap.backend.LDAPBackend",
    "django.contrib.auth.backends.ModelBackend",
)
