"""Who may write.

The role catalog in :mod:`api.security.rbac` names roles that read: ``auditor``
("read-only access to all reports"), ``readonly`` ("dashboard view only"),
``developer`` and ``business_owner`` ("view findings"). Guide 121 measured that
180 write operations were reachable by *any* authenticated principal, viewer
included — so those names were false. This module makes them true for human
sessions.

Rule: a human principal holding only read-only roles may not call a mutating
method. Machine credentials are not covered here — an API key's authority is
its own policy (``allowed_methods``, ``allowed_ips``, quota) and it carries its
own role list, which the key resolver already enforces; applying a user-role
rule to a collector key would break ingestion without tightening anything.

Self-service is exempt: rotating your own password, enrolling MFA, ending your
own sessions and logging out are things a read-only user must still be able to
do, and they act only on the caller's own account.
"""

from __future__ import annotations

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: Roles the catalog itself describes as read-only. Everything else in the
#: catalog owns some mutation — ``business_owner`` reviews changes to systems it
#: owns, ``developer`` files findings, ``scanner`` submits jobs — so this is a
#: deny-list of the roles whose *name* promises they cannot write, not a guess
#: at who should be allowed to do what.
READ_ONLY_ROLES = frozenset({"readonly", "auditor", "supervisor"})

#: Session lifecycle and self-service: a read-only user still has an account.
SELF_SERVICE_PREFIXES = (
    "/api/v1/auth/",
)

#: Recording an independent attestation is not changing platform state. An
#: ``auditor`` is the role that *signs* these — that is what independence means
#: here — and each handler still enforces its own assignment rules (the reviewer
#: must be assigned to that record and to that tenant), which the drills measure.
#: Kept to exact path suffixes so nothing else inherits the exemption.
ATTESTATION_SUFFIXES = (
    "/reviews",
    "/truth/approve",
)

ERROR_CODE = "WRITE_FORBIDDEN"


def is_write(method: str) -> bool:
    return str(method or "").upper() in WRITE_METHODS


def is_self_service(path: str) -> bool:
    """True for the caller's own session/credential lifecycle."""
    clean = str(path or "").rstrip("/") or "/"
    return any(clean.startswith(prefix.rstrip("/")) for prefix in SELF_SERVICE_PREFIXES)


def is_attestation(path: str) -> bool:
    """True for endpoints that record a signed statement rather than mutate state."""
    clean = str(path or "").rstrip("/")
    return any(clean.endswith(suffix) for suffix in ATTESTATION_SUFFIXES)


def refusal(roles: list[str] | tuple[str, ...] | None, method: str, path: str) -> str | None:
    """``None`` when the call is allowed, else the reason it is not.

    Fails closed on an empty or unreadable role set: an identity we cannot
    describe is not an identity we can authorize.
    """
    if not is_write(method):
        return None
    if is_self_service(path) or is_attestation(path):
        return None
    from api.security.rbac import normalize_roles

    granted = set(normalize_roles(roles))
    if not granted:
        return "no recognized role"
    read_only = granted & READ_ONLY_ROLES
    if read_only and not granted - READ_ONLY_ROLES:
        return f"role {', '.join(sorted(read_only))} may read but not write"
    return None
