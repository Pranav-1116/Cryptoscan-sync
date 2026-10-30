"""Schannel protocol and cipher policy — the Windows host's own TLS floor.

This closes the largest stated Windows gap that is closable without kernel or
ETW access: *what does this host's Schannel stack actually allow?* The answer
lives in the registry, and three keys decide it:

    HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\<proto>\\<role>
        Enabled           1 = offered, 0 = not offered
        DisabledByDefault 1 = not offered unless an application asks for it

    HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002
        Functions         the ordered cipher-suite list a policy administrator set

What this establishes — and it matters, because it is *not* observation:

* a protocol that is disabled cannot be negotiated by anything on the host;
* a protocol that is enabled is **permitted**, not used: an application that
  pins TLS 1.2 will use TLS 1.2 whatever the floor says;
* the cipher-suite order is a preference list, not a report of what any
  connection negotiated.

So this collector answers "what is this host allowed to do", and the Windows
matrix keeps the invocation gap open. Confusing the two is exactly the failure
mode the runtime-depth matrix exists to prevent.

The reader is injected (`reader(path) -> mapping`) so the evaluation logic is
testable on Linux, where the whole platform runs. The native reader is a thin
`winreg` wrapper that refuses with a `Refused("UNAVAILABLE", ...)` off Windows.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

SCHEMA = "cryptoscan.windows-schannel/1"

PROTOCOLS_KEY = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
CIPHER_ORDER_KEY = (
    r"SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
)
CIPHER_PREFERENCE_KEY = r"SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"

#: the protocol subkeys Schannel uses, and the version each one means
PROTOCOL_KEYS: dict[str, str] = {
    "SSL 2.0": "SSLv2",
    "SSL 3.0": "SSLv3",
    "TLS 1.0": "TLSv1.0",
    "TLS 1.1": "TLSv1.1",
    "TLS 1.2": "TLSv1.2",
    "TLS 1.3": "TLSv1.3",
    "DTLS 1.0": "DTLSv1.0",
    "DTLS 1.2": "DTLSv1.2",
}

#: versions a bank should not be offering. Kept here rather than derived so the
#: judgement is explicit and reviewable; it mirrors the platform's TLS floor.
DEPRECATED_VERSIONS: frozenset[str] = frozenset(
    {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "DTLSv1.0"}
)

ROLE_SERVER = "Server"
ROLE_CLIENT = "Client"

Reader = Callable[[str], Mapping[str, Mapping[str, Any]] | None]


def windows_reader() -> Reader:
    """The native reader: one registry key's subkeys and values, or ``None``."""

    def read(path: str) -> Mapping[str, Mapping[str, Any]] | None:
        import sys

        if sys.platform != "win32":
            from inventory.host import Refused

            raise Refused("UNAVAILABLE", "PLATFORM")
        import winreg

        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
        except FileNotFoundError:
            return None
        except PermissionError:
            from inventory.host import Refused

            raise Refused("UNAVAILABLE", "PERMISSION") from None
        try:
            values: dict[str, Any] = {}
            index = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(root, index)
                except OSError:
                    break
                values[name] = value
                index += 1
                if index > 512:
                    break
            return {**values, "__subkeys__": _subkeys(root)}
        finally:
            winreg.CloseKey(root)

    return read


def _subkeys(key: Any) -> dict[str, dict[str, Any]]:
    import winreg

    subkeys: dict[str, dict[str, Any]] = {}
    index = 0
    while True:
        try:
            name = winreg.EnumKey(key, index)
        except OSError:
            break
        index += 1
        if index > 64:
            break
        try:
            child = winreg.OpenKey(key, name, 0, winreg.KEY_READ)
        except OSError:
            continue
        try:
            values: dict[str, Any] = {}
            value_index = 0
            while True:
                try:
                    value_name, value, _ = winreg.EnumValue(child, value_index)
                except OSError:
                    break
                values[value_name] = value
                value_index += 1
                if value_index > 64:
                    break
            subkeys[name] = values
        finally:
            winreg.CloseKey(child)
    return subkeys


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"0", "false", "disabled"}:
            return False
        if lowered in {"1", "true", "enabled"}:
            return True
    return None


def _role_state(role_values: Mapping[str, Any] | None) -> dict[str, Any]:
    """Resolve one protocol/role from its two DWORDs.

    Absent keys are ``enabled: None`` — *unknown*, not enabled. Windows ships
    built-in defaults per version, and this build does not reproduce them: a
    table copied from documentation would be a guess presented as a measurement.
    What the reader can state honestly is which versions an administrator
    explicitly enabled or disabled, and that a stock host is on the default.
    """
    if role_values is None:
        return {
            "state": "DEFAULT",
            "enabled": None,
            "reason": "no key for this protocol/role — Windows' built-in default applies",
        }
    enabled = _as_bool(role_values.get("Enabled"))
    disabled_by_default = _as_bool(role_values.get("DisabledByDefault"))
    if disabled_by_default:
        return {
            "state": "DISABLED_BY_DEFAULT",
            "enabled": bool(enabled),
            "reason": "not offered unless an application explicitly asks for it",
        }
    if enabled is None:
        return {
            "state": "DEFAULT",
            "enabled": None,
            "reason": "key exists without a readable Enabled value — the built-in default applies",
        }
    return {
        "state": "ENABLED" if enabled else "DISABLED",
        "enabled": enabled,
        "reason": None,
    }


def evaluate(reader: Reader) -> dict[str, Any]:
    """Read and evaluate a host's Schannel policy.

    Three sets are kept apart on purpose: versions an administrator explicitly
    offered, versions explicitly disabled, and versions left on Windows'
    default (unknown to this build). Collapsing the third into either of the
    first two is how a stock host gets reported as a hardened one or a broken
    one.
    """
    protocols: dict[str, Any] = {}
    offered: list[str] = []
    disabled: list[str] = []
    unconfigured: list[str] = []
    deprecated_enabled: list[str] = []
    for subkey, version in PROTOCOL_KEYS.items():
        raw = reader(f"{PROTOCOLS_KEY}\\{subkey}") or {}
        subkeys = raw.get("__subkeys__") if isinstance(raw, dict) else None
        subkeys = subkeys if isinstance(subkeys, dict) else {}
        server = _role_state(subkeys.get(ROLE_SERVER))
        client = _role_state(subkeys.get(ROLE_CLIENT))
        states = {server["enabled"], client["enabled"]}
        if True in states:
            offered.append(version)
            if version in DEPRECATED_VERSIONS:
                deprecated_enabled.append(version)
        elif states == {False}:
            disabled.append(version)
        else:
            unconfigured.append(version)
        protocols[version] = {
            "registry_key": f"{PROTOCOLS_KEY}\\{subkey}",
            "server": server,
            "client": client,
            "offered": True if True in states else False if states == {False} else None,
            "deprecated": version in DEPRECATED_VERSIONS,
        }

    order_raw = reader(CIPHER_ORDER_KEY) or {}
    preference_raw = reader(CIPHER_PREFERENCE_KEY) or {}
    order = _suite_order(order_raw) or _suite_order(preference_raw)
    order_source = (
        CIPHER_ORDER_KEY
        if _suite_order(order_raw)
        else CIPHER_PREFERENCE_KEY
        if _suite_order(preference_raw)
        else None
    )

    floor = _floor(offered)
    return {
        "schema": SCHEMA,
        "protocols": protocols,
        "offered_versions": offered,
        "disabled_versions": disabled,
        "unconfigured_versions": unconfigured,
        "deprecated_versions_enabled": deprecated_enabled,
        "tls_floor": floor,
        "tls_floor_basis": (
            "the lowest version explicitly enabled in this host's Schannel policy"
            if floor
            else "no version is explicitly enabled, so this host is on Windows' built-in policy and "
            "this build does not reproduce that default as a floor"
        ),
        "cipher_suite_order": order[:200],
        "cipher_suite_order_source": order_source,
        "cipher_suite_count": len(order),
        "weak_suites_in_order": _weak_suites(order)[:50],
        "findings": _findings(offered, deprecated_enabled, order, order_source, unconfigured),
        "meaning": (
            "this is the host's Schannel *policy*: what Windows has been configured to permit and "
            "prefer. It is not a record of what any application negotiated — an application that "
            "pins a version uses that version whatever the policy says"
        ),
    }


def _suite_order(raw: Mapping[str, Any]) -> list[str]:
    value = raw.get("Functions") if isinstance(raw, dict) else None
    if not isinstance(value, str):
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


_WEAK_TOKENS = ("RC4", "3DES", "DES", "NULL", "MD5", "EXPORT", "anon")


def _weak_suites(order: list[str]) -> list[str]:
    weak: list[str] = []
    for suite in order:
        upper = suite.upper()
        if any(token in upper for token in _WEAK_TOKENS):
            weak.append(suite)
    return weak


def _floor(offered: list[str]) -> str | None:
    """The lowest TLS version still offered, from the offered set alone."""
    order = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    for version in order:
        if version in offered:
            return version
    for version in ("DTLSv1.0", "DTLSv1.2"):
        if version in offered:
            return version
    return None


def _findings(
    offered: list[str],
    deprecated: list[str],
    order: list[str],
    order_source: str | None,
    unconfigured: list[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if deprecated:
        findings.append(
            {
                "id": "DEPRECATED_PROTOCOL_ENABLED",
                "severity": "HIGH" if {"SSLv2", "SSLv3"} & set(deprecated) else "WARNING",
                "detail": (
                    "Schannel explicitly offers "
                    + ", ".join(deprecated)
                    + " — any application that does not pin a floor can negotiate one of these"
                ),
            }
        )
    if unconfigured:
        findings.append(
            {
                "id": "BUILTIN_POLICY_APPLIES",
                "severity": "INFO",
                "detail": (
                    "no explicit policy for "
                    + ", ".join(unconfigured)
                    + " — Windows' built-in default applies and this build does not restate it. "
                    "A host that looks unconfigured here is unconfigured, not hardened"
                ),
            }
        )
    if not order:
        findings.append(
            {
                "id": "NO_CIPHER_SUITE_ORDER_POLICY",
                "severity": "INFO",
                "detail": (
                    "no cipher-suite order policy is set, so Windows' built-in order applies. The "
                    "platform does not reproduce that built-in list: it is version-specific and "
                    "reading it from documentation would be a guess"
                ),
            }
        )
    elif _weak_suites(order):
        findings.append(
            {
                "id": "WEAK_SUITE_IN_ORDER",
                "severity": "WARNING",
                "detail": "the configured order still contains "
                + ", ".join(_weak_suites(order)[:5]),
            }
        )
    if "TLSv1.3" not in offered:
        findings.append(
            {
                "id": "TLS13_NOT_EXPLICITLY_ENABLED",
                "severity": "INFO",
                "detail": (
                    "TLS 1.3 is not explicitly enabled in this host's Schannel policy. Whether the "
                    "OS offers it by default depends on the build, which this read does not resolve"
                ),
            }
        )
    return findings


def collect(item: Any, limit: int, charge: Callable[[int], None]) -> dict[str, Any]:
    """Host-collector entry point: policy read, charged against the run budget."""
    from inventory.host import Refused

    charge(1024)
    report = evaluate(windows_reader())
    if len(report["protocols"]) > limit:
        raise Refused("BUDGET_EXCEEDED", "LIMIT")
    return report


__all__ = [
    "CIPHER_ORDER_KEY",
    "CIPHER_PREFERENCE_KEY",
    "DEPRECATED_VERSIONS",
    "PROTOCOLS_KEY",
    "PROTOCOL_KEYS",
    "SCHEMA",
    "collect",
    "evaluate",
    "windows_reader",
]
