"""Every write the API serves is either role-gated or a decision someone wrote down.

Guide 100 §5 (c) ends with a question it does not answer: 1212 operations sit
behind the session gate with no role requirement. For most of them that is
deliberate — an authenticated operator works the estate — but "deliberate" was
never recorded anywhere, so a **new** state-changing route could join that set and
nobody would notice. This module turns the set into an artifact:

* it reads the route tree and asks, per operation, whether the dependency closure
  contains a role requirement (``require_roles`` and friends, detected the same
  way ``dependant.call.allowed_roles`` is tagged for the live sweep);
* every write operation that is *not* public and *not* role-gated is written into
  a checked-in inventory, with the reason it holds no role — derived from a policy
  table over its path prefix, and marked ``REVIEW REQUIRED`` when no rule covers it;
* the test in ``scripts/tests/test_auth_write_inventory.py`` requires the live set
  and the inventory to be **equal**. Adding an unguarded write therefore fails the
  build until someone runs ``--write`` and states the reason. Nothing is grandfathered
  in by a wildcard.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs" / "bank-environment" / "102-authenticated-only-writes.json"

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

#: Why a whole prefix is authenticated-only rather than role-gated. The reason is
#: recorded per operation so a reviewer reads a policy, not a list of paths.
#: Longest prefix wins; anything unmatched is REVIEW REQUIRED, which is the point.
POLICY: dict[str, str] = {
    "/api/v1/auth": "self-service or session lifecycle: the caller acts on their own account",
    "/api/v1/estate": "operator surface: every signed-in operator inspects and curates the estate",
    "/api/v1/collection": "operator surface: collection targets, jobs and handoffs",
    # Alertmanager posts here; it has no session and no role. The credential is
    # the shared ALERTMANAGER_WEBHOOK_TOKEN, checked in the handler, because a
    # rule that fires must not be refused with 401 (guide 117).
    "/api/v1/ops": "machine-signed: Alertmanager posts notifications with its own token",
    # The authorize route cannot carry one static permission: each collector
    # plane has its own, and the route is the one place they are all asked. The
    # session gate supplies the principal and roles, and
    # api.security.collector_authority.evaluate() checks the plane's permission
    # from PERMISSION_MATRIX before the collection is answered.
    "/api/v1/collectors": "per-collector authority: the plane's own permission is "
                          "checked against PERMISSION_MATRIX inside the decision",
    "/api/v1/assurance": "operator surface: assurance scope, approvals and evidence intake",
    "/api/v1/network": "operator surface: network inventory and discovery runs",
    "/api/v1/cbom": "operator surface: CBOM assembly over estate data",
    # The VBOM question surface is four POSTs that write nothing: `answer`, `assess`, `summary`
    # and the CycloneDX projection all read stored evidence. POST is chosen because the question
    # is a request body, not because anything changes — and a reader who sees "POST, session only"
    # in the inventory would assume otherwise, so the reason says it here.
    "/api/v1/cbom/vbom": "read-only question surface: POST carries the question, the handler "
                          "writes nothing (guide 184)",
    # A snapshot is the platform's own reading of a firewall or an HSM. A browser session cannot
    # hold that claim, so the route refuses a user token outright and requires a machine identity.
    # There is no *role* to require: the credential kind is the gate.
    "/api/v1/security-controls": "machine-only: a user token is refused; the collector credential "
                                 "is the gate (guide 182)",
    "/api/v1/devsecops": "operator surface: pipeline and SBOM ingestion",
    "/api/v1/graph": "operator surface: graph curation of the estate",
    "/api/v1/vendors": "operator surface: vendor and profile registry",
    "/api/v1/technology-bom": "operator surface: BOM export schedules",
    "/api/v1/banking": "operator surface: group entity registry",
    "/api/v1/systems": "operator surface: system registry",
    "/api/v1/telecom": "operator surface: telecom estate inventory",
    "/api/v1/saas": "tenant-scoped: authority is the tenant role, enforced in the handler",
    "/api/v1/webhooks": "machine-signed: the caller proves itself with an HMAC, not a session role",
    "/api/v1/ingestion": "machine-signed: collector ingestion with its own credential",
    "/api/v1/scans": "operator surface: scans are started by any signed-in operator",
    "/api/v1/jobs": "operator surface: background job lifecycle",
    "/api/v1/certificates": "operator surface: certificate estate writes",
    "/api/v1/security": "operator surface: security posture and policy intake",
    "/api/v1/cloud": "operator surface: cloud account inventory and scans",
    "/api/v1/cloud-scans": "operator surface: cloud scan runs",
    "/api/v1/exceptions": "operator surface: exception workflow (tenant-scoped by the request)",
    "/api/v1/execution-controls": "operator surface: execution control records",
    "/api/v1/hardware": "operator surface: live hardware telemetry ingestion",
    "/api/v1/platform": "operator surface: platform-mode switch, superadmin in the handler",
    "/api/v1/runtime": "operator surface: runtime depth inspection",
    "/api/v1/automation": "operator surface: automation rules and runners",
    "/api/v1/host-evidence": "operator surface: explicit approval -> imported snapshot",
    "/api/v1/resource-monitoring": "operator surface: monitored resource targets",
    "/api/v1/monitor": "operator surface: monitoring targets and alerts",
    "/api/v1/traffic-control": "operator surface: traffic control policies",
    "/api/v1/business": "operator surface: business process and owner registry",
    "/api/v1/container-scans": "operator surface: container scan runs",
    "/api/v1/container": "operator surface: container image inventory",
    "/api/v1/ct-scans": "operator surface: certificate transparency scan runs",
    "/api/v1/hsm-scans": "operator surface: HSM scan runs",
    "/api/v1/control": "operator surface: control plane actions",
    "/api/v1/crypto": "operator surface: live crypto event ingestion",
    "/api/v1/ot": "operator surface: OT/ICS capture analysis and ingestion",
    "/api/v1/sectors": "operator surface: sector reference data",
    "/api/v1/digital-twin": "operator surface: twin scenario runs",
    "/api/v1/enterprise": "operator surface: enterprise inventory",
    "/api/v1/remediation": "operator surface: remediation tasks",
    "/api/v1/anomaly": "operator surface: anomaly review",
    "/api/v1/ci": "machine-signed: CI hook with its own credential",
    "/api/v1/connectors": "operator surface: connector configuration",
    "/api/v1/datalake": "operator surface: datalake export",
    "/api/v1/evidence-pack": "operator surface: evidence pack assembly",
    "/api/v1/governance": "operator surface: governance records",
    "/api/v1/inventory": "operator surface: inventory import",
    "/api/v1/marketplace": "operator surface: marketplace catalogue actions",
    "/api/v1/quantum": "operator surface: quantum readiness",
    "/api/v1/report": "operator surface: report generation",
    "/api/v1/repos": "operator surface: repository configuration",
    "/api/v1/stream": "operator surface: live stream subscriptions",
    "/api/v1/migrations": "operator surface: schema migration plan/apply, gated by the platform-mode switch in the handler",
    "/api/v1/api-keys": "self-service: the caller manages their own keys",
    # The CryptoLog family is its own decision, not an accident of the
    # /api/v1/crypto string prefix: event ingestion validates every record
    # through the event contract, and the alert lifecycle opens
    # investigations rather than declaring verdicts. Authenticated-only so
    # every record and every lifecycle action is attributable to the session
    # principal.
    "/api/v1/cryptolog": "operator surface: cryptographic event ingestion and "
                         "deterministic alert lifecycle; records carry their "
                         "evidence and alerts say what is proven",
    # The ZELNX Performance Intelligence family (docs/performance/
    # 01_PRODUCT_SPEC.md) accepts measurements from authorized monitoring
    # sources: read-only collection by default, tenant isolation on every
    # metric, missing telemetry never zero, idempotent per metric_id.
    # Authenticated-only so every measurement is attributable to the
    # session principal of the collector.
    "/api/v1/performance": "operator surface: performance metric ingestion "
                           "from authorized monitoring sources; read-only "
                           "collection, tenant-isolated, idempotent",
    # The roadmap family computes over posted rows and recorded state
    # (reconciliation, projection, migration planning, gates, vendor and
    # qualification registers). Answers are computed in the caller's tenant
    # context and carry their evidence links; the session principal is the
    # audit anchor.
    "/api/v1/intelligence": "operator surface: roadmap computation and "
                            "governance actions over posted rows and recorded "
                            "state; answers carry their evidence links",
}


def _demands_authority(dependant) -> bool:
    """True when the dependency tree contains any authority guard at all.

    Not just ``require_roles``: ``require_permission`` (an RBAC action) and
    ``require_tenant_roles`` (owner/admin *within* a tenant) are role requirements
    too, and counting only the first made `/saas/members/{username}` look like an
    unguarded delete when it is tenant-role gated. The factories are recognised by
    the qualname of the callable the app actually executes.
    """
    from authorization_register import GUARD_KINDS

    stack = [dependant]
    while stack:
        node = stack.pop()
        if node is None:
            continue
        call = getattr(node, "call", None)
        if call is not None:
            factory = (getattr(call, "__qualname__", "") or "").split(".<locals>", 1)[0]
            if factory in GUARD_KINDS:
                return True
        stack.extend(getattr(node, "dependencies", []) or [])
    return False


def role_gated_operations() -> dict[tuple[str, str], set[frozenset[str]]]:
    """{(METHOD, path): the role sets the route enforces} read from the route tree."""
    import api_contract

    gated: dict[tuple[str, str], set[frozenset[str]]] = {}
    for route in api_contract.application().routes:
        original = getattr(route, "original_router", None)
        if original is None:
            continue  # the app shell
        context = getattr(route, "include_context", None)
        prefix = (getattr(context, "prefix", "") or "") if context is not None else ""
        router_gated = any(
            _demands_authority(dependency) for dependency in getattr(original, "dependencies", []) or []
        )
        for child in original.routes:
            methods = getattr(child, "methods", None) or set()
            if not router_gated and not _demands_authority(getattr(child, "dependant", None)):
                continue
            for method in methods:
                if method in READ_METHODS or method in ("HEAD", "OPTIONS"):
                    continue
                gated.setdefault((method, prefix + getattr(child, "path", "")), set()).add(frozenset())
    return gated


def is_public(path: str) -> bool:
    """True when ``AuthMiddleware`` never asks for a credential on this path."""
    from api.middleware.auth_middleware import _is_unprotected

    return (
        path == "/"
        or path.startswith(("/login", "/static"))
        or _is_unprotected(path)
        or not path.startswith("/api/")
    )


def reason_for(path: str) -> str:
    """The recorded reason this prefix is authenticated-only, or REVIEW REQUIRED."""
    best: str | None = None
    for prefix, reason in POLICY.items():
        if path.startswith(prefix) and (best is None or len(prefix) > len(best)):
            best = prefix
    return POLICY[best] if best else "REVIEW REQUIRED"


def inventory() -> list[dict]:
    """Every write operation that is neither public nor role-gated."""
    import api_contract

    gated = role_gated_operations()
    rows: list[dict] = []
    for path, methods in api_contract.served_operations().items():
        if is_public(path):
            continue
        for method in methods:
            method = method.upper()
            if method not in WRITE_METHODS or (method, path) in gated:
                continue
            rows.append({"method": method, "path": path, "reason": reason_for(path)})
    return sorted(rows, key=lambda row: (row["path"], row["method"]))


def _key(row: dict) -> str:
    return f"{row['method']} {row['path']}"


def load() -> dict[str, str]:
    """{“METHOD path”: reason} from the checked-in inventory."""
    if not INVENTORY.is_file():
        return {}
    document = json.loads(INVENTORY.read_text())
    return {_key(row): row["reason"] for row in document["operations"]}


def write(rows: list[dict] | None = None) -> Path:
    rows = inventory() if rows is None else rows
    INVENTORY.parent.mkdir(parents=True, exist_ok=True)
    INVENTORY.write_text(
        json.dumps(
            {
                "schema": "cryptoscan.authenticated-only-writes/1",
                "why": (
                    "Every write operation with no *route-level* role requirement. Since guide "
                    "121's re-measure these are not open to everyone: "
                    "api/security/write_authority.py refuses any human session whose roles are "
                    "all read-only on every mutating method, so what this list records is which "
                    "writable role may call the route plus the reason it needs no finer "
                    "requirement. Regenerate with `python scripts/auth_write_inventory.py "
                    "--write` after a deliberate decision; the test fails when this list and "
                    "the application disagree."
                ),
                "platform_rule": (
                    "read-only roles (readonly, auditor, supervisor) are refused on POST, PUT, "
                    "PATCH and DELETE before the route runs, except on session lifecycle paths "
                    "and on paths that record a signed attestation"
                ),
                "operations": rows,
            },
            indent=2,
        )
        + "\n"
    )
    return INVENTORY


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="rewrite the inventory")
    parser.add_argument("--summary", action="store_true", help="print counts per reason")
    args = parser.parse_args(argv)

    rows = inventory()
    if args.write:
        print(f"wrote {write(rows)} ({len(rows)} operations)")
        return 0
    from collections import Counter

    counts = Counter(row["reason"] for row in rows)
    print(json.dumps({"operations": len(rows), "by_reason": counts.most_common()}, indent=2))
    return 0 if args.summary or rows else 0


if __name__ == "__main__":  # pragma: no cover - CLI
    raise SystemExit(main())
