"""Zero-trust policy decision point — external policy that can only RESTRICT.

Round 31 build of the policy-as-code half of advanced/82. A service
mesh, SPIRE, and Calico are infrastructure deployments this codebase
cannot ship; what it CAN ship is the authorization composition rule a
central PDP provides:

    PDP DENY  blocks a request RBAC would allow (deny-wins),
    PDP ALLOW never grants a request RBAC would deny (no bypass).

Policies are request-attribute rules in a version-controlled JSON file
(``ZERO_TRUST_POLICY_FILE``) — or, when ``OPA_URL`` is set, the SAME
input is POSTed to a real Open Policy Agent endpoint
(``/v1/data/{path}``) and its decision honored under the same
composition rule. Fail-open/fail-closed is explicit: an unreachable OPA
denies when ``ZERO_TRUST_ENFORCED`` (fail-closed), because an
enforcement layer that disappears on error is decoration.

Policy document shape (``zelnx-zero-trust/v1``)::

    {
      "version": 1,
      "rules": [
        {"id": "no-prod-writes-from-viewers",
         "effect": "deny",
         "roles": ["viewer", "readonly"],
         "methods": ["POST", "PUT", "PATCH", "DELETE"],
         "paths": ["/api/v1/systems/*"]},
        {"id": "block-legacy-tls-admin",
         "effect": "deny",
         "principals": ["svc-legacy"],
         "paths": ["/api/v1/crypto/*"]}
      ]
    }

Rule matching: a rule applies when EVERY present matcher matches
(missing matcher = wildcard). Evaluation: any matching DENY rule →
DENY; else any matching ALLOW rule → ALLOW; else NOT_APPLICABLE (the
PDP is silent and RBAC alone decides).
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)

POLICY_FORMAT = "zelnx-zero-trust/v1"
EFFECTS = {"allow", "deny"}
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_CACHE_TTL = 5.0


class PolicyError(ValueError):
    """Invalid policy document."""


def _match_list(value: Optional[str], patterns: Optional[list[str]]) -> bool:
    if patterns is None:
        return True
    return any(fnmatch.fnmatchcase(value or "", str(p)) for p in patterns)


def rule_applies(rule: dict[str, Any], *, principal: str, roles: list[str],
                 method: str, path: str) -> bool:
    """Every present matcher must match (missing matcher = wildcard)."""
    if not _match_list(principal, rule.get("principals")):
        return False
    if "roles" in rule and rule["roles"] is not None:
        rule_roles = {str(r) for r in rule["roles"]}
        if not rule_roles & set(roles or []):
            return False
    if not _match_list((method or "").upper(), [m.upper() for m in rule["methods"]]
                       if rule.get("methods") is not None else None):
        return False
    if not _match_list(path, rule.get("paths")):
        return False
    return True


def validate_policy_document(doc: Any) -> dict[str, Any]:
    """Structural validation — reject malformed policies at load time."""
    if not isinstance(doc, dict):
        raise PolicyError("policy document must be an object")
    if doc.get("format") not in (None, POLICY_FORMAT):
        raise PolicyError(f"unsupported policy format {doc.get('format')!r}")
    rules = doc.get("rules")
    if not isinstance(rules, list):
        raise PolicyError("policy document needs a rules list")
    seen: set[str] = set()
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise PolicyError(f"rule #{index} must be an object")
        rule_id = str(rule.get("id") or "").strip()
        if not rule_id:
            raise PolicyError(f"rule #{index} needs an id")
        if rule_id in seen:
            raise PolicyError(f"duplicate rule id '{rule_id}'")
        seen.add(rule_id)
        effect = str(rule.get("effect") or "").lower()
        if effect not in EFFECTS:
            raise PolicyError(f"rule '{rule_id}' effect must be allow|deny")
        for key in ("principals", "roles", "methods", "paths"):
            if rule.get(key) is not None and not isinstance(rule[key], list):
                raise PolicyError(f"rule '{rule_id}' {key} must be a list")
        methods = rule.get("methods")
        if methods is not None:
            bad = [m for m in methods if str(m).upper() not in _METHODS]
            if bad:
                raise PolicyError(f"rule '{rule_id}' has unknown methods: {bad}")
    return doc


def load_policies(path: str) -> dict[str, Any]:
    """Load + validate the policy file, mtime-cached."""
    if not path:
        return {"format": POLICY_FORMAT, "rules": [], "source": None}
    try:
        mtime = os.path.getmtime(path)
    except OSError as exc:
        raise PolicyError(f"policy file unreadable: {exc}") from exc
    cached = _CACHE.get(path)
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"policy file unparseable: {exc}") from exc
    doc = validate_policy_document(doc)
    _CACHE[path] = (mtime, doc)
    return doc


def evaluate_embedded(doc: dict[str, Any], *, principal: str, roles: list[str],
                      method: str, path: str) -> dict[str, Any]:
    """Evaluate the embedded policy document (deny-wins)."""
    matched_deny: list[str] = []
    matched_allow: list[str] = []
    for rule in doc.get("rules") or []:
        if rule_applies(rule, principal=principal, roles=roles, method=method, path=path):
            if str(rule.get("effect")).lower() == "deny":
                matched_deny.append(str(rule["id"]))
            else:
                matched_allow.append(str(rule["id"]))
    if matched_deny:
        return {"decision": "DENY", "engine": "embedded",
                "matched_rules": matched_deny}
    if matched_allow:
        return {"decision": "ALLOW", "engine": "embedded",
                "matched_rules": matched_allow}
    return {"decision": "NOT_APPLICABLE", "engine": "embedded", "matched_rules": []}


def evaluate_opa(base_url: str, policy_path: str, *, principal: str, roles: list[str],
                 method: str, path: str, token: str = "", timeout: float = 3.0,
                 fetch: Any = None) -> dict[str, Any]:
    """Ask a REAL Open Policy Agent: POST /v1/data/{policy_path}.

    OPA is authoritative only for DENY (composition rule): an OPA
    ``allow=false`` with an explicit deny decision denies; ``allow=true``
    maps to ALLOW (still no RBAC bypass). Transport failure raises —
    the caller decides fail-open/closed from ZERO_TRUST_ENFORCED.
    """
    import urllib.error
    import urllib.request

    url = f"{base_url.rstrip('/')}/v1/data/{policy_path.strip('/')}"
    payload = json.dumps({
        "input": {"principal": principal, "roles": list(roles or []),
                  "method": (method or "").upper(), "path": path},
    }).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    def _default(method_: str, url_: str, headers_: dict, body_: bytes, timeout_: float):
        request = urllib.request.Request(url_, data=body_, method=method_, headers=headers_)
        try:
            with urllib.request.urlopen(request, timeout=timeout_) as response:
                return response.status, response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError) as exc:
            raise PolicyError(f"OPA unreachable at {url_}: {exc}") from exc

    do_fetch = fetch or _default
    try:
        status, body = do_fetch("POST", url, headers, payload, timeout)
    except PolicyError:
        raise
    except (OSError, ValueError) as exc:  # injected transports may raise raw
        raise PolicyError(f"OPA unreachable at {url}: {exc}") from exc
    if status != 200:
        raise PolicyError(f"OPA returned HTTP {status}")
    try:
        result = json.loads(body).get("result")
    except json.JSONDecodeError as exc:
        raise PolicyError("OPA returned non-JSON") from exc
    if isinstance(result, dict) and "decision" in result:
        decision = str(result["decision"]).upper()
    elif isinstance(result, bool):
        decision = "ALLOW" if result else "DENY"
    else:
        raise PolicyError(f"OPA result unusable: {result!r}")
    return {"decision": decision, "engine": "opa", "matched_rules": []}


def zero_trust_decision(*, principal: str, roles: list[str], method: str,
                        path: str, policy_file: str = "", opa_url: str = "",
                        opa_policy_path: str = "cryptoscan/allow",
                        enforced: bool = False) -> dict[str, Any]:
    """The composed decision for one request.

    OPA (when configured) is consulted first; the embedded file policy
    composes on top. ANY deny → DENY. Fail-closed when ``enforced`` and
    a configured engine errors; the error is surfaced, never swallowed.
    """
    decisions: list[dict[str, Any]] = []
    errors: list[str] = []
    if opa_url:
        try:
            from api.config.settings import get_settings

            settings = get_settings()
            decisions.append(evaluate_opa(
                opa_url, opa_policy_path, principal=principal, roles=roles,
                method=method, path=path,
                timeout=settings.OPA_TIMEOUT_SECONDS,
            ))
        except PolicyError as exc:
            if enforced:
                return {"decision": "DENY", "engine": "opa", "matched_rules": [],
                        "reason": f"fail-closed: {exc}"}
            errors.append(str(exc))
    if policy_file:
        try:
            decisions.append(evaluate_embedded(
                load_policies(policy_file), principal=principal, roles=roles,
                method=method, path=path))
        except PolicyError as exc:
            if enforced:
                return {"decision": "DENY", "engine": "embedded", "matched_rules": [],
                        "reason": f"fail-closed: {exc}"}
            errors.append(str(exc))
    if any(d["decision"] == "DENY" for d in decisions):
        deny = next(d for d in decisions if d["decision"] == "DENY")
        return deny
    if any(d["decision"] == "ALLOW" for d in decisions):
        allow = next(d for d in decisions if d["decision"] == "ALLOW")
        allow = dict(allow)
        allow["note"] = "PDP allow does not bypass RBAC"
        return allow
    return {"decision": "NOT_APPLICABLE", "engine": "pdp",
            "matched_rules": [], "errors": errors}
