"""ZELNX Cloud Discovery Engine — IAM & cryptographic access intelligence
(spec §12).

Builds access relationships around crypto assets:

    Identity ── CAN_USE ── Cryptographic Key
    Identity ── CAN_ADMINISTER ── Cryptographic Key

Analyzes who can administer keys, who can use keys, cross-account /
cross-subscription / cross-project access, service identities and workload
identities.  **Never collects credential secrets** — only policy-derived
permission metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.models import EvidenceSource

AccessEnumerator = Callable[[], list[dict[str, Any]]]


def _pick(row: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return default


@dataclass
class AccessBinding:
    """One identity -> key access relationship."""

    identity: str
    key_id: str
    permission: str = "CAN_USE"  # CAN_USE | CAN_ADMINISTER
    identity_type: str = ""  # user | role | service_identity | workload_identity | group
    source_account: str = ""
    target_account: str = ""
    cross_account: bool = False
    granted_via: str = ""  # iam_policy | key_policy | vault_policy | iam_binding
    evidence: EvidenceSource = field(default_factory=EvidenceSource)

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "key_id": self.key_id,
            "permission": self.permission,
            "identity_type": self.identity_type,
            "source_account": self.source_account,
            "target_account": self.target_account,
            "cross_account": self.cross_account,
            "granted_via": self.granted_via,
            "evidence": self.evidence.to_dict(),
        }


@dataclass
class AccessInventory:
    """All crypto access bindings."""

    bindings: list[AccessBinding] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [binding.to_dict() for binding in self.bindings]

    def administrators(self, key_id: str) -> list[AccessBinding]:
        return [b for b in self.bindings if b.key_id == key_id and b.permission == "CAN_ADMINISTER"]

    def users(self, key_id: str) -> list[AccessBinding]:
        return [b for b in self.bindings if b.key_id == key_id and b.permission == "CAN_USE"]

    def cross_account(self) -> list[AccessBinding]:
        return [b for b in self.bindings if b.cross_account]

    def count(self) -> int:
        return len(self.bindings)

    def summary(self) -> dict[str, Any]:
        return {
            "bindings": len(self.bindings),
            "administrators": sum(1 for b in self.bindings if b.permission == "CAN_ADMINISTER"),
            "users": sum(1 for b in self.bindings if b.permission == "CAN_USE"),
            "cross_account": len(self.cross_account()),
            "errors": self.errors,
        }


class IamAccessDiscovery:
    """Discover crypto access bindings from injected enumerators.

    Adapter shape: ``{"provider": "aws", "enumerate_access": fn}`` where
    each row is one binding.  ``permission`` accepts AWS actions
    (kms:Encrypt → CAN_USE, kms:PutKeyPolicy → CAN_ADMINISTER), Azure roles
    (Key Vault Crypto User → CAN_USE, Crypto Officer → CAN_ADMINISTER) and
    GCP roles (roles/cloudkms.cryptoKeyEncrypterDecrypter → CAN_USE,
    roles/cloudkms.admin → CAN_ADMINISTER).
    """

    PERMISSION_HINTS = {
        "CAN_USE": ("encrypt", "decrypt", "sign", "verify", "use", "user", "encrypterdecrypter",
                    "cryptooperuser", "signerverifier", "envelope", "generatekey"),
        "CAN_ADMINISTER": ("admin", "putkeypolicy", "officer", "manage", "update", "delete",
                           "disable", "enable", "schedule", "iam", "owner"),
    }

    def __init__(self, providers: list[dict[str, Any]]) -> None:
        self._providers = list(providers)

    def discover(self) -> AccessInventory:
        inventory = AccessInventory()
        for entry in self._providers:
            provider = str(entry.get("provider") or "").lower()
            enumerator = entry.get("enumerate_access")
            if enumerator is None:
                continue
            try:
                rows = enumerator() or []
            except Exception as exc:  # noqa: BLE001
                inventory.errors.append(
                    {"provider": provider, "kind": "enumerate", "detail": str(exc)[:300]}
                )
                continue
            for row in rows:
                if isinstance(row, dict):
                    inventory.bindings.append(self._binding(row, provider=provider))
        return inventory

    @classmethod
    def classify_permission(cls, raw: str) -> str:
        """Map provider permission text to CAN_USE / CAN_ADMINISTER."""
        token = str(raw or "").lower()
        if not token:
            return "CAN_USE"
        for hint in cls.PERMISSION_HINTS["CAN_ADMINISTER"]:
            if hint in token:
                return "CAN_ADMINISTER"
        return "CAN_USE"

    def _binding(self, row: dict[str, Any], *, provider: str) -> AccessBinding:
        source = str(_pick(row, "source_account", "account", "subscription", "project",
                           default="") or "")
        target = str(_pick(row, "target_account", "key_account", "key_subscription",
                           "key_project", default="") or "")
        if not target:
            target = source
        raw_permission = str(_pick(row, "permission", "role", "action", "permissions",
                                   default="CAN_USE") or "CAN_USE")
        permission = (str(_pick(row, "permission_class", default="") or "")
                      or self.classify_permission(raw_permission))
        return AccessBinding(
            identity=str(_pick(row, "identity", "principal", "subject", "identity_name",
                               default="") or ""),
            key_id=str(_pick(row, "key_id", "resource", "key_arn", "vault", "key_name",
                             default="") or ""),
            permission=permission,
            identity_type=str(_pick(row, "identity_type", "type", default="") or ""),
            source_account=source,
            target_account=target,
            cross_account=bool(source and target and source != target)
            or bool(_pick(row, "cross_account", default=False)),
            granted_via=str(_pick(row, "granted_via", "policy", "via", default="") or ""),
            evidence=EvidenceSource(
                source_provider=provider,
                account=target,
                api_source=str(_pick(row, "api_source", default="iam-access") or ""),
            ),
        )
