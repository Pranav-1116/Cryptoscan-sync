"""IPsec: two phases, four transforms, and the one mistake that removes forward secrecy.

Review item 14 asks for VPN/IPsec depth. IPsec differs from TLS and SSH in a way that
changes what an inventory must record: a tunnel has **two security associations**, and
they are negotiated separately.

    IKE SA      (phase 1)  encryption · PRF/hash · integrity · DH group
    CHILD SA    (phase 2)  ESP encryption · ESP integrity · PFS group

The distinction that matters in practice is the last column: a CHILD SA with **no PFS
group** derives its keys from the IKE SA's key material, so one compromised peer key
decrypts every rekeyed tunnel back to the start. A configuration that reads
`AES-256 / SHA-256 / DH14` looks strong and can still have no forward secrecy for data —
which is why PFS is its own field and not inferred from the DH group of phase 1.

Three more facts are modelled rather than glossed:

* **IKEv1 aggressive mode with a pre-shared key** sends a hash of the PSK, which is
  offline-crackable. That is a property of the mode and the authentication, not of any
  cipher, so it is reported as its own problem.
* **`ENCR_NULL` is not encryption.** A tunnel with integrity and no encryption is a
  legitimate design for a private link and a catastrophic one over the internet, so the
  model reports it and refuses to call it safe either way.
* **the negotiated proposal is not the peer's policy.** A device offering only weak
  transforms and a device offering many where one weak was chosen look identical from
  one SA; the accepted offer is recorded when the collector has it and never assumed.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.cbom-ipsec/1"

PHASES: tuple[str, ...] = ("IKE", "CHILD")

#: IKE versions, and what each means for the peers
VERSIONS: tuple[str, ...] = ("IKEV1", "IKEV2")

#: authentication methods
AUTH_METHODS: tuple[str, ...] = ("PSK", "CERTIFICATE", "EAP", "UNKNOWN")

#: transforms whose presence is a finding, with the reason
WEAK_TRANSFORMS: dict[str, str] = {
    "des": "56-bit key",
    "3des": "64-bit block cipher with a sweet32 birthday bound",
    "null": "no confidentiality at all",
    "md5": "MD5 integrity",
    "sha1": "SHA-1 integrity",
    "sha-1": "SHA-1 integrity",
    "dh1": "768-bit MODP group",
    "dh2": "1024-bit MODP group",
    "dh5": "1536-bit MODP group",
    "modp768": "768-bit MODP group",
    "modp1024": "1024-bit MODP group",
    "modp1536": "1536-bit MODP group",
}

#: groups that are acceptable today, with their size
DH_GROUPS: dict[str, dict[str, Any]] = {
    "DH14": {"bits": 2048, "kind": "MODP", "acceptable": True},
    "MODP2048": {"bits": 2048, "kind": "MODP", "acceptable": True},
    "DH15": {"bits": 3072, "kind": "MODP", "acceptable": True},
    "DH16": {"bits": 4096, "kind": "MODP", "acceptable": True},
    "DH19": {"bits": 256, "kind": "ECP", "acceptable": True},
    "DH20": {"bits": 384, "kind": "ECP", "acceptable": True},
    "DH21": {"bits": 521, "kind": "ECP", "acceptable": True},
    "DH31": {"bits": 255, "kind": "CURVE25519", "acceptable": True},
    "DH1": {"bits": 768, "kind": "MODP", "acceptable": False},
    "DH2": {"bits": 1024, "kind": "MODP", "acceptable": False},
    "DH5": {"bits": 1536, "kind": "MODP", "acceptable": False},
}

#: groups whose security rests on a problem a quantum computer breaks
QUANTUM_GROUPS: tuple[str, ...] = ("MODP", "ECP", "CURVE25519")

#: PRFs/encryption that are fine, so an unknown name is not automatically weak
ACCEPTABLE = ("aes128", "aes192", "aes256", "aes128gcm16", "aes256gcm16", "gcm16",
              "chacha20poly1305", "sha256", "sha384", "sha512", "prfsha256",
              "prfsha384", "prfsha512")

NOT_PROVEN = [
    "that the negotiated proposal is the peer's policy: one SA is one choice, and a "
    "device that offers many transforms where one weak was chosen looks the same as a "
    "device that offers only the weak one",
    "that a tunnel is carrying traffic: an established SA with no packets is a "
    "configuration, and liveness needs counters this model does not read",
    "that a pre-shared key is strong: the model can see that PSK authentication is in "
    "use and cannot see the secret, so it cannot say whether aggressive mode is "
    "crackable here — only that it would be",
    "that the peers' identities are verified: certificate authentication without a "
    "validated chain is as weak as the chain, and the chain is guide 159's subject",
]


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _tokens(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [token.strip().lower() for token in
                value.replace(",", " ").split() if token.strip()]
    if isinstance(value, Iterable) and not isinstance(value, Mapping):
        return [str(token).strip().lower() for token in value if str(token).strip()]
    return []


def transform(name: str, *, phase: str = "IKE") -> dict[str, Any]:
    """One transform name judged in its phase, and its quantum exposure."""
    token = (name or "").strip().lower()
    if not token:
        raise ValueError("a transform needs a name")
    if phase not in PHASES:
        raise ValueError(f"{phase} is not one of {', '.join(PHASES)}")
    reason = WEAK_TRANSFORMS.get(token)
    group = DH_GROUPS.get(token.upper())
    is_null = token in {"null", "encr_null", "encr-null"}
    quantum = bool(group) or token.startswith(("rsa", "ecdsa"))
    if reason:
        rating = "BROKEN" if token in {"des", "null", "md5", "dh1", "modp768",
                                       "encr_null"} else "WEAK"
    elif group and not group["acceptable"]:
        rating = "WEAK"
    elif token in ACCEPTABLE or group:
        rating = "ACCEPTABLE"
    else:
        rating = "UNKNOWN"
    return {
        "transform": token,
        "phase": phase,
        "rating": rating,
        "reason": reason,
        "group_bits": group["bits"] if group else None,
        "group_kind": group["kind"] if group else None,
        "null_encryption": is_null,
        "quantum_vulnerable": quantum,
    }


def _ike_version(value: Any) -> str:
    text = str(value or "").strip().upper().replace("-", "").replace("_", "")
    if text in {"1", "IKEV1", "V1"}:
        return "IKEV1"
    if text in {"2", "IKEV2", "V2"}:
        return "IKEV2"
    return "UNKNOWN"


def tunnel(row: Mapping[str, Any]) -> dict[str, Any]:
    """One IPsec peer/tunnel record → both SAs, their transforms and their problems."""
    if not isinstance(row, Mapping):
        raise ValueError("an IPsec tunnel must be an object")
    peer = _text(row.get("peer") or row.get("remote") or row.get("endpoint"))
    if not peer:
        raise ValueError("an IPsec tunnel needs a peer")
    evidence = _text(row.get("evidence_id"))
    if not evidence:
        raise ValueError(f"{peer}: an SA with no evidence id is a claim, not a negotiation")
    version = _ike_version(row.get("ike_version"))
    if version == "UNKNOWN":
        raise ValueError(
            f"{peer}: the IKE version is unknown, and IKEv1 and IKEv2 have different "
            "transform vocabularies")
    ike = row.get("ike") if isinstance(row.get("ike"), Mapping) else {}
    child = row.get("child") if isinstance(row.get("child"), Mapping) else {}
    ike_proposal = [transform(name, phase="IKE") for name in
                    _tokens(ike.get("proposal") or ike.get("transforms"))]
    child_proposal = [transform(name, phase="CHILD") for name in
                      _tokens(child.get("proposal") or child.get("transforms"))]
    pfs_group = _text(child.get("pfs") or child.get("pfs_group"))
    auth = str(row.get("authentication") or "UNKNOWN").strip().upper()
    if auth not in AUTH_METHODS:
        auth = "UNKNOWN"
    mode = str(row.get("mode") or ("MAIN" if version == "IKEV2" else "UNKNOWN")).upper()
    if version == "IKEV2" and mode == "AGGRESSIVE":
        mode = "IKEV2_SA_INIT"  # IKEv2 has no aggressive mode
    problems: list[dict[str, Any]] = []
    for label, proposals in (("IKE", ike_proposal), ("CHILD", child_proposal)):
        for row_transform in proposals:
            if row_transform["rating"] in {"BROKEN", "WEAK"}:
                problems.append({"phase": label,
                                 "transform": row_transform["transform"],
                                 "rating": row_transform["rating"],
                                 "detail": row_transform["reason"]})
            if row_transform["null_encryption"]:
                problems.append({"phase": label, "transform": row_transform["transform"],
                                 "rating": "NO_CONFIDENTIALITY",
                                 "detail": ("integrity without encryption: legitimate "
                                            "on a private circuit, not over the internet")})
    if not child_proposal:
        problems.append({"phase": "CHILD", "transform": None, "rating": "NO_CHILD_SA",
                         "detail": ("only the IKE SA was observed, so nothing is known "
                                    "about the data path's cryptography")})
    if pfs_group:
        pfs = transform(pfs_group, phase="CHILD")
        if pfs["rating"] in {"BROKEN", "WEAK"}:
            problems.append({"phase": "CHILD", "transform": pfs["transform"],
                             "rating": pfs["rating"],
                             "detail": f"PFS group: {pfs['reason']}"})
    pfs_present = bool(pfs_group and DH_GROUPS.get(pfs_group.upper(), {}).get("acceptable"))
    if child_proposal and not pfs_group:
        problems.append({
            "phase": "CHILD", "transform": None, "rating": "NO_FORWARD_SECRECY",
            "detail": ("the CHILD SA has no PFS group, so its keys derive from the IKE "
                       "SA and one compromised peer key exposes every rekeyed tunnel")})
    if version == "IKEV1" and mode == "AGGRESSIVE" and auth == "PSK":
        problems.append({
            "phase": "IKE", "transform": None, "rating": "OFFLINE_PSK_ATTACK",
            "detail": ("IKEv1 aggressive mode sends a hash of the pre-shared key, which "
                       "can be attacked offline without touching the peer")})
    states = sorted({str(value["rating"]) for value in problems})
    return {
        "schema": SCHEMA,
        "peer": peer,
        "local": _text(row.get("local")),
        "ike_version": version,
        "mode": mode,
        "authentication": auth,
        "ike_proposal": ike_proposal,
        "child_proposal": child_proposal,
        "pfs": (transform(pfs_group, phase="CHILD") if pfs_group else None),
        "forward_secrecy_for_data": pfs_present,
        "lifetime_seconds": child.get("lifetime") or ike.get("lifetime"),
        "state": _text(row.get("state")) or "UNKNOWN",
        "problems": problems,
        "worst": _worst(states),
        "evidence_ids": [evidence],
        "source": _text(row.get("source")),
        "observed_at": _text(row.get("observed_at")),
        "statement": _statement(peer, version, ike_proposal, child_proposal, pfs_present,
                                problems),
    }


def _worst(ratings: Iterable[str]) -> str | None:
    order = ["OFFLINE_PSK_ATTACK", "BROKEN", "NO_CONFIDENTIALITY", "NO_FORWARD_SECRECY",
             "NO_CHILD_SA", "WEAK", "UNKNOWN"]
    present = set(ratings)
    return next((name for name in order if name in present), None)


def _statement(peer: str, version: str, ike: list[Mapping[str, Any]],
               child: list[Mapping[str, Any]], pfs: bool,
               problems: list[Mapping[str, Any]]) -> str:
    ike_names = ", ".join(row["transform"] for row in ike) or "no proposal recorded"
    child_names = ", ".join(row["transform"] for row in child) or "no CHILD SA recorded"
    return (f"{peer} ({version.lower()}): ike {ike_names}; child {child_names}; "
            + ("PFS on the data path" if pfs else "no PFS group on the data path")
            + (f"; {len(problems)} problem(s): "
               + ", ".join(sorted({str(problem['rating']) for problem in problems}))
               if problems else "; no weak transform in this SA"))


def estate(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Many tunnels → the VPN surface, with refusals and per-peer findings."""
    tunnels: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for row in rows or ():
        try:
            tunnels.append(tunnel(row))
        except ValueError as exc:
            refused.append({"tunnel": row if not isinstance(row, Mapping)
                            else {key: row.get(key) for key in ("peer", "endpoint")},
                            "reason": str(exc)})
    without_pfs = [body["peer"] for body in tunnels if not body["forward_secrecy_for_data"]]
    ikev1 = [body["peer"] for body in tunnels if body["ike_version"] == "IKEV1"]
    weak = sorted({problem["transform"] for body in tunnels
                   for problem in body["problems"] if problem["transform"]})
    return {
        "schema": SCHEMA,
        "tunnels": tunnels,
        "peers": sorted({body["peer"] for body in tunnels}),
        "refused": refused,
        "without_pfs": sorted(without_pfs),
        "ikev1": sorted(ikev1),
        "weak_transforms_in_use": weak,
        "statement": (
            f"{len(tunnels)} IPsec SA pair(s) across {len({b['peer'] for b in tunnels})} "
            "peer(s)"
            + (f"; {len(without_pfs)} without a PFS group on the data path"
               if without_pfs else "; every data path has a PFS group")
            + (f"; {len(ikev1)} still using IKEv1" if ikev1 else "")
            + (f"; weak transforms in use: {', '.join(weak)}" if weak else "")
            + (f"; {len(refused)} refused" if refused else "")),
        "not_proven": list(NOT_PROVEN),
    }


def to_algorithms(body: Mapping[str, Any]) -> dict[str, Any]:
    """IPsec transforms as CBOM facts, split by the phase that negotiated them."""
    if not isinstance(body, Mapping) or body.get("schema") != SCHEMA:
        raise ValueError(f"not a {SCHEMA} document")
    facts: list[dict[str, Any]] = []
    for tunnel_row in body.get("tunnels") or []:
        for phase, key in (("IKE", "ike_proposal"), ("CHILD", "child_proposal")):
            for row_transform in tunnel_row.get(key) or []:
                facts.append({
                    "algorithm": row_transform["transform"],
                    "role": _role(row_transform["transform"]),
                    "phase": phase,
                    "parameters": ({"group_bits": row_transform["group_bits"]}
                                   if row_transform["group_bits"] else {}),
                    "rating": row_transform["rating"],
                    "quantum_vulnerable": row_transform["quantum_vulnerable"],
                    "peer": tunnel_row["peer"],
                    "evidence_ids": list(tunnel_row["evidence_ids"]),
                    "class": "NETWORK_OBSERVED",
                    "protocol": "IPSEC",
                })
        if tunnel_row.get("pfs"):
            pfs = tunnel_row["pfs"]
            facts.append({
                "algorithm": pfs["transform"], "role": "KEY_EXCHANGE", "phase": "CHILD",
                "parameters": ({"group_bits": pfs["group_bits"]}
                               if pfs["group_bits"] else {}),
                "rating": pfs["rating"], "quantum_vulnerable": pfs["quantum_vulnerable"],
                "peer": tunnel_row["peer"],
                "evidence_ids": list(tunnel_row["evidence_ids"]),
                "class": "NETWORK_OBSERVED", "protocol": "IPSEC",
            })
    seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    for fact in facts:
        seen.setdefault((fact["peer"], fact["role"], fact["algorithm"]), fact)
    return {
        "schema": SCHEMA,
        "facts": sorted(seen.values(), key=lambda fact: (fact["peer"], fact["role"],
                                                         fact["algorithm"])),
        "peers": len({fact["peer"] for fact in facts}),
        "quantum_vulnerable": sorted({fact["algorithm"] for fact in facts
                                      if fact["quantum_vulnerable"]}),
        "statement": (f"{len(seen)} distinct IPsec transform fact(s) across "
                      f"{len({fact['peer'] for fact in facts})} peer(s)"),
    }


def _role(name: str) -> str:
    token = name.lower()
    if token in {key.lower() for key in DH_GROUPS}:
        return "KEY_EXCHANGE"
    if token in {"md5", "sha1", "sha-1", "sha256", "sha384", "sha512"} \
            or token.startswith("prf"):
        return "PRF_AND_INTEGRITY"
    return "BULK"


def summary(body: Mapping[str, Any]) -> dict[str, Any]:
    """One screen: which tunnels have no forward secrecy, and what is weak in use."""
    tunnels = body.get("tunnels") or []
    return {
        "schema": SCHEMA,
        "tunnels": len(tunnels),
        "peers": len(body.get("peers") or []),
        "without_pfs": body.get("without_pfs") or [],
        "ikev1": body.get("ikev1") or [],
        "weak_transforms_in_use": body.get("weak_transforms_in_use") or [],
        "worst": ({body["peer"]: body["worst"] for body in tunnels if body["worst"]}
                  if tunnels else {}),
        "refused": len(body.get("refused") or []),
        "statement": body.get("statement", ""),
        "not_proven": list(NOT_PROVEN),
    }
