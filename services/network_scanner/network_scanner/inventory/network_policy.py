"""Policy, risk and PQC readiness over network-observed crypto (spec 67 §28–§31).

Three rules govern this module:

1. **Only observed parameters are judged.** A record whose evidence type is not
   an observation (`CONFIG_IMPORTED`, `UNKNOWN`, a refused handshake) produces
   a coverage gap with status ``UNKNOWN`` — never a pass, never "safe".
2. **The layer stays named.** Every finding carries
   ``layer="NETWORK_TRANSPORT"`` so a TLS `AES-256-GCM` is never read as the
   application's crypto (§27).
3. **A version floor is not a cipher verdict.** Version, key exchange, cipher,
   MAC, certificate and chain are evaluated by separate rules, because a
   TLS 1.3 endpoint with an RSA-1024 signature and an expired chain is not
   "compliant" just because the protocol version is current.

Findings are plain dictionaries so the router, the CBOM projection and the
dashboard all read the same object.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from network_scanner.inventory.network_evidence import OBSERVED_EVIDENCE_TYPES

MODEL = "cryptoscan.network-risk/1"
POLICY_ID = "cryptoscan.bank-network-crypto-baseline"
POLICY_VERSION = "1.0"
LAYER = "NETWORK_TRANSPORT"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_TLS_VERSION_RANK = {
    "sslv2": 0,
    "sslv3": 1,
    "tlsv1": 2,
    "tlsv1.0": 2,
    "tlsv1.1": 3,
    "tlsv1.2": 4,
    "tlsv1.3": 5,
}

FORWARD_SECRECY_TOKENS = ("ecdhe", "dhe", "x25519", "secp", "curve25519")

#: only finite-field groups are judged against a bit-length floor; an elliptic
#: curve's 256-bit coordinate is not a weak 256-bit DH group
FINITE_FIELD_GROUP_TOKENS = ("ffdhe", "diffie-hellman-group", "dh-", "modp")

#: Bank baseline. Anything an operator wants differently is an override in the
#: policy document, never a code change.
DEFAULT_POLICY: dict[str, Any] = {
    "policy_id": POLICY_ID,
    "version": POLICY_VERSION,
    "min_tls_version": "TLSv1.2",
    "forbidden_tls_versions": ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"],
    "require_forward_secrecy": True,
    "min_dh_bits": 2048,
    "min_rsa_bits": 2048,
    "min_ec_bits": 224,
    "forbidden_cipher_tokens": ["RC4", "RC2", "3DES", "DES-CBC", "NULL", "EXPORT", "IDEA", "SEED"],
    "forbidden_mac_tokens": ["MD5", "SHA1", "SHA-1"],
    "forbidden_signature_tokens": ["MD5", "SHA1", "SHA-1"],
    "certificate_expiry_warning_days": 30,
    "require_complete_chain": True,
    "require_mtls_endpoints": [],
    "ssh": {
        "forbidden_kex": [
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "gss-group1-sha1-",
        ],
        "forbidden_host_key": ["ssh-dss", "ssh-rsa"],
        "forbidden_cipher": [
            "3des-cbc",
            "aes128-cbc",
            "aes192-cbc",
            "aes256-cbc",
            "arcfour",
            "blowfish-cbc",
            "cast128-cbc",
        ],
        "forbidden_mac": ["hmac-md5", "hmac-sha1-96", "hmac-sha1", "umac-64@openssh.com"],
        "min_host_key_bits": 2048,
    },
    "ipsec": {
        "forbidden_tokens": ["des", "3des", "md5", "sha1", "sha-1", "group1", "group2", "group5"],
        "min_dh_group": 14,
    },
}

#: PQC-relevant key agreement names that are *not* classical-only
PQC_KEX_TOKENS = ("mlkem", "kyber", "x25519mlkem", "x25519_mlkem", "hybrid", "frodo", "sike", "ntru")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _norm(value: Any) -> str:
    return str(value or "").strip().lower().replace("_", "-")


def _endpoint(record: dict[str, Any]) -> str | None:
    target = record.get("target") or {}
    return target.get("endpoint") or (
        f"{target.get('host')}:{target.get('port')}" if target.get("host") else None
    )


def _observed(record: dict[str, Any]) -> bool:
    return str(record.get("evidence_type") or "").upper() in OBSERVED_EVIDENCE_TYPES


def merge_policy(policy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Deep-merge an operator policy over the bank baseline."""
    merged = {key: (dict(value) if isinstance(value, dict) else list(value) if isinstance(value, list) else value)
              for key, value in DEFAULT_POLICY.items()}
    for key, value in (policy or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    merged.setdefault("policy_id", POLICY_ID)
    merged.setdefault("version", POLICY_VERSION)
    return merged


def _finding(
    rule_id: str,
    severity: str,
    status: str,
    record: dict[str, Any],
    message: str,
    *,
    observed: Any = None,
    expected: Any = None,
    reference: str | None = None,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "status": status,
        "layer": LAYER,
        "protocol": record.get("protocol"),
        "endpoint": _endpoint(record),
        "evidence_id": record.get("evidence_id"),
        "evidence_type": record.get("evidence_type"),
        "observation_status": record.get("observation_status"),
        "observed": observed,
        "expected": expected,
        "message": message,
        "reference": reference,
        "observed_at": record.get("observed_at"),
    }


def _unknown(rule_id: str, record: dict[str, Any], message: str) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": "info",
        "status": "UNKNOWN",
        "layer": LAYER,
        "protocol": record.get("protocol"),
        "endpoint": _endpoint(record),
        "evidence_id": record.get("evidence_id"),
        "evidence_type": record.get("evidence_type"),
        "observation_status": record.get("observation_status"),
        "observed": None,
        "expected": None,
        "message": message,
        "reference": None,
        "observed_at": record.get("observed_at"),
    }


def _contains(text: Any, tokens: Iterable[str]) -> str | None:
    haystack = _norm(text)
    if not haystack:
        return None
    for token in tokens:
        if _norm(token) and _norm(token) in haystack:
            return token
    return None


# --------------------------------------------------------------- TLS rules


def _tls_rules(
    record: dict[str, Any],
    policy: dict[str, Any],
    now: datetime,
    endpoint: str | None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    version = record.get("tls_version")
    decomposition = record.get("decomposition") or {}
    certificate = record.get("certificate") or {}
    chain = record.get("certificate_chain") or {}
    suite = record.get("cipher_suite")

    if version:
        floor = _TLS_VERSION_RANK.get(_norm(policy["min_tls_version"]), 4)
        rank = _TLS_VERSION_RANK.get(_norm(version))
        if rank is None:
            findings.append(
                _finding(
                    "NET-TLS-VERSION-UNKNOWN",
                    "medium",
                    "UNKNOWN",
                    record,
                    f"negotiated version {version} is not in the recognised TLS version table",
                    observed=version,
                    expected=policy["min_tls_version"],
                )
            )
        elif rank < floor or str(version) in (policy.get("forbidden_tls_versions") or []):
            findings.append(
                _finding(
                    "NET-TLS-VERSION-MIN",
                    "critical" if rank <= 2 else "high",
                    "FAIL",
                    record,
                    f"{endpoint} negotiated {version}: below the {policy['min_tls_version']} floor",
                    observed=version,
                    expected=policy["min_tls_version"],
                    reference="PCI DSS 4.0 §4.2.1 / NIST SP 800-52r2",
                )
            )
        else:
            findings.append(
                _finding(
                    "NET-TLS-VERSION-MIN",
                    "high",
                    "PASS",
                    record,
                    f"{endpoint} negotiated {version}",
                    observed=version,
                    expected=policy["min_tls_version"],
                )
            )

    key_exchange = decomposition.get("key_exchange")
    if policy.get("require_forward_secrecy"):
        if key_exchange:
            if _contains(key_exchange, FORWARD_SECRECY_TOKENS) or _contains(key_exchange, PQC_KEX_TOKENS):
                findings.append(
                    _finding(
                        "NET-TLS-FORWARD-SECRECY",
                        "critical",
                        "PASS",
                        record,
                        f"key exchange {key_exchange} provides forward secrecy",
                        observed=key_exchange,
                        expected="ECDHE/DHE",
                    )
                )
            else:
                findings.append(
                    _finding(
                        "NET-TLS-FORWARD-SECRECY",
                        "critical",
                        "FAIL",
                        record,
                        f"key exchange {key_exchange} is static: recorded traffic can be decrypted "
                        "if the private key leaks, and it is harvested-now-decrypt-later exposed",
                        observed=key_exchange,
                        expected="ECDHE/DHE",
                        reference="NIST SP 800-57 / BSI TR-02102",
                    )
                )
        elif suite:
            # a TLS 1.2 suite name carries the key exchange even when the
            # decomposition is partial; TLS 1.3 always has forward secrecy
            if _norm(version) == "tlsv1.3":
                findings.append(
                    _finding(
                        "NET-TLS-FORWARD-SECRECY",
                        "critical",
                        "PASS",
                        record,
                        "TLS 1.3 always uses ephemeral key agreement",
                        observed=version,
                        expected="ECDHE/DHE",
                    )
                )
            else:
                findings.append(
                    _unknown("NET-TLS-FORWARD-SECRECY", record,
                             "cipher suite observed but key-exchange decomposition is empty")
                )

    dh_bits = decomposition.get("key_size_bits")
    if key_exchange and dh_bits and _contains(key_exchange, FINITE_FIELD_GROUP_TOKENS):
        try:
            bits = int(dh_bits)
        except (TypeError, ValueError):
            bits = 0
        if bits and bits < int(policy["min_dh_bits"]):
            findings.append(
                _finding(
                    "NET-TLS-DH-GROUP",
                    "high",
                    "FAIL",
                    record,
                    f"key exchange group is {bits} bits: below the {policy['min_dh_bits']}-bit floor",
                    observed=bits,
                    expected=policy["min_dh_bits"],
                    reference="NIST SP 800-57 Part 1",
                )
            )

    cipher_token = _contains(suite, policy["forbidden_cipher_tokens"])
    if suite and cipher_token:
        findings.append(
            _finding(
                "NET-TLS-CIPHER",
                "critical" if _norm(cipher_token) in {"rc4", "null", "export", "des-cbc", "3des"} else "high",
                "FAIL",
                record,
                f"cipher suite {suite} uses {cipher_token}",
                observed=suite,
                expected="AEAD (AES-GCM / ChaCha20-Poly1305)",
                reference="NIST SP 800-131A",
            )
        )
    elif suite:
        findings.append(
            _finding(
                "NET-TLS-CIPHER",
                "high",
                "PASS",
                record,
                f"cipher suite {suite} has no forbidden token",
                observed=suite,
                expected="AEAD (AES-GCM / ChaCha20-Poly1305)",
            )
        )

    mac = decomposition.get("mac_or_prf")
    mac_token = _contains(mac, policy["forbidden_mac_tokens"])
    if mac and mac_token:
        findings.append(
            _finding(
                "NET-TLS-MAC-PRF",
                "medium",
                "FAIL",
                record,
                f"MAC/PRF {mac} uses {mac_token}",
                observed=mac,
                expected="SHA-256 or stronger",
                reference="NIST SP 800-131A",
            )
        )

    signature = certificate.get("signature_algorithm")
    sig_token = _contains(signature, policy["forbidden_signature_tokens"])
    if signature and sig_token:
        findings.append(
            _finding(
                "NET-CERT-SIGNATURE",
                "high",
                "FAIL",
                record,
                f"certificate signature {signature} uses {sig_token}",
                observed=signature,
                expected="SHA-256 or stronger",
                reference="CA/Browser Forum BR 7.1.3",
            )
        )

    algorithm = _norm(certificate.get("public_key_algorithm"))
    bits = certificate.get("public_key_bits")
    if algorithm and bits:
        try:
            key_bits = int(bits)
        except (TypeError, ValueError):
            key_bits = 0
        floor_bits = int(policy["min_ec_bits"]) if "ec" in algorithm or "ed" in algorithm else int(policy["min_rsa_bits"])
        if key_bits and key_bits < floor_bits:
            findings.append(
                _finding(
                    "NET-CERT-KEY-SIZE",
                    "critical" if key_bits < 2048 else "high",
                    "FAIL",
                    record,
                    f"certificate public key is {certificate.get('public_key_algorithm')} {key_bits} bits: "
                    f"below the {floor_bits}-bit floor",
                    observed=f"{certificate.get('public_key_algorithm')} {key_bits}",
                    expected=f">= {floor_bits} bits",
                    reference="NIST SP 800-57 Part 1",
                )
            )

    not_after = _parse_time(certificate.get("not_after"))
    if not_after is not None:
        remaining = (not_after - now).days
        if remaining < 0:
            findings.append(
                _finding(
                    "NET-CERT-EXPIRY",
                    "critical",
                    "FAIL",
                    record,
                    f"certificate expired {abs(remaining)} day(s) ago",
                    observed=certificate.get("not_after"),
                    expected="valid",
                )
            )
        elif remaining <= int(policy["certificate_expiry_warning_days"]):
            findings.append(
                _finding(
                    "NET-CERT-EXPIRY",
                    "high",
                    "FAIL",
                    record,
                    f"certificate expires in {remaining} day(s)",
                    observed=certificate.get("not_after"),
                    expected=f"> {policy['certificate_expiry_warning_days']} days",
                )
            )

    if policy.get("require_complete_chain"):
        status = str(chain.get("structural_status") or "").upper()
        trust = str(chain.get("trust_status") or "").upper()
        if status and status not in {"COMPLETE", "VALID"}:
            findings.append(
                _finding(
                    "NET-CERT-CHAIN",
                    "high",
                    "FAIL",
                    record,
                    f"presented chain is {status}: clients may have to fetch or guess an intermediate",
                    observed=status,
                    expected="complete chain to a trusted root",
                )
            )
        elif trust and trust not in {"TRUSTED", "VALID"}:
            findings.append(
                _finding(
                    "NET-CERT-CHAIN",
                    "critical",
                    "FAIL",
                    record,
                    f"chain trust status is {trust}",
                    observed=trust,
                    expected="TRUSTED",
                )
            )

    required = [item for item in policy.get("require_mtls_endpoints") or [] if item]
    if required and endpoint and any(
        endpoint == item or endpoint.split(":")[0] == item for item in required
    ):
        mutual = str(record.get("mutual_tls") or "").upper()
        if mutual in {"CLIENT_CERT_REQUESTED", "REQUIRED", "ENABLED"}:
            findings.append(
                _finding("NET-MTLS-REQUIRED", "high", "PASS", record,
                         "server requested a client certificate", observed=mutual, expected="client certificate")
            )
        elif mutual == "NOT_REQUIRED":
            findings.append(
                _finding(
                    "NET-MTLS-REQUIRED",
                    "high",
                    "FAIL",
                    record,
                    f"{endpoint} is in the mTLS-required set but completed a handshake without a client certificate",
                    observed=mutual,
                    expected="client certificate",
                    reference="policy.require_mtls_endpoints",
                )
            )
    return findings


# --------------------------------------------------------------- SSH rules


def _ssh_rules(record: dict[str, Any], policy: dict[str, Any]) -> list[dict[str, Any]]:
    ssh_policy = policy.get("ssh") or {}
    ssh = record.get("ssh") or {}
    offered = ssh.get("algorithms_offered") or {}
    findings: list[dict[str, Any]] = []

    for field, key in (
        ("kex", "NET-SSH-KEX"),
        ("host_key", "NET-SSH-HOST-KEY"),
        ("cipher", "NET-SSH-CIPHER"),
        ("mac", "NET-SSH-MAC"),
    ):
        values = [str(item) for item in offered.get(field) or []]
        forbidden = ssh_policy.get(f"forbidden_{field}") or []
        weak = [item for item in values if _contains(item, forbidden)]
        if weak:
            findings.append(
                _finding(
                    key,
                    "high" if field in {"kex", "host_key"} else "medium",
                    "FAIL",
                    record,
                    f"SSH server offers {len(weak)} deprecated {field} algorithm(s): {', '.join(weak[:4])}"
                    + ("…" if len(weak) > 4 else ""),
                    observed=weak[:8],
                    expected=f"no legacy {field}",
                    reference="NIST SP 800-131A / RFC 8332",
                )
            )
        elif values:
            findings.append(
                _finding(key, "high" if field in {"kex", "host_key"} else "medium", "PASS", record,
                         f"no deprecated {field} algorithm offered", observed=len(values), expected=f"no legacy {field}")
            )

    minimum = int(ssh_policy.get("min_host_key_bits") or 2048)
    for key in ssh.get("host_keys") or []:
        bits = key.get("bits")
        if not bits:
            continue
        try:
            key_bits = int(bits)
        except (TypeError, ValueError):
            continue
        key_type = _norm(key.get("key_type"))
        # ed25519 / ecdsa are not RSA bit-lengths; only apply the RSA floor
        if "rsa" in key_type and key_bits < minimum:
            findings.append(
                _finding(
                    "NET-SSH-HOST-KEY-SIZE",
                    "high",
                    "FAIL",
                    record,
                    f"SSH host key {key.get('key_type')} is {key_bits} bits: below {minimum}",
                    observed=f"{key.get('key_type')} {key_bits}",
                    expected=f">= {minimum} bits",
                )
            )
    return findings


# ---------------------------------------------------------------- DB rules


def _db_rules(record: dict[str, Any], policy: dict[str, Any]) -> list[dict[str, Any]]:
    database = record.get("database") or {}
    transport = database.get("transport") or {}
    findings: list[dict[str, Any]] = []
    engine = database.get("engine") or "database"

    if transport.get("tls_negotiated") is True:
        findings.append(
            _finding("NET-DB-TLS", "high", "PASS", record,
                     f"{engine} transport is TLS-protected ({transport.get('tls_version')})",
                     observed=transport.get("tls_version"), expected="TLS")
        )
    elif transport.get("ssl_supported") is False:
        findings.append(
            _finding(
                "NET-DB-TLS",
                "critical",
                "FAIL",
                record,
                f"{engine} refused/does not offer TLS: credentials and rows cross the network in plaintext",
                observed="TLS_NOT_OFFERED",
                expected="TLS required",
                reference="PCI DSS 4.0 §4.2.1",
            )
        )
    else:
        findings.append(
            _unknown("NET-DB-TLS", record,
                     f"{engine} transport crypto NOT_OBSERVED — a refusal is not proof of absence")
        )
    findings.append(
        _unknown(
            "NET-DB-STORAGE",
            record,
            "TDE, column encryption and runtime query crypto are invisible to a network scan "
            "(§18) — the database collector owns them",
        )
    )
    return findings


# ------------------------------------------------------------- IPsec rules


def _ipsec_rules(record: dict[str, Any], policy: dict[str, Any]) -> list[dict[str, Any]]:
    ipsec_policy = policy.get("ipsec") or {}
    proposals = record.get("ike") or record.get("ipsec") or {}
    findings: list[dict[str, Any]] = []
    forbidden = ipsec_policy.get("forbidden_tokens") or []
    seen: list[str] = []
    for proposal in proposals.get("proposals") or proposals.get("sa_proposals") or []:
        for field in ("encryption", "integrity", "prf", "dh_group"):
            value = proposal.get(field) if isinstance(proposal, dict) else None
            if value and _contains(value, forbidden):
                seen.append(f"{field}={value}")
    if seen:
        findings.append(
            _finding("NET-IPSEC-ALGORITHM", "high", "FAIL", record,
                     f"IKE proposal uses deprecated algorithms: {', '.join(seen[:5])}",
                     observed=seen[:8], expected="AES-GCM / SHA-2 / DH >= 14",
                     reference="RFC 8221")
        )
    elif proposals:
        findings.append(_finding("NET-IPSEC-ALGORITHM", "high", "PASS", record,
                                 "no deprecated IKE proposal observed", observed="ok",
                                 expected="AES-GCM / SHA-2 / DH >= 14"))
    else:
        findings.append(_unknown("NET-IPSEC-ALGORITHM", record,
                                 "no IKE proposal payload was returned"))
    return findings


# ------------------------------------------------------------------- driver


def evaluate(
    records: Iterable[dict[str, Any]],
    policy: dict[str, Any] | None = None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Evaluate network evidence against the policy pack.

    Unobserved records become ``status="UNKNOWN"`` coverage gaps; they never
    silently pass. The report always states what it could not judge.
    """
    effective = merge_policy(policy)
    clock = now or _now()
    findings: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    endpoints: set[str] = set()
    protocols: dict[str, int] = {}

    for record in records:
        endpoint = _endpoint(record)
        if endpoint:
            endpoints.add(endpoint)
        protocol = str(record.get("protocol") or record.get("detection", {}).get("detected") or "UNKNOWN").upper()
        protocols[protocol] = protocols.get(protocol, 0) + 1

        if not _observed(record):
            gaps.append(
                _unknown(
                    "NET-EVIDENCE-COVERAGE",
                    record,
                    f"{endpoint or 'endpoint'} has {record.get('evidence_type') or 'no'} evidence: "
                    "its crypto is UNKNOWN, not compliant",
                )
            )
            continue

        if protocol in {"TLS", "HTTPS", "POSTGRESQL", "MYSQL", "DATABASE"}:
            findings.extend(_tls_rules(record, effective, clock, endpoint))
            if record.get("database"):
                findings.extend(_db_rules(record, effective))
        elif protocol == "SSH":
            findings.extend(_ssh_rules(record, effective))
        elif protocol in {"IPSEC", "IKE", "ESP"}:
            findings.extend(_ipsec_rules(record, effective))
        else:
            gaps.append(_unknown("NET-EVIDENCE-COVERAGE", record,
                                 f"{protocol} evidence exists but no policy rule matches this protocol"))

    all_findings = findings + gaps
    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for finding in all_findings:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
        by_status[finding["status"]] = by_status.get(finding["status"], 0) + 1

    failed = [item for item in all_findings if item["status"] == "FAIL"]
    failed.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["rule_id"]))
    unknown_count = len([item for item in all_findings if item["status"] == "UNKNOWN"])
    verdict = (
        "NO_EVIDENCE"
        if not endpoints
        else "FAIL"
        if failed
        else "NOT_ASSESSABLE"
        if unknown_count and not [item for item in all_findings if item["status"] == "PASS"]
        else "PASS_WITH_UNKNOWN"
        if unknown_count
        else "PASS"
    )
    return {
        "model": MODEL,
        "policy": {
            "policy_id": effective["policy_id"],
            "version": effective["version"],
            "min_tls_version": effective["min_tls_version"],
            "require_forward_secrecy": effective["require_forward_secrecy"],
        },
        "layer": LAYER,
        "verdict": verdict,
        "findings": all_findings,
        "failed": failed,
        "coverage_gaps": gaps,
        "summary": {
            "endpoints": len(endpoints),
            "records": sum(protocols.values()),
            "protocols": protocols,
            "by_severity": by_severity,
            "by_status": by_status,
            "failed": len(failed),
            "unknown": unknown_count,
            "rules": sorted({item["rule_id"] for item in all_findings}),
        },
        "limitations": [
            "only observed parameters are judged — CONFIG_IMPORTED, VENDOR_DECLARED and UNKNOWN "
            "records are coverage gaps, never passes",
            "a policy verdict on transport crypto says nothing about application, storage or HSM crypto",
            "a PASS means the observed handshake met the pack; it is not an assurance that every "
            "path to the service looks the same",
        ],
        "evaluated_at": clock.isoformat(),
    }


def pqc_readiness(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Report post-quantum readiness from network-observable facts only.

    A classical handshake is harvest-now-decrypt-later exposed; a hybrid group
    is the only network-visible sign of PQ migration. Certificate signature
    algorithms are counted separately because a PQ key exchange with an RSA
    certificate is still only half migrated.
    """
    endpoints: list[dict[str, Any]] = []
    kex_counts: dict[str, int] = {}
    signature_counts: dict[str, int] = {}
    unobserved = 0

    for record in records:
        endpoint = _endpoint(record)
        if not _observed(record):
            unobserved += 1
            endpoints.append(
                {
                    "endpoint": endpoint,
                    "readiness": "NOT_OBSERVED",
                    "key_exchange": None,
                    "certificate_signature": None,
                    "note": "no handshake observed — readiness is unknown, not classical and not PQ",
                }
            )
            continue
        decomposition = record.get("decomposition") or {}
        certificate = record.get("certificate") or {}
        ssh = record.get("ssh") or {}
        key_exchange = decomposition.get("key_exchange") or (
            (ssh.get("algorithms_offered") or {}).get("kex") or [None]
        )[0]
        signature = certificate.get("signature_algorithm")
        hybrid = bool(_contains(key_exchange, PQC_KEX_TOKENS))
        if key_exchange:
            kex_counts[str(key_exchange)] = kex_counts.get(str(key_exchange), 0) + 1
        if signature:
            signature_counts[str(signature)] = signature_counts.get(str(signature), 0) + 1
        if hybrid:
            readiness = "HYBRID_KEX_OBSERVED"
        elif key_exchange:
            readiness = "CLASSICAL_ONLY"
        else:
            readiness = "NOT_OBSERVED"
        endpoints.append(
            {
                "endpoint": endpoint,
                "readiness": readiness,
                "key_exchange": key_exchange,
                "certificate_signature": signature,
                "harvest_now_decrypt_later_exposed": readiness == "CLASSICAL_ONLY",
                "note": (
                    "hybrid post-quantum key agreement observed"
                    if hybrid
                    else "classical key agreement only: recorded traffic is harvest-now-decrypt-later exposed"
                    if readiness == "CLASSICAL_ONLY"
                    else "key agreement not observed"
                ),
            }
        )

    observed_rows = [row for row in endpoints if row["readiness"] != "NOT_OBSERVED"]
    hybrid_count = len([row for row in observed_rows if row["readiness"] == "HYBRID_KEX_OBSERVED"])
    return {
        "model": "cryptoscan.network-pqc-readiness/1",
        "layer": LAYER,
        "endpoints": endpoints,
        "summary": {
            "endpoints": len(endpoints),
            "observed": len(observed_rows),
            "not_observed": unobserved,
            "hybrid_kex": hybrid_count,
            "classical_only": len(observed_rows) - hybrid_count,
            "key_exchange": kex_counts,
            "certificate_signature": signature_counts,
        },
        "verdict": (
            "NOT_OBSERVED"
            if not observed_rows
            else "HYBRID_KEX_PRESENT"
            if hybrid_count == len(observed_rows)
            else "PARTIAL"
            if hybrid_count
            else "CLASSICAL_ONLY"
        ),
        "limitations": [
            "network observation sees the negotiated group, not the library's PQC roadmap",
            "a hybrid key exchange does not mean the certificates are PQ-signed: signature algorithm "
            "is reported separately",
            "storage, application and HSM crypto (where the long-lived secrets live) are out of network reach",
        ],
    }


# ---------------------------------------------------------- NBOM / TechBOM


def to_nbom(records: Iterable[dict[str, Any]], *, estate: str | None = None) -> dict[str, Any]:
    """Project network evidence into a CycloneDX NBOM (spec §28)."""
    from cbom.nbom import build_nbom

    endpoints: list[dict[str, Any]] = []
    tunnels: list[dict[str, Any]] = []
    devices: list[dict[str, Any]] = []
    seen: set[str] = set()

    for record in records:
        target = record.get("target") or {}
        endpoint = _endpoint(record)
        if not endpoint or endpoint in seen:
            continue
        seen.add(endpoint)
        protocol = str(record.get("protocol") or "UNKNOWN").upper()
        observed = _observed(record)
        if protocol in {"IPSEC", "IKE", "ESP"}:
            ike = record.get("ike") or record.get("ipsec") or {}
            tunnels.append(
                {
                    "name": endpoint,
                    "kind": "IPsec",
                    "peer": target.get("host"),
                    "encryption": ike.get("encryption"),
                    "integrity": ike.get("integrity"),
                    "key_exchange": ike.get("dh_group"),
                    "observed": observed,
                    "device": (record.get("context") or {}).get("device"),
                }
            )
            continue
        certificate = record.get("certificate") or {}
        endpoints.append(
            {
                "host": target.get("host") or endpoint.rsplit(":", 1)[0],
                "port": target.get("port") or endpoint.rsplit(":", 1)[-1],
                "protocol": protocol,
                "tls_version": record.get("tls_version"),
                "cipher_suite": record.get("cipher_suite"),
                "service": (record.get("detection") or {}).get("detected"),
                "observed": observed,
                "certificate": {
                    "subject": certificate.get("subject"),
                    "issuer": certificate.get("issuer"),
                    "public_key_algorithm": certificate.get("public_key_algorithm"),
                    "public_key_size": certificate.get("public_key_bits"),
                    "not_after": certificate.get("not_after"),
                    "is_self_signed": bool(
                        certificate.get("subject") and certificate.get("subject") == certificate.get("issuer")
                    ),
                }
                if certificate.get("subject")
                else {},
            }
        )
        device = (record.get("context") or {}).get("device")
        if device:
            devices.append({"name": device, "role": "terminator"})

    nbom = build_nbom(endpoints, tunnels=tunnels, devices=devices, estate=estate)
    nbom["metadata"]["properties"] = [
        {"name": "cryptoscan:model", "value": MODEL},
        {"name": "cryptoscan:layer", "value": LAYER},
        {"name": "cryptoscan:unobserved_endpoints", "value": str(len([e for e in endpoints if not e["observed"]]))},
    ]
    return nbom


def to_techbom(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Protocol/service inventory observed on the network (a TechBOM, not a CBOM)."""
    protocols: dict[str, dict[str, Any]] = {}
    services: dict[str, int] = {}
    endpoints: set[str] = set()
    for record in records:
        endpoint = _endpoint(record)
        if endpoint:
            endpoints.add(endpoint)
        protocol = str(record.get("protocol") or "UNKNOWN").upper()
        bucket = protocols.setdefault(protocol, {"endpoints": 0, "observed": 0, "not_observed": 0})
        bucket["endpoints"] += 1
        if _observed(record):
            bucket["observed"] += 1
        else:
            bucket["not_observed"] += 1
        detected = (record.get("detection") or {}).get("detected")
        if detected:
            services[str(detected)] = services.get(str(detected), 0) + 1
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "bom_type": "TECHBOM",
        "model": "cryptoscan.network-techbom/1",
        "endpoints": len(endpoints),
        "protocols": [
            {"protocol": protocol, **counts} for protocol, counts in sorted(protocols.items())
        ],
        "services": [{"service": name, "endpoints": count} for name, count in sorted(services.items())],
        "note": "a TechBOM records which protocols and services are exposed; it makes no crypto claim",
    }
