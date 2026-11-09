"""OS-CRYPTO rule catalogue (docs/os-kernel-intelligence/
01_PRODUCT_SPEC.md §9).

These are PROPOSED DETECTION RULES, not automatic vulnerability
verdicts. Every rule produces a finding whose wording is a detection,
and every detection carries its evidence source, observation type and
limitations. A rule whose evidence source was not collected evaluates
to NOT EVALUABLE with the missing source named — it never reports a
clean result (§2.1).

Severity is computed (risk.py, R=f(S,E,X,B,C)), never named by hand.
Runtime usage is never confirmed by these detections (§2.2). No rule
infers application↔kernel relationships from same-host co-location.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Sequence

from .risk import RiskAssessment, assess

RULE_MODEL_VERSION = "os-crypto-rules/1.0"

#: Weak / legacy algorithm registrations (OS-CRYPTO-001/005 inputs).
#: Presence is a REGISTERED IMPLEMENTATION — never proof of use (§2.2).
_WEAK_ALGORITHMS = {
    "des", "des3_ede", "md5", "md4", "sha1", "rc4", "arc4", "tea",
    "xtea", "cast5", "cast6", "anubis", "khazad", "tgr192", "wp512",
    "wp384", "wp256", "rmd128", "rmd160", "rmd256", "rmd320", "null",
}
#: SHA-1/HMAC-SHA1 and MD5 as digest are weak; sha1 as a CIPHER digest
#: inside hmac(...) is still noted for review but is not the same claim.
_LEGACY_PROVIDER_MODULES = {"ansi_cprng", "tcrypt", "crypto_null"}

#: PQC-family names: presence identifies a MIGRATION DEPENDENCY for
#: planning — presence is never usage and never readiness.
_PQC_NAMES = ("kyber", "ml-kem", "dilithium", "ml-dsa", "sphincs",
              "falcon", "bike", "hqc", "mceliece", "ntru")

_CRYPTO_MODULE_HINTS = ("aes", "sha", "crypto", "cryptd", "af_alg",
                        "algif", "ansi_cprng", "tcrypt", "chacha",
                        "poly1305", "curve25519", "rsa", "dh", "ecc",
                        "essiv", "xts", "cbc", "ecb", "gcm", "cmac",
                        "hmac", "drbg", "jitter", "rng")


@dataclass
class RuleResult:
    rule_id: str
    detection: str
    potential_impact: str
    status: str                       # "evaluated" | "not_evaluable"
    evaluation_note: str
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "detection": self.detection,
            "potential_impact": self.potential_impact,
            "status": self.status,
            "evaluation_note": self.evaluation_note,
            "findings": self.findings,
            "note": "a detection rule result, never an automatic "
                    "vulnerability verdict (§9)",
        }


@dataclass
class RuleReport:
    results: List[RuleResult]
    model_version: str = RULE_MODEL_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_model_version": self.model_version,
            "results": [r.as_dict() for r in self.results],
            "note": "rule results are detections, not verdicts (§9); "
                    "severity is computed by risk.py with preserved "
                    "factors; a not_evaluable rule is never a clean "
                    "result (§2.1)",
        }


def _finding(*, rule_id: str, detection: str, subject: str,
             evidence_source: str, observation_type: str,
             evidence_class: str, details: Dict[str, Any],
             limitations: List[str],
             risk: RiskAssessment) -> Dict[str, Any]:
    d = risk.as_dict()
    return {
        "finding_type": rule_id,
        "host_id": subject,
        "algorithm": details.get("algorithm", ""),
        "implementation": details.get("implementation", ""),
        "evidence_source": evidence_source,
        "observation_type": observation_type,
        "runtime_usage_confirmed": False,
        "evidence_class": evidence_class,
        "severity_label": d["severity_label"],
        "severity_factors": {"factors": d["factors"],
                             "derivation": d["derivation"]},
        "risk_model_version": d["risk_model_version"],
        "details": {k: v for k, v in details.items()
                    if k not in ("algorithm", "implementation")},
        "limitations": limitations + [d["note"]],
    }


def _not_evaluable(rule_id: str, detection: str, impact: str,
                   missing_source: str, why: str) -> RuleResult:
    return RuleResult(
        rule_id=rule_id, detection=detection, potential_impact=impact,
        status="not_evaluable",
        evaluation_note=f"evidence source {missing_source} was not "
                        f"collected — {why}. The missing source is "
                        "recorded as unavailable and is NEVER treated "
                        "as 'disabled', 'absent' or a clean result "
                        "(§2.1).")


#: the catalogue itself (§9 table) — what each rule detects.
CATALOGUE = (
    ("OS-CRYPTO-001", "Weak cryptographic implementation exposed",
     "Legacy cryptographic risk"),
    ("OS-CRYPTO-002", "Deprecated cryptographic interface enabled",
     "Increased attack surface"),
    ("OS-CRYPTO-003", "Unexpected crypto module loaded",
     "Possible configuration drift"),
    ("OS-CRYPTO-004", "Untrusted or unexpected driver signature",
     "Kernel integrity concern"),
    ("OS-CRYPTO-005", "Legacy provider detected", "Migration assessment"),
    ("OS-CRYPTO-006", "TLS configuration allows weak protocols",
     "Network cryptographic exposure"),
    ("OS-CRYPTO-007", "Disk encryption not established",
     "Data-at-rest protection gap"),
    ("OS-CRYPTO-008", "Certificate near expiration",
     "Service availability risk"),
    ("OS-CRYPTO-009", "TPM unavailable or misconfigured",
     "Hardware trust concern"),
    ("OS-CRYPTO-010", "Secure Boot disabled", "Boot integrity concern"),
    ("OS-CRYPTO-011", "Crypto provider version vulnerable",
     "Potential software risk"),
    ("OS-CRYPTO-012", "Cryptographic configuration changed",
     "Drift investigation"),
    ("OS-CRYPTO-013", "Unexpected kernel module signer",
     "Integrity investigation"),
    ("OS-CRYPTO-014", "Randomness configuration concern",
     "Cryptographic assurance concern"),
    ("OS-CRYPTO-015", "PQC migration dependency identified",
     "Migration planning requirement"),
    ("OS-CRYPTO-016", "Kernel crypto capability unavailable",
     "Compatibility or dependency concern"),
    ("OS-CRYPTO-017", "Runtime collector losing events",
     "Observability gap"),
    ("OS-CRYPTO-018", "HSM or TPM provider state changed",
     "Hardware trust investigation"),
)

_BY_ID = {r[0]: (r[1], r[2]) for r in CATALOGUE}


def _wrap(rule_id: str, status: str, note: str,
          findings: Optional[List[Dict[str, Any]]] = None) -> RuleResult:
    detection, impact = _BY_ID[rule_id]
    return RuleResult(rule_id=rule_id, detection=detection,
                      potential_impact=impact, status=status,
                      evaluation_note=note, findings=findings or [])

_DATE_FORMATS = (
    "%b %d %H:%M:%S %Y",        # openssl: Jun  4 11:04:38 2035 GMT
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %I:%M %p",        # certutil (en-US locale)
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%d",
)


def _parse_cert_date(value: str) -> Optional[date]:
    """Parse a certificate validity date. Unparseable dates are
    UNKNOWN — never guessed (§2.1)."""
    text = value.strip()
    if text.endswith("GMT"):
        text = text[:-3].strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(" ".join(text.split()), fmt).date()
        except ValueError:
            continue
    return None


def evaluate(inventory: Dict[str, Any],
             *, baseline_modules: Optional[Sequence[str]] = None,
             previous: Optional[Dict[str, Any]] = None,
             as_of: Optional["date"] = None,
             runtime_session: Optional[Any] = None) -> RuleReport:
    """Evaluate the catalogue against one collected inventory.

    Optional inputs change evaluability only — they never fabricate
    evidence: `baseline_modules` (declared expected modules, for
    OS-CRYPTO-003), `previous` (a prior collection, for OS-CRYPTO-
    012/018 drift) and `as_of` (the clock for certificate expiration
    evaluation — tests pass a fixed date, production uses today).
    Without them those rules stay not_evaluable."""
    today = as_of or date.today()
    results: List[RuleResult] = []
    identity = inventory.get("identity", {}) or {}
    platform = str(identity.get("platform", "linux")).lower()
    subject = str(inventory.get("host_id", "unknown"))
    crypto = inventory.get("crypto_api", []) or []
    modules = inventory.get("modules", []) or []
    flags = inventory.get("config_flags", {}) or {}
    storage = inventory.get("storage", []) or []
    trust = inventory.get("hardware_trust", []) or []
    coverage = inventory.get("coverage", {}) or {}
    collected = set(coverage.get("sources_collected", []) or [])

    # --- OS-CRYPTO-001: weak implementation exposed ------------------
    weak_rows = []
    for entry in crypto:
        name = str(entry.get("algorithm", ""))
        components = {name, name.split("(")[0]}
        components.update(part for part in name.replace(")", "(").split("(")
                          if part)
        if components & _WEAK_ALGORITHMS:
            weak_rows.append(entry)
    if "proc_crypto" not in collected and not crypto:
        results.append(_not_evaluable(
            "OS-CRYPTO-001", *_BY_ID["OS-CRYPTO-001"],
            "/proc/crypto",
            "the registered-implementation inventory is unavailable"))
    elif weak_rows:
        findings = []
        for entry in weak_rows:
            findings.append(_finding(
                rule_id="OS-CRYPTO-001",
                detection="Weak cryptographic implementation exposed",
                subject=subject,
                evidence_source="Linux Kernel Crypto API (/proc/crypto)",
                observation_type="registered_capability",
                evidence_class="observed",
                details={
                    "algorithm": entry.get("algorithm", ""),
                    "implementation": entry.get("driver", ""),
                    "condition": "algorithm is considered weak or "
                                 "legacy and is registered on this host",
                    "observed_runtime_negotiation": "Not established",
                    "affected_service": "Requires correlation",
                    "business_system": "Requires registered mapping",
                    "risk": "Legacy cryptographic risk — a registered "
                            "weak implementation is exposure of the "
                            "host, not evidence that any application "
                            "used it",
                    "recommendation": "Review whether this "
                        "implementation is required on this host; plan "
                        "migration where it is.",
                },
                limitations=[
                    "a registered implementation is inventory, never "
                    "proof of runtime use (§2.2)",
                    "weakness is a property of the algorithm as "
                    "registered; it is not a vulnerability verdict",
                ],
                risk=assess(security_significance="medium",
                            evidence_class="observed",
                            exposure="configuration_only")))
        results.append(_wrap("OS-CRYPTO-001", "evaluated",
                             f"{len(weak_rows)} weak/legacy "
                             "implementations registered", findings))
    else:
        results.append(_wrap(
            "OS-CRYPTO-001", "evaluated",
            "no weak or legacy implementations among the registered "
            "entries — 'not detected' is never 'absent' (§2.1)",
            [_finding(rule_id="OS-CRYPTO-001",
                      detection="Weak cryptographic implementation exposed",
                      subject=subject,
                      evidence_source="Linux Kernel Crypto API "
                                      "(/proc/crypto)",
                      observation_type="registered_capability",
                      evidence_class="not_detected",
                      details={"condition": "not detected among "
                                            "registered implementations"},
                      limitations=["not_detected is never proof of "
                                   "absence — only that this detection "
                                   "did not fire on the collected "
                                   "inventory (§2.1)"],
                      risk=assess(security_significance="low",
                                  evidence_class="not_detected"))]))

    # --- OS-CRYPTO-002: deprecated interface enabled -----------------
    af_alg = flags.get("CONFIG_CRYPTO_USER_API") if platform == "linux" \
        else None
    if platform != "linux":
        results.append(_not_evaluable(
            "OS-CRYPTO-002", *_BY_ID["OS-CRYPTO-002"],
            "the Linux kernel configuration (CONFIG_CRYPTO_USER_API)",
            "this source is Linux-specific and this is a "
            f"{platform} collection — not_evaluable, never clean"))
    elif af_alg is None and "config_flags" not in collected:
        results.append(_not_evaluable(
            "OS-CRYPTO-002", *_BY_ID["OS-CRYPTO-002"],
            "kernel configuration",
            "the kernel configuration source is unavailable"))
    elif af_alg in ("y", "m"):
        results.append(_wrap("OS-CRYPTO-002", "evaluated",
            "AF_ALG user-api interface is enabled in the kernel "
            "configuration", [_finding(
                rule_id="OS-CRYPTO-002",
                detection="Deprecated cryptographic interface enabled",
                subject=subject,
                evidence_source="kernel configuration",
                observation_type="configuration_state",
                evidence_class="observed",
                details={"flag": "CONFIG_CRYPTO_USER_API",
                         "value": af_alg,
                         "condition": "the AF_ALG user-space crypto "
                                      "interface is enabled",
                         "risk": "increased attack surface where "
                                 "untrusted local code executes",
                         "recommendation": "assess the kernel version "
                             "and this host's use case before any "
                             "change — AF_ALG is not blanket-"
                             "recommended for disabling (§5)"},
                limitations=["a configuration state is not runtime "
                             "usage; no application was observed using "
                             "AF_ALG"],
                risk=assess(security_significance="medium",
                            evidence_class="observed",
                            exposure="configuration_only"))]))
    else:
        results.append(_wrap(
            "OS-CRYPTO-002", "evaluated",
            f"CONFIG_CRYPTO_USER_API recorded as {af_alg!r} — 'not "
            "detected' is never 'absent' (§2.1)", []))

    # --- OS-CRYPTO-003: unexpected crypto module --------------------
    if baseline_modules is None:
        results.append(_not_evaluable(
            "OS-CRYPTO-003", *_BY_ID["OS-CRYPTO-003"],
            "a declared module baseline",
            "without a declared baseline 'unexpected' cannot be "
            "asserted — observed modules are inventoried, never judged"))
    else:
        expected = set(baseline_modules)
        unexpected = [m for m in modules
                      if m.get("name") not in expected
                      and any(h in str(m.get("name", "")) for h in
                              _CRYPTO_MODULE_HINTS)]
        findings = [_finding(
            rule_id="OS-CRYPTO-003",
            detection="Unexpected crypto module loaded",
            subject=subject,
            evidence_source="/proc/modules vs declared baseline",
            observation_type="loaded_module",
            evidence_class="indicated",
            details={"module": m.get("name", ""),
                     "condition": "module matches crypto provider "
                                  "hints and is not in the declared "
                                  "baseline",
                     "risk": "possible configuration drift"},
            limitations=["'unexpected' is judged against the DECLARED "
                         "baseline supplied for this evaluation, not "
                         "against any platform-invented expectation",
                         "a missing /proc/modules row is never proof a "
                         "feature is unavailable — it may be built in"],
            risk=assess(security_significance="medium",
                        evidence_class="indicated")) for m in unexpected]
        results.append(_wrap(
            "OS-CRYPTO-003", "evaluated",
            f"{len(unexpected)} crypto-hinted modules outside the "
            "declared baseline" if unexpected else
            "no crypto-hinted modules outside the declared baseline — "
            "'not detected' is never 'absent' (§2.1)",
            findings))

    # --- OS-CRYPTO-004: untrusted/unexpected driver signature --------
    taints = identity.get("tainted_meanings", []) or []
    integrity_taints = [t for t in taints if t in
                        ("UNSIGNED_MODULE", "OUT_OF_TREE_MODULE",
                         "FORCED_MODULE", "PROPRIETARY_MODULE")]
    if integrity_taints:
        results.append(_wrap("OS-CRYPTO-004", "evaluated",
            f"kernel taints recorded: {', '.join(integrity_taints)}",
            [_finding(
                rule_id="OS-CRYPTO-004",
                detection="Untrusted or unexpected driver signature",
                subject=subject,
                evidence_source="/proc/sys/kernel/tainted",
                observation_type="configuration_state",
                evidence_class="observed",
                details={"taint_flags": identity.get("tainted_flags"),
                         "taint_meanings": integrity_taints,
                         "condition": "the running kernel carries "
                                      "taint state indicating "
                                      "unsigned/out-of-tree/forced "
                                      "modules",
                         "risk": "kernel integrity concern — the "
                                 "kernel is outside its supported "
                                 "pristine condition",
                         "recommendation": "establish which module set "
                             "the bank expects on this host and "
                             "reconcile"},
                limitations=["a taint flag is a state record, never a "
                             "defect verdict (§1)",
                             "the taint does not identify which module "
                             "set it"],
                risk=assess(security_significance="high",
                            evidence_class="observed",
                            exposure="configuration_only"))]))
    elif "tainted" in collected:
        results.append(_wrap(
            "OS-CRYPTO-004", "evaluated",
            "no integrity-relevant taints recorded — the tainted "
            "source was read and carries no integrity flag; 'not "
            "detected' is never 'absent' (§2.1)", []))
    else:
        results.append(_not_evaluable(
            "OS-CRYPTO-004", *_BY_ID["OS-CRYPTO-004"],
            "/proc/sys/kernel/tainted",
            "the taint source is unavailable — unavailable is never "
            "'no taints' (§2.1)"))

    # --- OS-CRYPTO-005: legacy provider ------------------------------
    legacy = [e for e in crypto
              if str(e.get("module", "")) in _LEGACY_PROVIDER_MODULES
              or str(e.get("driver", "")) in _LEGACY_PROVIDER_MODULES]
    if not crypto:
        results.append(_not_evaluable(
            "OS-CRYPTO-005", *_BY_ID["OS-CRYPTO-005"],
            "/proc/crypto",
            "the provider inventory is unavailable"))
    elif legacy:
        results.append(_wrap("OS-CRYPTO-005", "evaluated",
            f"{len(legacy)} legacy provider registrations found",
            [_finding(
                rule_id="OS-CRYPTO-005",
                detection="Legacy provider detected",
                subject=subject,
                evidence_source="Linux Kernel Crypto API (/proc/crypto)",
                observation_type="registered_capability",
                evidence_class="observed",
                details={"algorithm": e.get("algorithm", ""),
                         "implementation": e.get("driver", ""),
                         "module": e.get("module", ""),
                         "condition": "implementation is provided by a "
                                      "known-legacy provider module",
                         "risk": "migration assessment — legacy "
                                 "providers constrain future crypto "
                                 "agility"},
                limitations=["registered provider is inventory, never "
                             "proof of use (§2.2)"],
                risk=assess(security_significance="low",
                            evidence_class="observed",
                            exposure="configuration_only"))
             for e in legacy]))
    else:
        results.append(_wrap(
            "OS-CRYPTO-005", "evaluated",
            "no legacy provider modules among the registrations — "
            "'not detected' is never 'absent' (§2.1)", []))

    # --- OS-CRYPTO-006: weak TLS -------------------------------------
    # The three TLS findings stay DISTINCT (§9): this rule reads the
    # ENABLED-BY-CONFIG axis only. 'supported' and 'observed-
    # negotiated' are never established here.
    weak_tls_protocols = ("tls 1.0", "tls 1.1", "ssl 2.0", "ssl 3.0")
    enabled_rows = [
        (key, value) for key, value in flags.items()
        if key.startswith("SCHANNEL\\")
        and key.lower().split("\\")[1] in weak_tls_protocols
        and key.lower().endswith("\\enabled")
        and value == "enabled"]
    schannel_collected = any(
        k.startswith("SCHANNEL\\") for k in flags) or any(
        "schannel" in str(u).lower()
        for u in coverage.get("sources_unavailable", []) or [])
    if not schannel_collected and platform == "linux":
        results.append(_not_evaluable(
            "OS-CRYPTO-006", *_BY_ID["OS-CRYPTO-006"],
            "TLS configuration and runtime negotiation sources",
            "the OS engine does not collect TLS configuration; the "
            "three TLS findings (supported / enabled-by-config / "
            "observed-negotiated) are distinct claims and none is "
            "available here"))
    elif not schannel_collected:
        results.append(_not_evaluable(
            "OS-CRYPTO-006", *_BY_ID["OS-CRYPTO-006"],
            "the SCHANNEL protocol registry",
            "the TLS configuration source is unavailable — "
            "unavailable is never 'no weak protocol' (§2.1)"))
    elif enabled_rows:
        findings = []
        for key, value in enabled_rows:
            protocol = key.split("\\")[1]
            side = key.split("\\")[2]
            findings.append(_finding(
                rule_id="OS-CRYPTO-006",
                detection="TLS configuration allows weak protocols",
                subject=subject,
                evidence_source="SCHANNEL protocol registry "
                                "(configuration state)",
                observation_type="configuration_state",
                evidence_class="observed",
                details={
                    "configured_protocol": protocol,
                    "configured_side": side,
                    "configured_state": value,
                    "observed_runtime_negotiation": "Not established",
                    "affected_service": "Requires correlation",
                    "business_system": "Requires registered mapping",
                    "condition": f"configuration PERMITS {protocol} "
                                 f"on the {side} side",
                    "risk": "legacy protocol exposure — a permitted "
                            "protocol, not a witnessed negotiation",
                    "recommendation": "review application "
                        "compatibility, approved protocol policy and "
                        "client dependencies",
                },
                limitations=[
                    "this is the ENABLED-BY-CONFIG axis only — "
                    "'supported' and 'observed-negotiated' are "
                    "distinct TLS findings and are NOT established "
                    "here (§9)",
                    "no service was correlated with this "
                    "configuration and no business mapping is "
                    "assumed",
                ],
                risk=assess(security_significance="high",
                            evidence_class="observed",
                            exposure="configuration_only")))
        results.append(_wrap("OS-CRYPTO-006", "evaluated",
                             f"{len(enabled_rows)} weak protocol "
                             "configuration state(s) permit legacy "
                             "TLS", findings))
    else:
        results.append(_wrap(
            "OS-CRYPTO-006", "evaluated",
            "no weak protocol is ENABLED in the collected SCHANNEL "
            "configuration — 'not detected' is never 'absent'; the "
            "supported and observed-negotiated axes remain "
            "unestablished (§9)", []))

    # --- OS-CRYPTO-007: disk encryption not established ---------------
    storage_sources = ("storage_metadata", "manage_bde")
    if not any(src in collected for src in storage_sources) and \
            not storage:
        results.append(_not_evaluable(
            "OS-CRYPTO-007", *_BY_ID["OS-CRYPTO-007"],
            "disk-encryption metadata",
            "the storage metadata source is unavailable"))
    else:
        def _encryption_established(fact: Dict[str, Any]) -> bool:
            # LUKS container metadata, or a Windows BitLocker
            # conversion status of Fully Encrypted — either
            # ESTABLISHES an encryption layer from the metadata.
            if fact.get("fstype") in ("crypto_LUKS", "crypto_LUKS2"):
                return True
            meta = fact.get("metadata") or {}
            status = str(meta.get("conversion_status", "")).lower()
            return status == "fully encrypted"

        unestablished = [s for s in storage
                         if not _encryption_established(s)]
        findings = [_finding(
            rule_id="OS-CRYPTO-007",
            detection="Disk encryption not established",
            subject=subject,
            evidence_source="storage metadata (lsblk view)",
            observation_type="metadata_extraction",
            evidence_class="indicated",
            details={"device": s.get("device", ""),
                     "fstype": s.get("fstype", ""),
                     "condition": "no encryption layer is established "
                                  "from the available metadata for this "
                                  "device",
                     "risk": "data-at-rest protection gap for this "
                             "device",
                     "recommendation": "confirm the intended "
                         "data-at-rest policy for this host with the "
                         "system owner"},
            limitations=["'not established' is what the metadata "
                         "shows — it is not proof that no encryption "
                         "exists below this view (hardware encryption, "
                         "layers outside the lsblk view)",
                         "no recovery keys, key files or secrets were "
                         "collected (§7)"],
            risk=assess(security_significance="medium",
                        evidence_class="indicated"))
            for s in unestablished]
        results.append(_wrap(
            "OS-CRYPTO-007", "evaluated",
            f"{len(unestablished)} device(s) without an established "
            "encryption layer" if unestablished else
            "no devices without an established encryption layer in the "
            "collected metadata — 'not detected' is never 'absent'",
            findings))

    # --- OS-CRYPTO-008: certificate near expiration ------------------
    certs = inventory.get("certificates") or []
    if not certs:
        results.append(_not_evaluable(
            "OS-CRYPTO-008", *_BY_ID["OS-CRYPTO-008"],
            "certificate metadata",
            "no certificate metadata was collected; an unread "
            "certificate list is never 'all valid'"))
    else:
        findings = []
        dated = 0
        for cert in certs:
            not_after = _parse_cert_date(str(cert.get("not_after", "")))
            if not_after is None:
                continue
            dated += 1
            days_remaining = (not_after - today).days
            if days_remaining < 0:
                state = "expired"
            elif days_remaining <= 30:
                state = "near_expiration"
            else:
                continue
            findings.append(_finding(
                rule_id="OS-CRYPTO-008",
                detection="certificate near expiration",
                subject=subject,
                evidence_source="certificate metadata "
                                "(public certificate object)",
                observation_type="certificate_metadata",
                evidence_class="observed",
                details={
                    "subject": cert.get("subject", "unknown"),
                    "issuer": cert.get("issuer", "unknown"),
                    "not_after": cert.get("not_after", "unknown"),
                    "days_remaining": days_remaining,
                    "state": state,
                    "condition": f"certificate validity ends in "
                                 f"{days_remaining} day(s) "
                                 f"(state: {state})",
                    "risk": "service continuity and trust concern — "
                            "an expired or expiring certificate "
                            "disrupts authenticated communication",
                    "recommendation": "review certificate "
                        "replacement and renewal with the certificate "
                        "owner",
                },
                limitations=[
                    "public certificate metadata only — private key "
                    "protection and certificate usage are never "
                    "inferred from the certificate (§7/§2.2)",
                    "the certificate owner and the services using "
                    "this certificate require correlation — no "
                    "service mapping is assumed",
                ],
                risk=assess(
                    security_significance="high" if state == "expired"
                    else "medium",
                    evidence_class="observed",
                    exposure="observed")))
        if dated == 0:
            results.append(_not_evaluable(
                "OS-CRYPTO-008", *_BY_ID["OS-CRYPTO-008"],
                "certificate validity dates",
                f"{len(certs)} certificate(s) were collected but "
                "validity dates could not be parsed — expiration state "
                "is UNKNOWN, never 'not expired' (§2.1)"))
        elif findings:
            results.append(_wrap("OS-CRYPTO-008", "evaluated",
                f"{len(findings)} of {dated} dated certificate(s) are "
                "expired or within 30 days of expiration", findings))
        else:
            results.append(_wrap(
                "OS-CRYPTO-008", "evaluated",
                f"no certificate among {dated} dated certificate(s) "
                "is expired or within 30 days of expiration — 'not "
                "detected' is never 'absent'; undated certificates "
                "remain UNKNOWN (§2.1)", []))

    # --- OS-CRYPTO-009: TPM unavailable or misconfigured ---------------
    tpm = next((t for t in trust if t.get("subject") == "tpm"), None)
    if tpm is None and trust:
        subjects = sorted({str(t.get("subject")) for t in trust})
        results.append(_not_evaluable(
            "OS-CRYPTO-009", *_BY_ID["OS-CRYPTO-009"],
            "a TPM trust fact",
            "no TPM subject was collected on this platform; recorded "
            f"hardware trust subjects are {subjects} — distinct "
            "claims, never substitutes; the absence of a TPM fact is "
            "never 'no hardware trust' (§2.1)"))
    elif tpm is None:
        results.append(_not_evaluable(
            "OS-CRYPTO-009", *_BY_ID["OS-CRYPTO-009"],
            "hardware trust facts",
            "no hardware trust source was collected"))
    elif tpm.get("state") == "unavailable":
        results.append(_wrap("OS-CRYPTO-009", "evaluated",
            "TPM availability is NOT ESTABLISHED from the collected "
            "source", [_finding(
                rule_id="OS-CRYPTO-009",
                detection="TPM unavailable or misconfigured",
                subject=subject,
                evidence_source="device presence (/dev/tpm*)",
                observation_type="device_presence",
                evidence_class="unknown",
                details={"state": "unavailable",
                         "condition": "TPM availability could not be "
                                      "established from the collected "
                                      "device source",
                         "risk": "hardware trust concern — trust "
                                 "anchoring cannot be confirmed for "
                                 "this host",
                         "recommendation": "verify TPM presence and "
                             "provisioning through the platform's "
                             "hardware inventory process"},
                limitations=["no /dev/tpm* node observed is NOT proof "
                             "of absence of a TPM (§2.1)",
                             "device presence is metadata, never a "
                             "trust verdict (§12)"],
                risk=assess(security_significance="medium",
                            evidence_class="unknown"))]))
    else:
        results.append(_wrap(
            "OS-CRYPTO-009", "evaluated",
            "TPM device presence observed — presence is metadata, "
            "never a trust verdict (§12); misconfiguration is not "
            "assessed by device presence alone", []))

    # --- OS-CRYPTO-010: Secure Boot disabled -------------------------
    secure_boot = next((t for t in trust
                        if t.get("subject") == "secure_boot"), None)
    if secure_boot is None:
        other_subjects = sorted({str(t.get("subject")) for t in trust})
        detail = (f" — recorded hardware trust subjects are "
                  f"{other_subjects}; they are distinct claims and "
                  "never substitutes for Secure Boot state"
                  if other_subjects else "")
        results.append(_not_evaluable(
            "OS-CRYPTO-010", *_BY_ID["OS-CRYPTO-010"],
            "EFI Secure Boot state",
            "no Secure Boot state source was collected" + detail +
            "; an unread state is never reported as 'disabled'"))
    elif secure_boot.get("state") == "disabled":
        results.append(_wrap("OS-CRYPTO-010", "evaluated",
            "Secure Boot reported disabled by the firmware interface",
            [_finding(
                rule_id="OS-CRYPTO-010",
                detection="Secure Boot disabled",
                subject=subject,
                evidence_source="firmware interface "
                                "(Confirm-SecureBootUEFI)",
                observation_type="configuration_state",
                evidence_class="observed",
                details={"state": "disabled",
                         "condition": "Secure Boot is reported "
                                      "disabled by the firmware "
                                      "interface",
                         "risk": "boot integrity concern — the boot "
                                 "chain's measured-boot guarantee is "
                                 "not active on this host",
                         "recommendation": "confirm the expected boot "
                             "integrity policy for this host class "
                             "with the system owner"},
                limitations=["a firmware configuration state is not a "
                             "defect verdict (§1) — Secure Boot "
                             "disablement can be an intentional "
                             "configuration",
                             "this says nothing about the integrity "
                             "of any specific boot"],
                risk=assess(security_significance="high",
                            evidence_class="observed",
                            exposure="configuration_only"))]))
    elif secure_boot.get("state") == "enabled":
        results.append(_wrap(
            "OS-CRYPTO-010", "evaluated",
            "Secure Boot reported enabled by the firmware interface — "
            "a configuration state, never a trust verdict (§12)", []))
    else:
        results.append(_wrap(
            "OS-CRYPTO-010", "evaluated",
            "Secure Boot availability is NOT ESTABLISHED from the "
            "collected source — recorded as unavailable, never as "
            "'disabled' (§2.1)", []))

    # --- OS-CRYPTO-011: provider version vulnerable ------------------
    results.append(_not_evaluable(
        "OS-CRYPTO-011", *_BY_ID["OS-CRYPTO-011"],
        "vulnerability correlation data",
        "no vulnerability feed correlation is performed in this "
        "phase"))

    # --- OS-CRYPTO-012: configuration changed ------------------------
    if previous is None:
        results.append(_not_evaluable(
            "OS-CRYPTO-012", *_BY_ID["OS-CRYPTO-012"],
            "a previous collection",
            "there is no predecessor to compare — drift needs two "
            "points in time"))
    else:
        prev_caps = {str(e.get("algorithm")) + "|" + str(e.get("driver"))
                     for e in previous.get("crypto_api", []) or []}
        now_caps = {str(e.get("algorithm")) + "|" + str(e.get("driver"))
                    for e in crypto}
        added = sorted(now_caps - prev_caps)
        removed = sorted(prev_caps - now_caps)
        findings = []
        for change, rows in (("added", added), ("removed", removed)):
            for row in rows:
                findings.append(_finding(
                    rule_id="OS-CRYPTO-012",
                    detection="Cryptographic configuration changed",
                    subject=subject,
                    evidence_source="collection comparison",
                    observation_type="configuration_state",
                    evidence_class="strongly_supported",
                    details={"change": change,
                             "entry": row,
                             "condition": "registered crypto "
                                          "configuration differs from "
                                          "the previous collection",
                             "risk": "drift investigation"},
                    limitations=["the comparison proves the CHANGE, "
                                 "not its cause — never auto-blamed on "
                                 "any component"],
                    risk=assess(security_significance="medium",
                                evidence_class="strongly_supported")))
        results.append(_wrap(
            "OS-CRYPTO-012", "evaluated",
            f"{len(added)} added, {len(removed)} removed registrations "
            "vs the previous collection" if findings else
            "no registration drift vs the previous collection — "
            "'not detected' is never 'absent'", findings))

    # --- OS-CRYPTO-013: unexpected module signer ---------------------
    module_sig = flags.get("CONFIG_MODULE_SIG")
    sig_evidence = []
    if "UNSIGNED_MODULE" in taints:
        sig_evidence.append("UNSIGNED_MODULE taint recorded")
    if module_sig in ("not_set",):
        sig_evidence.append("CONFIG_MODULE_SIG explicitly not set")
    if sig_evidence:
        results.append(_wrap("OS-CRYPTO-013", "evaluated",
            "; ".join(sig_evidence), [_finding(
                rule_id="OS-CRYPTO-013",
                detection="Unexpected kernel module signer",
                subject=subject,
                evidence_source="kernel taints + kernel configuration",
                observation_type="configuration_state",
                evidence_class="indicated",
                details={"condition": " | ".join(sig_evidence),
                         "risk": "integrity investigation — module "
                                 "signature enforcement cannot be "
                                 "confirmed for this host",
                         "recommendation": "reconcile the module "
                             "signing policy with the bank's expected "
                             "baseline"},
                limitations=["neither source names the signer of any "
                             "specific module"],
                risk=assess(security_significance="high",
                            evidence_class="indicated",
                            exposure="configuration_only"))]))
    else:
        results.append(_wrap(
            "OS-CRYPTO-013", "evaluated",
            "no unsigned-module evidence in the collected sources — "
            "'not detected' is never 'absent' (§2.1)", []))

    # --- OS-CRYPTO-014: randomness configuration ---------------------
    if platform != "linux":
        results.append(_not_evaluable(
            "OS-CRYPTO-014", *_BY_ID["OS-CRYPTO-014"],
            "the Linux kernel entropy-trust configuration "
            "(CONFIG_RANDOM_TRUST_CPU)",
            "this source is Linux-specific and this is a "
            f"{platform} collection — not_evaluable, never clean"))
        trust_cpu = None
    else:
        trust_cpu = flags.get("CONFIG_RANDOM_TRUST_CPU")
    if platform != "linux":
        pass  # already reported not_evaluable above
    elif trust_cpu == "not_set":
        results.append(_wrap("OS-CRYPTO-014", "evaluated",
            "CONFIG_RANDOM_TRUST_CPU explicitly not set", [_finding(
                rule_id="OS-CRYPTO-014",
                detection="Randomness configuration concern",
                subject=subject,
                evidence_source="kernel configuration",
                observation_type="configuration_state",
                evidence_class="observed",
                details={"flag": "CONFIG_RANDOM_TRUST_CPU",
                         "value": "not_set",
                         "condition": "the kernel does not trust the "
                                      "CPU RNG by configuration",
                         "risk": "cryptographic assurance concern — "
                                 "entropy source trust is a "
                                 "configuration choice that should be "
                                 "reviewed",
                         "recommendation": "review this host's entropy "
                             "sources and their trust configuration "
                             "against the bank's policy"},
                limitations=["randomness is NEVER declared secure or "
                             "insecure from one entropy counter or one "
                             "configuration flag (§5)",
                             "this is a configuration state, not an "
                             "entropy measurement"],
                risk=assess(security_significance="medium",
                            evidence_class="observed",
                            exposure="configuration_only"))]))
    elif trust_cpu is None and "config_flags" not in collected:
        results.append(_not_evaluable(
            "OS-CRYPTO-014", *_BY_ID["OS-CRYPTO-014"],
            "kernel configuration",
            "the entropy-trust configuration state is unavailable"))
    else:
        results.append(_wrap(
            "OS-CRYPTO-014", "evaluated",
            f"CONFIG_RANDOM_TRUST_CPU recorded as {trust_cpu!r} — a "
            "single source never proves randomness health (§5)", []))

    # --- OS-CRYPTO-015: PQC migration dependency ---------------------
    pqc_rows = [e for e in crypto
                if any(n in str(e.get("algorithm", "")).lower()
                       or n in str(e.get("driver", "")).lower()
                       for n in _PQC_NAMES)]
    if pqc_rows:
        results.append(_wrap("OS-CRYPTO-015", "evaluated",
            f"{len(pqc_rows)} PQC-family registrations identified",
            [_finding(
                rule_id="OS-CRYPTO-015",
                detection="PQC migration dependency identified",
                subject=subject,
                evidence_source="Linux Kernel Crypto API (/proc/crypto)",
                observation_type="registered_capability",
                evidence_class="indicated",
                details={"algorithm": e.get("algorithm", ""),
                         "implementation": e.get("driver", ""),
                         "condition": "PQC-family algorithm registered "
                                      "on this host",
                         "risk": "migration planning requirement — "
                                 "identify dependent systems and "
                                 "timelines",
                         "recommendation": "map application "
                             "dependencies before planning; presence "
                             "is not usage"},
                limitations=["PQC presence is NEVER PQC usage and "
                             "never PQC readiness",
                             "a registered implementation is not proof "
                             "any application used it (§2.2)"],
                risk=assess(security_significance="low",
                            evidence_class="indicated")) for e in pqc_rows]))
    elif not crypto:
        results.append(_not_evaluable(
            "OS-CRYPTO-015", *_BY_ID["OS-CRYPTO-015"],
            "/proc/crypto", "the algorithm inventory is unavailable"))
    else:
        results.append(_wrap(
            "OS-CRYPTO-015", "evaluated",
            "no PQC-family registrations in the collected inventory — "
            "'not detected' is never 'absent'; migration planning does "
            "not depend on kernel registration alone (§9)",
            [_finding(rule_id="OS-CRYPTO-015",
                      detection="PQC migration dependency identified",
                      subject=subject,
                      evidence_source="Linux Kernel Crypto API "
                                      "(/proc/crypto)",
                      observation_type="registered_capability",
                      evidence_class="not_detected",
                      details={"condition": "not detected among "
                                            "registered implementations"},
                      limitations=["not_detected is never proof of "
                                   "absence (§2.1)",
                                   "PQC migration dependency is NOT "
                                   "ruled out by kernel inventory — "
                                   "user-space libraries carry most "
                                   "PQC implementations"],
                      risk=assess(security_significance="low",
                                  evidence_class="not_detected"))]))

    # --- OS-CRYPTO-016: kernel crypto capability unavailable ----------
    if platform != "linux":
        results.append(_not_evaluable(
            "OS-CRYPTO-016", *_BY_ID["OS-CRYPTO-016"],
            "the Linux kernel configuration (CONFIG_CRYPTO_*)",
            "this source is Linux-specific and this is a "
            f"{platform} collection — not_evaluable, never clean"))
    explicitly_off = [k for k, v in flags.items()
                      if v == "not_set" and k.startswith("CONFIG_CRYPTO")] \
        if platform == "linux" else []
    if platform != "linux":
        pass  # already reported not_evaluable above
    elif explicitly_off:
        results.append(_wrap("OS-CRYPTO-016", "evaluated",
            f"{len(explicitly_off)} CONFIG_CRYPTO_* flags explicitly "
            "not set", [_finding(
                rule_id="OS-CRYPTO-016",
                detection="Kernel crypto capability unavailable",
                subject=subject,
                evidence_source="kernel configuration",
                observation_type="configuration_state",
                evidence_class="observed",
                details={"flags": explicitly_off,
                         "condition": "capability explicitly disabled "
                                      "in the kernel configuration",
                         "risk": "compatibility or dependency concern "
                                 "for software relying on this "
                                 "capability",
                         "recommendation": "confirm which software on "
                             "this host requires the capability"},
                limitations=["'not set' is an explicit configuration "
                             "state — different from a flag missing in "
                             "an unavailable source (§2.1)",
                             "a capability absent from /proc/modules is "
                             "never 'unavailable' — it may be built in"],
                risk=assess(security_significance="low",
                            evidence_class="observed",
                            exposure="configuration_only"))
             for _ in [0]]))
    elif "config_flags" not in collected:
        results.append(_not_evaluable(
            "OS-CRYPTO-016", *_BY_ID["OS-CRYPTO-016"],
            "kernel configuration",
            "the configuration source is unavailable; unavailable is "
            "never 'disabled' (§2.1)"))
    else:
        results.append(_wrap(
            "OS-CRYPTO-016", "evaluated",
            "no CONFIG_CRYPTO_* flag is explicitly not set in the "
            "collected configuration", []))

    # --- OS-CRYPTO-017: runtime collector losing events ---------------
    if runtime_session is None:
        results.append(_not_evaluable(
            "OS-CRYPTO-017", *_BY_ID["OS-CRYPTO-017"],
            "a Tier-2 runtime event stream",
            "no runtime session was collected — Tier-2 collection is "
            "separately approved (§3) and this evaluation input is "
            "absent; absence of a runtime session is never reported as "
            "'healthy' and never as 'no event loss'"))
    else:
        loss = (runtime_session.loss_report()
                if hasattr(runtime_session, "loss_report")
                else dict(runtime_session))
        lost = int(loss.get("events_lost") or 0)
        accepted = int(loss.get("events_accepted") or 0)
        if lost > 0:
            results.append(_wrap("OS-CRYPTO-017", "evaluated",
                f"{lost} runtime event(s) lost against {accepted} "
                "accepted — observability gap", [_finding(
                rule_id="OS-CRYPTO-017",
                detection="Runtime collector losing events",
                subject=subject,
                evidence_source=str(loss.get("evidence_source")
                                    or "Tier-2 runtime session "
                                        "accounting"),
                observation_type="runtime_session_accounting",
                evidence_class="observed",
                details={
                    "events_lost": lost,
                    "events_accepted": accepted,
                    "loss_ratio": loss.get("loss_ratio"),
                    "condition": f"the runtime collector lost "
                                 f"{lost} event(s) during the "
                                 "collected session",
                    "risk": "observability gap — lost runtime events "
                            "degrade usage coverage; capabilities "
                            "without runtime events remain 'usage "
                            "not confirmed', NEVER 'unused'",
                    "recommendation": "review collector attach "
                        "points, buffer sizing and drop accounting "
                        "on the collection host",
                },
                limitations=[
                    "lost-event counts come from the collector's own "
                    "accounting — recorded, never guessed",
                    "event loss is an observability gap, not evidence "
                    "about the cryptography itself",
                ],
                risk=assess(security_significance="medium",
                            evidence_class="observed",
                            exposure="observed"))]))
        elif accepted > 0:
            results.append(_wrap(
                "OS-CRYPTO-017", "evaluated",
                f"no event loss observed in this runtime session "
                f"({accepted} events accepted) — 'not detected' is "
                "never 'absent'; coverage is per-session, not "
                "continuous (§3)", []))
        else:
            results.append(_wrap(
                "OS-CRYPTO-017", "evaluated",
                "the collected runtime session accepted zero events "
                "with zero loss — coverage for this session is "
                "UNKNOWN; zero events is never 'no cryptographic "
                "activity' (§2.1)", []))

    # --- OS-CRYPTO-018: HSM/TPM provider state changed ----------------
    if previous is None:
        results.append(_not_evaluable(
            "OS-CRYPTO-018", *_BY_ID["OS-CRYPTO-018"],
            "a previous collection",
            "hardware trust state change needs two points in time"))
    else:
        prev_state = {t.get("subject"): t.get("state")
                      for t in previous.get("hardware_trust", []) or []}
        findings = []
        for fact in trust:
            subject_name = fact.get("subject")
            before = prev_state.get(subject_name)
            if before is not None and before != fact.get("state"):
                findings.append(_finding(
                    rule_id="OS-CRYPTO-018",
                    detection="HSM or TPM provider state changed",
                    subject=subject,
                    evidence_source="hardware trust fact comparison",
                    observation_type="device_presence",
                    evidence_class="strongly_supported",
                    details={"provider": subject_name,
                             "previous_state": before,
                             "current_state": fact.get("state"),
                             "condition": "hardware trust provider "
                                          "state differs from the "
                                          "previous collection",
                             "risk": "hardware trust investigation"},
                    limitations=["the comparison proves the CHANGE of "
                                 "recorded state, not its cause"],
                    risk=assess(security_significance="high",
                                evidence_class="strongly_supported")))
        results.append(_wrap(
            "OS-CRYPTO-018", "evaluated",
            f"{len(findings)} trust-state changes vs the previous "
            "collection" if findings else
            "no recorded trust-state change vs the previous "
            "collection — 'not detected' is never 'absent'", findings))

    return RuleReport(results=results)
