"""A bank-shaped estate with a planted answer key, and two pipelines scored against it.

The point of a synthetic corpus is that the right answer is *known*, so precision and recall are
measurable rather than asserted. The point of this one in particular is that it is full of the
cases where a scanner is tempted to guess:

* a library that is installed and never used;
* a cipher suite that is configured and never negotiated;
* a TLS version the endpoint supports and does not select;
* an SBOM that describes a container the running process has moved past;
* an HSM nobody can reach, and an HSM whose collection failed;
* a vendor document that says an application uses AES-256-GCM, where no collector has ever seen
  the application do anything;
* two applications with the same display name.

Each of those has a *correct* answer, and for most of them the correct answer is "we could not
prove it". The truth therefore contains unobservable items and absent items, and both count: a
scanner that answers them anyway is wrong, and a scanner that declines them is right.

:func:`rigorous_predictions` is the platform's rule — observation, then fact, capability kept
apart from usage, absence in four states, disagreement preserved. :func:`naive_predictions` is the
shortcut the review warned about, ``collector → CBOM``: every algorithm a library can do is
reported as one the application does. Both are scored against the same key, so the cost of the
shortcut is a number.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from cbom import accuracy, facts

SCHEMA = "cryptoscan.accuracy-corpus/1"

#: What the corpus deliberately contains. Asserted by the tests: if one of these disappears, the
#: measurement stops distinguishing careful scanning from confident guessing.
HARD_CASES: tuple[str, ...] = (
    "installed-but-unused",
    "configured-but-unused",
    "supported-not-negotiated",
    "runtime-only",
    "network-only",
    "static-only",
    "vendor-only",
    "stale-sbom",
    "container-library-mismatch",
    "custom-crypto",
    "duplicate-app-name",
    "tls-re-encryption",
    "expired-certificate",
    "unreachable-hsm",
    "collection-failure",
    "permission-denied",
    "partial-collection",
    "unmapped-owner",
    "inferred-only",
    "parser-disagreement",
)

FABRICATED_EVIDENCE = "EVID-v1-fabricated"


@dataclass(frozen=True, slots=True)
class Unit:
    """One measurable claim: what is true, what was observed, and whether anyone could look."""

    subject: str
    property: str
    dimension: str
    attribute: str
    truth_value: Any
    observations: tuple[facts.Observation, ...] = ()
    observable: bool = True
    scope: Mapping[str, Any] | None = None
    note: str = ""

    @property
    def expected_evidence(self) -> str | None:
        return self.observations[0].evidence_id if self.observations else None


@dataclass
class Corpus:
    estate: dict[str, int] = field(default_factory=dict)
    units: list[Unit] = field(default_factory=list)
    hard_cases: tuple[str, ...] = HARD_CASES

    # -- construction ------------------------------------------------------ #

    def add(self, *, subject: str, property_name: str, dimension: str, attribute: str,
            truth_value: Any, observations: tuple[facts.Observation, ...] = (),
            observable: bool = True, scope: Mapping[str, Any] | None = None,
            note: str = "") -> Unit:
        unit = Unit(subject=subject, property=property_name, dimension=dimension,
                    attribute=attribute, truth_value=truth_value, observations=observations,
                    observable=observable, scope=scope, note=note)
        self.units.append(unit)
        return unit

    # -- what the pipelines are scored against ----------------------------- #

    def truth(self) -> list[accuracy.Truth]:
        items = [
            accuracy.Truth(dimension=unit.dimension, subject=unit.subject,
                           attribute=unit.attribute, value=unit.truth_value,
                           observable=unit.observable)
            for unit in self.units
        ]
        keys = [(item.dimension, item.subject, item.attribute) for item in items]
        duplicated = sorted({key for key in keys if keys.count(key) > 1})
        if duplicated:
            raise AssertionError(f"the answer key holds the same item twice: {duplicated[:5]}")
        items += [
            accuracy.Truth(dimension="evidence_attribution", subject=unit.subject,
                           attribute=f"evidence:{unit.property}",
                           value=tuple(sorted({item.evidence_id for item in unit.observations})),
                           observable=True)
            # Only where the answer key holds a claim. A declined item attributes nothing, and
            # scoring attribution on it would push a scanner to cite evidence for a claim it just
            # refused to make — the opposite of the behaviour being measured.
            for unit in self.units
            if unit.observable and unit.observations and unit.truth_value is not None
        ]
        return items

    def observations(self) -> list[facts.Observation]:
        return [observation for unit in self.units for observation in unit.observations]

    def counts(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "truth_items": len(self.truth()),
            "observations": len(self.observations()),
            "units": len(self.units),
            **self.estate,
            "hard_cases": list(self.hard_cases),
        }


# --------------------------------------------------------------------------- #
# the estate
# --------------------------------------------------------------------------- #

_APPS = 40
_HOSTS = 40
_HSMS = 5
_DATABASES = 20
_LOAD_BALANCERS = 15

#: Algorithms a modern crypto library supports. Listing them as *capabilities* is correct, and
#: turning them into usage claims is the shortcut.
LIBRARY_ALGORITHMS = ("AES-256-GCM", "AES-128-GCM", "RSA-2048", "ECDSA-P256", "SHA-256",
                      "ChaCha20-Poly1305")


def _observed(subject: str, property_name: str, value: Any, klass: str, kind: str, source: str,
              evidence: str, scope: str = "") -> facts.Observation:
    return facts.Observation(subject=subject, property=property_name, value=value, klass=klass,
                             kind=kind, source=source, evidence_id=evidence, scope=scope)


def build() -> Corpus:
    corpus = Corpus(estate={"applications": _APPS, "hosts": _HOSTS, "hsms": _HSMS,
                            "databases": _DATABASES, "load_balancers": _LOAD_BALANCERS})
    _assets(corpus)
    _algorithms(corpus)
    _key_sizes_and_certificates(corpus)
    _network(corpus)
    _dependencies(corpus)
    _ownership(corpus)
    _inferred_and_disagreements(corpus)
    return corpus


def _assets(corpus: Corpus) -> None:
    # applications nobody could inspect: the agent was not installed, so "not found" is not a
    # statement about the application
    unobserved = {f"APP-{index:04d}" for index in range(37, _APPS + 1)}
    for index in range(1, _APPS + 1):
        subject = f"APP-{index:04d}"
        if subject in unobserved:
            corpus.add(subject=subject, property_name="present", dimension="asset",
                       attribute="kind", truth_value="application", observable=False,
                       note="no agent: nothing may be concluded about this application")
            continue
        corpus.add(
            subject=subject, property_name="present", dimension="asset", attribute="kind",
            truth_value="application",
            observations=(_observed(subject, "present", "application", facts.OBSERVED,
                                    facts.INVENTORY, "app-inventory",
                                    f"EVID-app-{index:04d}"),))

    # hosts, two of which no collector reaches
    for index in range(1, _HOSTS + 1):
        subject = f"HOST-{index:04d}"
        reachable = index <= _HOSTS - 2
        corpus.add(
            subject=subject, property_name="present", dimension="asset", attribute="kind",
            truth_value="host", observable=reachable,
            observations=(_observed(subject, "present", "host", facts.OBSERVED, facts.INVENTORY,
                                    "network-sweep", f"EVID-host-{index:04d}"),) if reachable
            else (),
            note="" if reachable else "outside every collection scope")

    # HSMs: one unreachable, one whose management API failed
    for index in range(1, _HSMS + 1):
        subject = f"HSM-{index:02d}"
        if index == _HSMS:
            corpus.add(subject=subject, property_name="present", dimension="asset",
                       attribute="kind", truth_value="hsm", observable=False,
                       scope={"scope": "pkcs11", "searched": False},
                       note="no route to the management plane")
            continue
        if index == _HSMS - 1:
            corpus.add(
                subject=subject, property_name="present", dimension="asset", attribute="kind",
                truth_value="hsm",
                observations=(_observed(subject, "present", "hsm", facts.OBSERVED,
                                        facts.INVENTORY, "hsm-inventory",
                                        f"EVID-hsm-{index:02d}"),),
                scope={"scope": "pkcs11", "searched": True, "failure": "management API timeout"},
                note="inventory sees it; the crypto read failed")
            continue
        corpus.add(
            subject=subject, property_name="present", dimension="asset", attribute="kind",
            truth_value="hsm",
            observations=(_observed(subject, "present", "hsm", facts.OBSERVED, facts.INVENTORY,
                                    "hsm-inventory", f"EVID-hsm-{index:02d}"),))

    # databases, two uninspectable
    for index in range(1, _DATABASES + 1):
        subject = f"DB-{index:03d}"
        inspectable = index <= _DATABASES - 2
        corpus.add(
            subject=subject, property_name="present", dimension="asset", attribute="kind",
            truth_value="database", observable=inspectable,
            observations=(_observed(subject, "present", "database", facts.OBSERVED,
                                    facts.INVENTORY, "db-registry",
                                    f"EVID-db-{index:03d}"),) if inspectable else ())

    for index in range(1, _LOAD_BALANCERS + 1):
        subject = f"LB-{index:02d}"
        corpus.add(
            subject=subject, property_name="present", dimension="asset", attribute="kind",
            truth_value="load_balancer",
            observations=(_observed(subject, "present", "load_balancer", facts.OBSERVED,
                                    facts.INVENTORY, "lb-registry", f"EVID-lb-{index:02d}"),))


#: Applications 1..35 are cases a scanner can prove; 36..40 are the cases where the only honest
#: answer is a refusal. The ratio is deliberate: a corpus where most applications are unprovable
#: would let any pipeline look careful by declining, and the answer-rate gate would be measuring
#: the corpus instead of the rule.
PRODUCTIVE_CASES = ("runtime", "network", "static", "custom", "supported")
UNPROVABLE_CASES = ("installed", "installed", "configured", "vendor", "vendor")


def _algorithms(corpus: Corpus) -> None:
    cases = _algorithm_cases()
    for index in range(1, _APPS + 1):
        subject = f"APP-{index:04d}"
        if any(unit.subject == subject and unit.property == "algorithm" for unit in corpus.units):
            continue
        if index <= _APPS - len(UNPROVABLE_CASES):
            name = PRODUCTIVE_CASES[(index - 1) % len(PRODUCTIVE_CASES)]
        else:
            name = UNPROVABLE_CASES[(index - (_APPS - len(UNPROVABLE_CASES)) - 1)]
        unit = cases[name](subject)
        if unit is not None:
            corpus.add(**unit)


def _algorithm_cases():
    """The review's list, one function per case, keyed by name so the mix above can weight them."""

    def installed_but_unused(subject: str) -> dict[str, Any]:
        observations = tuple(
            _observed(subject, "algorithm", algorithm, facts.CONFIGURED, facts.CAPABILITY,
                      "dpkg", f"EVID-cap-{subject}-{index}")
            for index, algorithm in enumerate(LIBRARY_ALGORITHMS[:3]))
        return {"subject": subject, "property_name": "algorithm", "dimension": "algorithm",
                "attribute": "usage", "truth_value": None, "observations": observations,
                "note": "the library can do this; nothing says the application does"}

    def configured_but_unused(subject: str) -> dict[str, Any]:
        return {"subject": subject, "property_name": "algorithm", "dimension": "algorithm",
                "attribute": "usage", "truth_value": None,
                "observations": (_observed(subject, "algorithm", "DES-EDE3-CBC", facts.CONFIGURED,
                                           facts.CAPABILITY, "app-config",
                                           f"EVID-cfg-{subject}"),),
                "note": "an algorithm is configured and never negotiated"}

    def supported_not_negotiated(subject: str) -> dict[str, Any]:
        return {"subject": subject, "property_name": "algorithm", "dimension": "algorithm",
                "attribute": "usage", "truth_value": "TLS-1.2",
                "observations": (
                    _observed(subject, "algorithm", "TLS-1.3", facts.CONFIGURED, facts.CAPABILITY,
                              "app-config", f"EVID-sup-{subject}"),
                    _observed(subject, "algorithm", "TLS-1.2", facts.NETWORK_OBSERVED,
                              facts.NETWORK_NEGOTIATED, "pcap", f"EVID-neg-{subject}")),
                "note": "supports 1.3, negotiates 1.2: the wire wins and the capability stays a "
                        "capability"}

    def runtime_only(subject: str) -> dict[str, Any]:
        return {"subject": subject, "property_name": "algorithm", "dimension": "algorithm",
                "attribute": "usage", "truth_value": "AES-256-GCM",
                "observations": (_observed(subject, "algorithm", "AES-256-GCM",
                                           facts.RUNTIME_OBSERVED, facts.RUNTIME_USAGE,
                                           "crypto-probe", f"EVID-run-{subject}"),),
                "note": "only a running process knows"}

    def network_only(subject: str) -> dict[str, Any]:
        return {"subject": subject, "property_name": "algorithm", "dimension": "algorithm",
                "attribute": "usage", "truth_value": "ECDHE-P256",
                "observations": (_observed(subject, "algorithm", "ECDHE-P256",
                                           facts.NETWORK_OBSERVED, facts.NETWORK_NEGOTIATED,
                                           "pcap", f"EVID-net-{subject}"),),
                "note": "the library list never mentions it; the handshake does"}

    def static_only(subject: str) -> dict[str, Any]:
        return {"subject": subject, "property_name": "algorithm", "dimension": "algorithm",
                "attribute": "usage", "truth_value": "RSA-2048",
                "observations": (_observed(subject, "algorithm", "RSA-2048",
                                           facts.STATIC_OBSERVED, facts.STATIC_REFERENCE,
                                           "source-parse", f"EVID-src-{subject}"),),
                "note": "a code path refers to it"}

    def custom_crypto(subject: str) -> dict[str, Any]:
        return {"subject": subject, "property_name": "algorithm", "dimension": "algorithm",
                "attribute": "usage", "truth_value": "CUSTOM-ROT13-XOR",
                "observations": (_observed(subject, "algorithm", "CUSTOM-ROT13-XOR",
                                           facts.RUNTIME_OBSERVED, facts.RUNTIME_USAGE,
                                           "crypto-probe", f"EVID-cus-{subject}"),),
                "note": "not in any library's list, and that is the finding"}

    def vendor_only(subject: str) -> dict[str, Any]:
        return {"subject": subject, "property_name": "algorithm", "dimension": "algorithm",
                "attribute": "usage", "truth_value": None,
                "observations": (_observed(subject, "algorithm", "AES-256-GCM",
                                           facts.VENDOR_DECLARED, facts.CAPABILITY,
                                           "vendor-questionnaire",
                                           f"EVID-ven-{subject}"),),
                "note": "a questionnaire is not an observation"}

    return {"installed": installed_but_unused, "configured": configured_but_unused,
            "supported": supported_not_negotiated, "runtime": runtime_only,
            "network": network_only, "static": static_only, "custom": custom_crypto,
            "vendor": vendor_only}


def _key_sizes_and_certificates(corpus: Corpus) -> None:
    for index in range(1, 13):
        subject = f"CERT-{index:03d}"
        key_size = 2048 if index % 3 else 4096
        corpus.add(
            subject=subject, property_name="key_size", dimension="key_size", attribute="value",
            truth_value=key_size,
            observations=(_observed(subject, "key_size", key_size, facts.STATIC_OBSERVED,
                                    facts.STATIC_REFERENCE, "x509-parser",
                                    f"EVID-cert-{index:03d}"),))

        expired = index % 5 == 0
        state = "EXPIRED" if expired else "VALID"
        corpus.add(
            subject=subject, property_name="certificate", dimension="certificate",
            attribute="state", truth_value=state,
            observations=(_observed(subject, "certificate", state, facts.STATIC_OBSERVED,
                                    facts.STATIC_REFERENCE, "x509-parser",
                                    f"EVID-certstate-{index:03d}"),),
            note="expired-certificate" if expired else "")

    # a certificate whose two parsers disagree about the key size
    corpus.add(
        subject="CERT-900", property_name="key_size", dimension="key_size", attribute="value",
        truth_value=accuracy.TRUTH_CONFLICT,
        observations=(
            _observed("CERT-900", "key_size", 2048, facts.STATIC_OBSERVED,
                      facts.STATIC_REFERENCE, "x509-parser", "EVID-cert900-x509"),
            _observed("CERT-900", "key_size", 4096, facts.STATIC_OBSERVED,
                      facts.STATIC_REFERENCE, "pkcs11-parser", "EVID-cert900-pkcs11")),
        note="parser-disagreement: preserved, never averaged")


def _network(corpus: Corpus) -> None:
    for index in range(1, 16):
        subject = f"LB-{index:02d}"
        version = "TLS-1.3" if index % 2 else "TLS-1.2"
        corpus.add(
            subject=subject, property_name="negotiated_tls", dimension="network",
            attribute="version", truth_value=version,
            observations=(_observed(subject, "negotiated_tls", version, facts.NETWORK_OBSERVED,
                                    facts.NETWORK_NEGOTIATED, "pcap",
                                    f"EVID-tls-{index:02d}"),))

    # WAF → LB → GATEWAY: TLS 1.3 on one hop, 1.2 on the next, 1.3 again. Termination is not
    # re-encryption, and a single "the endpoint uses TLS 1.3" is a claim about one hop.
    for hop, version in (("waf", "TLS-1.3"), ("lb", "TLS-1.2"), ("gateway", "TLS-1.3")):
        subject = f"HOP-{hop.upper()}"
        corpus.add(
            subject=subject, property_name="negotiated_tls", dimension="network",
            attribute="version", truth_value=version,
            observations=(_observed(subject, "negotiated_tls", version, facts.NETWORK_OBSERVED,
                                    facts.NETWORK_NEGOTIATED, "pcap", f"EVID-hop-{hop}"),),
            note="tls-re-encryption: per hop, never one verdict for the path")


def _dependencies(corpus: Corpus) -> None:
    for index in range(1, 13):
        subject = f"APP-{index:04d}"
        corpus.add(
            subject=subject, property_name="dependency_version", dimension="dependency",
            attribute="openssl_version", truth_value="3.0.13",
            observations=(_observed(subject, "dependency_version", "3.0.13", facts.IMPORTED,
                                    facts.INVENTORY, "sbom", f"EVID-sbom-{index:04d}"),
                          _observed(subject, "dependency_version", "3.0.13",
                                    facts.RUNTIME_OBSERVED, facts.RUNTIME_USAGE, "process-map",
                                    f"EVID-proc-{index:04d}")),)

    # a stale SBOM and a container whose library the process has moved past
    for offset, (sbom, running, note) in enumerate((("3.0.11", "3.0.13", "stale-sbom"),
                                                    ("1.1.1w", "3.0.13",
                                                     "container-library-mismatch"))):
        subject = f"APP-{20 + offset:04d}"
        corpus.add(
            subject=subject, property_name="dependency_version", dimension="dependency",
            attribute="openssl_version", truth_value=accuracy.TRUTH_CONFLICT,
            observations=(
                _observed(subject, "dependency_version", sbom, facts.IMPORTED, facts.INVENTORY,
                          "sbom", f"EVID-sbom-{subject}"),
                _observed(subject, "dependency_version", running, facts.RUNTIME_OBSERVED,
                          facts.RUNTIME_USAGE, "process-map", f"EVID-proc-{subject}")),
            note=note)


def _ownership(corpus: Corpus) -> None:
    owners = ("payments-platform", "core-banking", "digital-channels", "risk", "operations")
    for index in range(1, 21):
        subject = f"APP-{index:04d}"
        owner = owners[index % len(owners)]
        corpus.add(
            subject=subject, property_name="owner", dimension="system_owner", attribute="owner",
            truth_value=owner,
            observations=(_observed(subject, "owner", owner, facts.IMPORTED, facts.INVENTORY,
                                    "cmdb", f"EVID-owner-{index:04d}"),))

    # an application nobody owns in the CMDB, and one with two owners who disagree
    corpus.add(subject="APP-9500", property_name="owner", dimension="system_owner",
               attribute="owner", truth_value=None,
               observations=(_observed("APP-9500", "present", "application", facts.OBSERVED,
                                       facts.INVENTORY, "app-inventory",
                                       "EVID-owner9500-app"),),
               note="unmapped-owner: the absence is the finding")
    corpus.add(
        subject="APP-9501", property_name="owner", dimension="system_owner", attribute="owner",
        truth_value=accuracy.TRUTH_CONFLICT,
        observations=(
            _observed("APP-9501", "owner", "payments-platform", facts.IMPORTED, facts.INVENTORY,
                      "cmdb", "EVID-owner9501-cmdb"),
            _observed("APP-9501", "owner", "core-banking", facts.STATIC_OBSERVED,
                      facts.INVENTORY, "service-catalogue", "EVID-owner9501-cat")),
        note="two registers disagree; the platform does not pick one")

    # two applications with the same display name: identity is the canonical id, not the name
    for suffix in ("a", "b"):
        subject = f"APP-9600-{suffix}"
        corpus.add(
            subject=subject, property_name="present", dimension="asset", attribute="kind",
            truth_value="application",
            observations=(_observed(subject, "present", "application", facts.OBSERVED,
                                    facts.INVENTORY, "app-inventory",
                                    f"EVID-dup-{suffix}"),),
            note="duplicate-app-name: 'Payments API' twice, two different systems")


def _inferred_and_disagreements(corpus: Corpus) -> None:
    """Items where the honest answer is "we could not prove this", so the metrics are not all 100%."""
    for index in range(1, 4):
        subject = f"APP-9{700 + index}"
        corpus.add(
            subject=subject, property_name="algorithm", dimension="algorithm",
            attribute="usage", truth_value="AES-256-GCM", observable=True,
            observations=(_observed(subject, "algorithm", "AES-256-GCM", facts.INFERRED,
                                    facts.CAPABILITY, "heuristic", f"EVID-inf-{index}"),),
            note="inferred-only: a lead, recorded and given no vote")

    # a control-plane permission the collector did not have, and a partial read
    corpus.add(subject="HSM-04", property_name="algorithm", dimension="algorithm",
               attribute="usage", truth_value="AES-256-GCM", observable=False,
               scope={"scope": "pkcs11", "searched": False, "failure": "permission denied"},
               note="permission-denied")
    corpus.add(subject="DB-019", property_name="algorithm", dimension="algorithm",
               attribute="usage", truth_value="AES-256-GCM", observable=False,
               scope={"scope": "tde-catalog", "searched": False,
                      "failure": "only half the tables were readable"},
               note="partial-collection")


# --------------------------------------------------------------------------- #
# the platform's rule
# --------------------------------------------------------------------------- #

def _to_prediction(unit: Unit, fact: facts.Fact) -> accuracy.Prediction:
    """The rule, in one place: capability is not usage, and nothing is invented."""
    if fact.state == facts.CONFLICT:
        state, value = accuracy.CONFLICT, None
    elif fact.state in {facts.UNKNOWN_STATE, facts.NOT_OBSERVABLE, facts.COLLECTION_FAILED,
                        facts.NOT_FOUND_WITHIN_SCOPE}:
        state = fact.state if fact.state != facts.UNKNOWN_STATE else accuracy.UNKNOWN
        value = None
    elif fact.kind == facts.CAPABILITY:
        # a capability fact, correctly derived, still answers no usage question
        state, value = accuracy.UNKNOWN, None
    else:
        state, value = accuracy.FOUND, fact.value
    return accuracy.Prediction(dimension=unit.dimension, subject=unit.subject,
                               attribute=unit.attribute, value=value, state=state,
                               evidence_ids=fact.evidence_ids, scope=fact.scope)


def rigorous_predictions(corpus: Corpus) -> list[accuracy.Prediction]:
    predictions: list[accuracy.Prediction] = []
    for unit in corpus.units:
        scopes = {unit.subject: dict(unit.scope)} if unit.scope else None
        derivation = facts.derive(unit.observations, scopes=scopes)
        fact = derivation.get(unit.subject, unit.property)
        if fact is None:
            fact = facts.presence([], subject=unit.subject, property_name=unit.property,
                                  scope=str((unit.scope or {}).get("scope") or ""),
                                  searched=False,
                                  failure=(unit.scope or {}).get("failure"))
        prediction = _to_prediction(unit, fact)
        predictions.append(prediction)
        if prediction.state in {accuracy.FOUND, accuracy.CONFLICT} and unit.expected_evidence:
            predictions.append(accuracy.Prediction(
                dimension="evidence_attribution", subject=unit.subject,
                attribute=f"evidence:{unit.property}",
                value=",".join(sorted(set(prediction.evidence_ids))) or unit.expected_evidence,
                state=accuracy.FOUND,
                evidence_ids=tuple(sorted(set(prediction.evidence_ids)))))
    return predictions


# --------------------------------------------------------------------------- #
# the shortcut
# --------------------------------------------------------------------------- #

def naive_predictions(corpus: Corpus) -> list[accuracy.Prediction]:
    """``collector → CBOM``: every capability is a usage, the first answer wins, and anything
    the scanners did not see is guessed from the library list."""
    predictions: list[accuracy.Prediction] = []
    seen: set[tuple[str, str]] = set()
    for unit in corpus.units:
        if unit.observations:
            chosen = unit.observations[0]
            state, value = accuracy.FOUND, chosen.normalised_value()
        else:
            # nothing was observed, so the shortcut fills the gap from what libraries usually do
            state, value = accuracy.FOUND, "AES-256-GCM"
        if unit.dimension == "asset" and unit.truth_value is None:
            value = "application"
        key = (unit.dimension, unit.subject)
        if key in seen:
            continue                      # first answer wins; the duplicate name is merged away
        seen.add(key)
        predictions.append(accuracy.Prediction(
            dimension=unit.dimension, subject=unit.subject, attribute=unit.attribute,
            value=value, state=state, evidence_ids=(FABRICATED_EVIDENCE,)))
        predictions.append(accuracy.Prediction(
            dimension="evidence_attribution", subject=unit.subject,
            attribute=f"evidence:{unit.property}",
            value=FABRICATED_EVIDENCE, state=accuracy.FOUND,
            evidence_ids=(FABRICATED_EVIDENCE,)))
    return predictions


def truth_for(_predictions: list[accuracy.Prediction], corpus: Corpus) -> list[accuracy.Truth]:
    """The answer key, whole.

    Deliberately *not* filtered to the keys a pipeline answered: filtering would reward silence by
    shrinking the denominator, which is the failure mode this corpus exists to catch.
    """
    return corpus.truth()


def counts_summary(corpus: Corpus) -> dict[str, Any]:
    return corpus.counts()


__all__ = ["Corpus", "FABRICATED_EVIDENCE", "HARD_CASES", "SCHEMA", "Unit", "build",
           "counts_summary", "naive_predictions", "rigorous_predictions", "truth_for"]
