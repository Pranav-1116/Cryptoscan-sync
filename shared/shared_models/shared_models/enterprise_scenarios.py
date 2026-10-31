"""The enterprise simulation engine, scenario by scenario — implemented, partial, absent.

A simulation engine is easy to overstate, because the adjective "simulation"
covers two different things: a scenario that *computes* over evidence the twin
holds, and a scenario that *models a mechanism* (PKI hierarchies, KMS grant
graphs, supply-chain provenance) the twin may not represent at all. This build
has the first and only part of the second.

So each scenario below states which it is:

    EXISTS    a scenario computes this today, over collected evidence
    PARTIAL   a scenario models part of it; what it cannot see is listed
    ABSENT    nothing computes it; seeding an existing scenario is not a substitute

``covered_by`` names the real scenario ids that implement a row — the agility
catalogue (``services/agility/agility/twin_scenarios.py``) or the twin's own
scenario kinds (``shared_models/estate_twin.py``). ``test_enterprise_scenarios``
fails if a name here is not executable in this build, so a row cannot drift into
advertising a scenario nobody wrote.

The distinction matters at a bank: "we simulated an HSM failure" is true when the
engine reaches the assets that depend on the custodian, and misleading when it
suggests the failure was modelled at the HSM's own operation level — which
requires execution evidence this platform does not collect.
"""

from __future__ import annotations

SCHEMA = "cryptoscan.enterprise-simulation-scenarios/1"

EXISTS = "EXISTS"
PARTIAL = "PARTIAL"
ABSENT = "ABSENT"

STATUS_MEANING = {
    EXISTS: "a scenario computes this today over collected evidence",
    PARTIAL: "a scenario models part of this; the rest is listed rather than assumed",
    ABSENT: "nothing computes this — an existing scenario seeded to look like it is not it",
}

#: Where a scenario id comes from. Recorded so a reader can run the thing that an
#: EXISTS row points at, and so the test can resolve each id against its engine.
AGILITY = "agility"
TWIN = "twin"


def _scenario(
    identifier: str,
    label: str,
    status: str,
    *,
    covered_by: tuple[tuple[str, str], ...] = (),
    cannot: tuple[str, ...] = (),
    requires: tuple[str, ...] = (),
    note: str = "",
) -> dict:
    if status not in STATUS_MEANING:
        raise ValueError(f"unknown scenario status {status!r}")
    if status == EXISTS and not covered_by:
        raise ValueError(f"{identifier}: an EXISTS row must name the scenario that implements it")
    if status in {PARTIAL, ABSENT} and not cannot:
        raise ValueError(f"{identifier}: a {status} row must say what it cannot do")
    return {
        "id": identifier,
        "label": label,
        "status": status,
        "status_meaning": STATUS_MEANING[status],
        "covered_by": [{"engine": engine, "scenario": name} for engine, name in covered_by],
        "cannot": list(cannot),
        "requires": list(requires),
        "note": note,
    }


#: The ten scenarios an enterprise simulation engine is expected to answer,
#: in the order the assessment lists them. Every row was set by reading the two
#: engines in this tree, not from a plan.
SCENARIOS: tuple[dict, ...] = (
    _scenario(
        "PQC_MIGRATION", "PQC migration", EXISTS,
        covered_by=((AGILITY, "pqc_migration"), (TWIN, "MIGRATE_QUANTUM_VULNERABLE")),
        cannot=(
            "a migration *schedule*: it reports posture and blast radius, not a costed "
            "sequence of changes across owners",
        ),
        note="the deepest scenario in the product: quantum posture per asset, plus a simulated change on a copy",
    ),
    _scenario(
        "TLS_DOWNGRADE", "TLS downgrade", PARTIAL,
        covered_by=((AGILITY, "protocol_deprecation"), (TWIN, "DISABLE_PROTOCOL")),
        cannot=(
            "a negotiated-parameter downgrade: the twin holds what a handshake produced, not what "
            "a client would accept if the floor moved",
            "per-client fallback behaviour (a client that only speaks TLS 1.0 is not an asset)",
        ),
        requires=("negotiated handshake evidence per endpoint",),
        note="raises or lowers a protocol floor over collected facts; it does not re-negotiate",
    ),
    _scenario(
        "CERTIFICATE_COMPROMISE", "Certificate compromise", PARTIAL,
        covered_by=((AGILITY, "attack_path"), (TWIN, "CASCADE_CRYPTO_COMPROMISE")),
        cannot=(
            "revocation propagation: the twin does not model which sessions or systems accepted a "
            "certificate, so 'what breaks when this key is revoked' is not computable",
            "cross-signing and CA hierarchy traversal",
        ),
        requires=("certificate→endpoint binding evidence", "issuer hierarchy edges"),
        note="a compromised certificate is one seeded asset; the propagation is topological, not PKI-aware",
    ),
    _scenario(
        "HSM_FAILURE", "HSM failure", PARTIAL,
        covered_by=((AGILITY, "hsm_outage"), (TWIN, "CASCADE_ASSET_UNAVAILABLE")),
        cannot=(
            "operation-level failure: the twin knows which assets reference a custodian, not which "
            "signing operations actually went to it — that needs invocation evidence",
            "capacity and failover behaviour of an HSM cluster",
        ),
        requires=("runtime invocation evidence attributed to the custodian",),
        note="capability loss over the hardware fleet the live engine knows",
    ),
    _scenario(
        "KMS_FAILURE", "KMS failure", PARTIAL,
        covered_by=((AGILITY, "hsm_outage"), (TWIN, "CASCADE_ASSET_UNAVAILABLE")),
        cannot=(
            "grant/policy reasoning: which principal loses which key operation is not modelled",
            "per-region or per-account key replication",
        ),
        requires=("KMS key policy graph",),
        note="the same outage scenario covers a KMS custodian, at asset granularity",
    ),
    _scenario(
        "CRYPTO_LIBRARY_COMPROMISE", "Crypto-library compromise", PARTIAL,
        covered_by=((AGILITY, "vendor_compromise"), (TWIN, "CASCADE_ASSET_UNAVAILABLE")),
        cannot=(
            "version-range matching against an advisory: the twin records the observed library "
            "version, not which builds of it are affected",
            "static-link and vendored copies that carry no package record",
        ),
        requires=("library→binary provenance",),
        note="the blast radius follows library-user edges that were actually collected",
    ),
    _scenario(
        "SUPPLY_CHAIN_COMPROMISE", "Supply-chain compromise", PARTIAL,
        covered_by=((AGILITY, "vendor_compromise"),),
        cannot=(
            "artifact provenance: image digest → build → dependency chain is not a graph the twin "
            "holds, so 'which estates run the compromised build' is not answerable here",
            "transitive dependency depth beyond the collected dependency edges",
        ),
        requires=("signed provenance attestations per artifact",),
        note="vendor-level blast radius only; not artifact-level provenance",
    ),
    _scenario(
        "TRUST_COMPROMISE", "Trust compromise (CA / PKI)", ABSENT,
        cannot=(
            "everything a CA signed: certificate→issuer edges are not modelled as a hierarchy, so "
            "seeding a CA asset into attack_path reaches only what has an explicit dependency edge",
            "cross-signed chains and trust stores",
        ),
        requires=("issuer hierarchy", "trust-store membership per host"),
        note=(
            "the closest existing scenario is attack_path with a CA asset as the seed — which is "
            "topological propagation, not a trust model"
        ),
    ),
    _scenario(
        "SERVICE_COMPROMISE", "Service compromise", PARTIAL,
        covered_by=((AGILITY, "attack_path"), (TWIN, "CASCADE_ASSET_UNAVAILABLE")),
        cannot=(
            "lateral movement beyond collected edges: an unobserved connection is not in the model, "
            "and is reported as a blind spot rather than assumed absent",
            "credential reuse paths",
        ),
        note="BFS over established edges, with the unestablished ones listed as blockers",
    ),
    _scenario(
        "CUSTOM_SCENARIO", "Custom scenario", ABSENT,
        cannot=(
            "an operator-authored scenario: there is no scenario DSL, no expression over evidence "
            "facts, and no way to express a change the seven built-in kinds do not describe",
            "composition of several scenarios into one run with an ordered timeline",
        ),
        requires=("a scenario expression language", "ordered multi-step simulation"),
        note="a caller may run the existing kinds in sequence externally; that is orchestration, not a custom engine",
    ),
)


def catalogue() -> dict:
    """The ten rows with a rollup that counts states rather than scoring them."""
    counts = {state: 0 for state in STATUS_MEANING}
    for row in SCENARIOS:
        counts[row["status"]] += 1
    return {
        "schema": SCHEMA,
        "statuses": dict(STATUS_MEANING),
        # Copied deeply enough that a caller annotating a row (the route marks
        # ``present`` per engine) cannot rewrite the module-level table.
        "scenarios": [
            {**row, "covered_by": [dict(entry) for entry in row["covered_by"]]}
            for row in SCENARIOS
        ],
        "rollup": {"scenarios": len(SCENARIOS), **counts},
        "note": (
            "PARTIAL and ABSENT are not failures: they are the boundary of an evidence-driven "
            "engine. A scenario that models a mechanism the twin does not represent would produce "
            "a confident answer with no evidence behind it."
        ),
        "cannot_claim": (
            "A generic enterprise simulation engine that answers arbitrary what-if questions "
            "across every crypto failure mode.",
        ),
    }


def summary() -> dict:
    """The counts, and the one sentence they add up to.

    Used by ``GET /api/v1/platform/scope`` so the platform's self-description
    carries the ratio, not only the per-scenario rows: "one of the ten scenarios
    an enterprise simulation engine is asked for computes today" is the fact a
    reader needs before the detail.
    """
    counts = {state: 0 for state in STATUS_MEANING}
    for row in SCENARIOS:
        counts[row["status"]] += 1
    total = len(SCENARIOS)
    return {
        "scenarios": total,
        "computing": counts[EXISTS],
        "partial": counts[PARTIAL],
        "absent": counts[ABSENT],
        "headline": (
            f"{counts[EXISTS]} of {total} scenarios compute today; {counts[PARTIAL]} model part "
            f"of the mechanism and say what they cannot see; {counts[ABSENT]} have no model at "
            "all. This is not a generic enterprise simulation engine."
        ),
        "detail_at": "/estate/evidence/twin/simulation-scenarios",
    }


__all__ = [
    "ABSENT",
    "AGILITY",
    "EXISTS",
    "PARTIAL",
    "SCENARIOS",
    "SCHEMA",
    "STATUS_MEANING",
    "TWIN",
    "catalogue",
    "summary",
]
