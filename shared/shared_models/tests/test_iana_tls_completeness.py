"""The algorithm registry must parse every cipher suite IANA registers.

"Cover every algorithm in the world" is not a checkable claim — there is no
list of the world. "Cover every entry in a named authoritative registry" is,
and it is the one an auditor can actually verify, so that is what this pins.

The source is IANA's TLS Cipher Suite registry (tls-parameters-4), vendored
next to this test as a dated snapshot. Vendored rather than fetched: the suite
is hermetic (see the repo conftest — no test may open a non-loopback socket),
and a gate that silently passes when the network is down is not a gate.

Refreshing the snapshot is deliberate work: download tls-parameters-4.csv,
drop it in, and let this test tell you which newly-registered suites the
registry does not yet parse. That is the intended workflow — the diff in
coverage is the point.

    https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv
"""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

from shared_models.algorithm_registry import parse_algorithm

SNAPSHOT = (
    Path(__file__).resolve().parents[1]
    / "shared_models" / "data" / "iana_tls_parameters.csv"
)


def _registered_suites() -> list[tuple[str, str]]:
    """(code_point, name) for every concrete suite in the registry.

    Rows whose Value spans a range ("0xFB-FD,*") are Unassigned/Reserved
    blocks, not suites, and carry no TLS_ name.
    """
    with SNAPSHOT.open(encoding="utf-8") as fh:
        return [
            (row["Value"], row["Description"].strip())
            for row in csv.DictReader(fh)
            if row["Description"].strip().startswith("TLS_") and "-" not in row["Value"]
        ]


def test_snapshot_is_present_and_plausible():
    assert SNAPSHOT.is_file(), f"vendored IANA snapshot missing at {SNAPSHOT}"
    suites = _registered_suites()
    # Guards against a truncated or wrong-registry file being dropped in.
    assert len(suites) > 300, f"snapshot looks truncated: only {len(suites)} suites"


@pytest.mark.parametrize(("code_point", "name"), _registered_suites())
def test_every_iana_suite_is_recognised(code_point, name):
    """Each suite parses to something, and never to a bare primitive.

    The second half matters more than the first. Before this test,
    TLS_SHA256_SHA256 and TLS_SHA384_SHA384 (RFC 9150, integrity-only) parsed
    as the hash their names end in — so a scan reported "SHA-256" and lost the
    fact that the suite negotiates *no encryption at all*. Recognition alone
    would not have caught that; the family assertion does.
    """
    info = parse_algorithm(name)
    assert info.recognized, f"{code_point} {name} is not recognised"
    assert info.family in {"tls-suite", "tls-signalling"}, (
        f"{code_point} {name} parsed as {info.family!r} ({info.canonical}), "
        "not as a suite — a cipher suite reported as a bare primitive loses "
        "its other components"
    )


def test_integrity_only_suites_are_not_reported_as_encryption():
    """RFC 9150 suites authenticate and send plaintext. Say so."""
    for name in ("TLS_SHA256_SHA256", "TLS_SHA384_SHA384"):
        info = parse_algorithm(name)
        assert info.status == "DISALLOWED", name
        assert "NO ENCRYPTION" in info.notes, name
        # No bulk cipher component at all — that is the whole point.
        roles = {c.get("role") for c in (info.components or ())}
        assert "bulk_cipher" not in roles, name


def test_scsv_values_are_flagged_as_signalling_not_algorithms():
    """SCSVs occupy suite code points but name no algorithm."""
    for name in ("TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "TLS_FALLBACK_SCSV"):
        info = parse_algorithm(name)
        assert info.family == "tls-signalling", name
        assert not info.components, f"{name} should decompose to nothing"
