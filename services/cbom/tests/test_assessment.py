"""CBOM crypto-posture assessment tests (cbom.assessment)."""

from __future__ import annotations

import pytest

from cbom.assessment import assess_cbom


def _bom(components: list[dict]) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000001",
        "metadata": {"component": {"name": "payments-api", "version": "1.2.0"}},
        "components": components,
    }


def _crypto_component(name: str, *, primitive: str, designation: str,
                      quantum: bool | None = None, bom_ref: str = "r1") -> dict:
    return {
        "bom-ref": bom_ref,
        "type": "cryptographic-asset",
        "name": name,
        "cryptoProperties": {
            "primitive": primitive,
            "nistDesignation": designation,
            "quantumVulnerable": quantum,
            "oid": None,
        },
    }


class TestCbomAssessment:
    def test_clean_cbom_scores_a(self):
        bom = _bom([
            _crypto_component("AES-256-GCM", primitive="aead",
                              designation="APPROVED", quantum=False),
            _crypto_component("SHA-256", primitive="hash",
                              designation="APPROVED", quantum=False),
        ])
        result = assess_cbom(bom)
        assert result["score"] >= 90
        assert result["grade"] == "A"
        assert result["subject"]["name"] == "payments-api"
        assert result["subject"]["components"] == 2

    def test_disallowed_algorithm_penalty_and_finding(self):
        bom = _bom([
            _crypto_component("MD5", primitive="hash",
                              designation="DISALLOWED", quantum=False),
            _crypto_component("AES-256-GCM", primitive="aead",
                              designation="APPROVED", quantum=False),
        ])
        result = assess_cbom(bom)
        assert result["score"] < 100
        assert result["grade"] != "A"
        md5 = [f for f in result["findings"] if f["algorithm"] == "MD5"]
        assert md5 and md5[0]["severity"] == "high"
        assert any("SHA-256" in f["recommendation"] for f in md5)
        assert any("Retire broken algorithms" in r for r in result["recommendations"])

    def test_quantum_vulnerable_rsa(self):
        bom = _bom([
            _crypto_component("RSA", primitive="pke",
                              designation="APPROVED", quantum=True),
        ])
        result = assess_cbom(bom)
        assert "pke" in result["summary"]["quantum_exposed_families"]
        assert "RSA" in result["summary"]["quantum_vulnerable_algorithms"]
        assert any("ML-KEM" in r for r in result["recommendations"])

    def test_unknown_algorithm_falls_back_to_knowledge_base(self):
        # No cryptoProperties at all → known-algorithm KB supplies designation
        bom = _bom([{"bom-ref": "r1", "type": "cryptographic-asset",
                     "name": "DES"}])
        result = assess_cbom(bom)
        des = [f for f in result["findings"] if f["algorithm"] == "DES"]
        assert des and des[0]["designation"] == "DISALLOWED"

    def test_concentration_scaling(self):
        # 4 of 5 components use the same DISALLOWED algorithm → heavier penalty
        bom = _bom([
            _crypto_component("RC4", primitive="stream-cipher",
                              designation="DISALLOWED", quantum=False),
            _crypto_component("RC4", primitive="stream-cipher",
                              designation="DISALLOWED", quantum=False),
            _crypto_component("RC4", primitive="stream-cipher",
                              designation="DISALLOWED", quantum=False),
            _crypto_component("RC4", primitive="stream-cipher",
                              designation="DISALLOWED", quantum=False),
            _crypto_component("AES-256-GCM", primitive="aead",
                              designation="APPROVED", quantum=False),
        ])
        result = assess_cbom(bom)
        assert result["subject"]["components"] == 5
        rc4 = [f for f in result["findings"] if f["algorithm"] == "RC4"]
        assert rc4[0]["occurrences"] == 4

    def test_summary_counts(self):
        bom = _bom([
            _crypto_component("AES-256-GCM", primitive="aead",
                              designation="APPROVED", quantum=False),
            _crypto_component("AES-256-GCM", primitive="aead",
                              designation="APPROVED", quantum=False),
            _crypto_component("SHA-512", primitive="hash",
                              designation="APPROVED", quantum=False),
        ])
        result = assess_cbom(bom)
        assert result["summary"]["algorithms"]["AES-256-GCM"] == 2
        assert result["summary"]["primitives"]["aead"] == 2
        assert result["summary"]["designations"]["APPROVED"] == 3

    def test_empty_bom_is_honest(self):
        result = assess_cbom({"components": []})
        assert result["score"] == 100
        assert result["grade"] == "A"
        assert result["subject"]["components"] == 0
        assert result["recommendations"]

    def test_oids_captured(self):
        component = _crypto_component("RSA", primitive="pke",
                                      designation="APPROVED", quantum=True)
        component["cryptoProperties"]["oid"] = "2.5.8.1.1"
        result = assess_cbom(_bom([component]))
        rsa = [e for e in result["per_algorithm"] if e["algorithm"] == "RSA"]
        assert rsa and rsa[0]["oids"] == ["2.5.8.1.1"]
