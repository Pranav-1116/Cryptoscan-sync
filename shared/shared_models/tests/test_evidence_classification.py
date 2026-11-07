"""Evidence classification (gap analysis §A), as tests.

Roadmap rule: the five evidence levels — Capability / Static reference /
Configuration / Runtime observed / Network negotiated — must never be
confused, and "every record shows evidence classification".
"""

from __future__ import annotations

from shared_models.evidence_classification import (
    CAPABILITY,
    CONFIGURATION,
    NETWORK_NEGOTIATED,
    RUNTIME_OBSERVED,
    STATIC_REFERENCE,
    UNCLASSIFIED,
    classify_evidence,
    classify_records,
)


class TestClassifyEvidence:

    def test_an_explicit_level_wins(self):
        row = classify_evidence({"evidence_level": "capability",
                                 "file_path": "x.conf"})
        assert row["level"] == CAPABILITY
        assert "states its evidence level" in row["rule"]

    def test_collector_source_decides_network_and_runtime(self):
        net = classify_evidence({"collector": "tls-handshake-scanner"})
        assert net["level"] == NETWORK_NEGOTIATED
        live = classify_evidence({"source": "runtime process probe"})
        assert live["level"] == RUNTIME_OBSERVED

    def test_file_shape_decides_configuration_and_static_reference(self):
        config = classify_evidence({"file_path": "/etc/openssl/openssl.cnf",
                                    "line_number": 12})
        assert config["level"] == CONFIGURATION
        code = classify_evidence({"file_path": "src/crypto.py",
                                  "line_number": 40})
        assert code["level"] == STATIC_REFERENCE

    def test_nothing_recorded_is_unclassified_never_promoted(self):
        row = classify_evidence({"algorithm": "AES"})
        assert row["level"] == UNCLASSIFIED
        assert "never promoted" in row["rule"]
        bogus = classify_evidence({"evidence_level": "probably-runtime"})
        assert bogus["level"] == UNCLASSIFIED

    def test_static_reference_is_never_observed_use(self):
        report = classify_records([
            {"file_path": "a.py", "line_number": 3},
            {"file_path": "b.py", "line_number": 9},
        ])
        assert report["strongest_level"] == STATIC_REFERENCE
        assert report["counts"][RUNTIME_OBSERVED] == 0
        assert "never merge upward" in report["note"]

    def test_the_strongest_recorded_level_is_named(self):
        report = classify_records([
            {"file_path": "a.py", "line_number": 3},
            {"collector": "pcap-capture"},
        ])
        assert report["strongest_level"] == NETWORK_NEGOTIATED
