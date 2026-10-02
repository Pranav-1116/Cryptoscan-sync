from api.live_scan.dependency_graph import build_live_dependency_graph


def test_live_graph_preserves_evidence_and_transitive_cascade():
    graph = build_live_dependency_graph([
        {"type": "library", "name": "OpenSSL", "version": "3.2", "ref": "lib:openssl", "source": "runtime", "evidence_reference": "sha256:lib"},
        {"type": "algorithm", "name": "AES-GCM", "ref": "algo:aes", "source": "source", "evidence_reference": "sha256:algo"},
        {"type": "service", "name": "payments", "asset_id": "svc:payments", "library": "OpenSSL", "algorithm": "AES-GCM", "source": "source", "depends_on": ["lib:openssl"], "evidence_reference": "sha256:svc"},
        {"type": "service", "name": "checkout", "asset_id": "svc:checkout", "depends_on": ["payments"], "source": "source", "evidence_reference": "sha256:checkout"},
    ])
    assert graph["summary"]["nodes"] == 4
    assert any(edge["relation"] == "DEPENDS_ON" for edge in graph["edges"])
    assert any(edge["relation"] == "USES_LIBRARY" for edge in graph["edges"])
    report = next(row for row in graph["cascade_reports"] if row["changed_node"] == "lib:openssl")
    assert "payments" in report["direct_dependents"]
    assert "checkout" in report["transitive_dependents"]
    assert report["destructive_execution"] is False


def test_unresolved_relationships_are_not_fabricated():
    graph = build_live_dependency_graph([
        {"type": "service", "name": "payments", "depends_on": ["missing-service"], "source": "vendor", "evidence_reference": "sha256:x"},
    ])
    assert graph["edges"] == []
    assert graph["summary"]["unresolved_relationships"] == 1
    assert graph["unresolved_relationships"][0]["reference"] == "missing-service"
