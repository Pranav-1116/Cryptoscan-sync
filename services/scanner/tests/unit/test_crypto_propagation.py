"""Transitive crypto propagation (report 13 §1.3): package graph ⟕ crypto libraries.

Two levels:
* the propagation function directly — chains, flags, honest coverage;
* an end-to-end scan over an npm repo whose lockfile carries real nested
  parent edges, so the propagation runs on exactly what the inventory
  parsers produce.
"""

from __future__ import annotations


from scanner.analysis.cascade import (
    LibraryNode,
    PackageDependencyNode,
    propagate_crypto_dependencies,
)
from scanner.core.scanner import Scanner

NOW = "2026-10-09T00:00:00+00:00"
REF = "sha256:" + "0" * 64


def _node(ecosystem: str, name: str, *, direct: bool, parent: str | None) -> PackageDependencyNode:
    return PackageDependencyNode(
        ecosystem=ecosystem, name=name, version="1.0.0", dependency_type="direct" if direct else "transitive",
        direct=direct, parent=parent, source="package-lock.json", evidence_type="lockfile",
        evidence_reference=REF, observed_at=NOW,
    )


def test_propagation_marks_ancestors_and_records_chains():
    nodes = [
        _node("npm", "websock", direct=True, parent=None),
        _node("npm", "mid-layer", direct=False, parent="websock"),
        _node("npm", "crypto-js", direct=False, parent="mid-layer"),
        _node("npm", "left-pad", direct=True, parent=None),
    ]
    libraries = [LibraryNode(library="crypto-js", algorithms=["AES-CBC", "MD5"])]

    paths, coverage = propagate_crypto_dependencies(nodes, libraries)

    by_name = {n.name: n for n in nodes}
    # the crypto library itself and every ancestor are crypto-bearing
    assert by_name["crypto-js"].crypto_bearing is True
    assert by_name["mid-layer"].crypto_bearing is True
    assert by_name["websock"].crypto_bearing is True
    # algorithms observed in first-party code ride up the chain
    assert by_name["websock"].crypto_algorithms == ["AES-CBC", "MD5"]
    # unrelated direct deps stay clean
    assert by_name["left-pad"].crypto_bearing is False

    assert len(paths) == 1
    path = paths[0]
    assert path.crypto_package == "crypto-js"
    assert path.library == "crypto-js"
    assert path.algorithms == ["AES-CBC", "MD5"]
    assert path.direct_entry == "websock", "chain must end at the direct dependency"
    assert path.chain == ["crypto-js", "mid-layer", "websock"]
    assert path.depth == 3
    assert coverage["ecosystems_with_parent_edges"] == ["npm"]


def test_direct_crypto_package_is_a_depth_one_chain():
    nodes = [_node("pypi", "pycryptodome", direct=True, parent=None)]
    paths, _ = propagate_crypto_dependencies(nodes, [])
    assert len(paths) == 1
    assert paths[0].depth == 1
    assert paths[0].chain == ["pycryptodome"]
    assert paths[0].direct_entry == "pycryptodome"
    # no first-party usage observed → identity only, no fabricated algorithms
    assert paths[0].algorithms == []


def test_flat_lockfile_invents_no_chains():
    # go.sum: flat list, no parent edges — only the crypto package is flagged
    nodes = [
        _node("go", "golang.org/x/crypto", direct=True, parent=None),
        _node("go", "github.com/some/indirect", direct=False, parent=None),
    ]
    paths, coverage = propagate_crypto_dependencies(nodes, [])
    by_name = {n.name: n for n in nodes}
    assert by_name["golang.org/x/crypto"].crypto_bearing is True
    assert by_name["github.com/some/indirect"].crypto_bearing is False, "no edges → no invented exposure"
    assert len(paths) == 1 and paths[0].depth == 1
    assert coverage["ecosystems_with_parent_edges"] == []


def test_cycle_does_not_loop_forever():
    nodes = [
        _node("npm", "a", direct=True, parent=None),
        _node("npm", "b", direct=False, parent="a"),
        _node("npm", "crypto-js", direct=False, parent="b"),
        # defensive: a malformed lockfile edge that would cycle b→crypto-js→b
        _node("npm", "b-dup", direct=False, parent="crypto-js"),
    ]
    nodes[3] = nodes[3].model_copy(update={"name": "b", "parent": "crypto-js"})
    nodes = nodes[:3] + [nodes[3]]
    paths, _ = propagate_crypto_dependencies(nodes, [])
    assert paths, "cycle must not swallow the real chain"


def test_end_to_end_scan_propagates_npm_nested_chain(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    (root / "package.json").write_text('{"dependencies": {"websock": "^2.0.0"}}')
    (root / "package-lock.json").write_text(
        """
{
  "packages": {
    "": {"name": "app"},
    "node_modules/websock": {"version": "2.1.0"},
    "node_modules/websock/node_modules/crypto-js": {"version": "4.2.0"},
    "node_modules/left-pad": {"version": "1.3.0"}
  }
}
"""
    )

    result = Scanner().scan(str(root))
    cascade = result.cascade
    assert cascade is not None

    summary = cascade["summary"]
    # crypto-js is the crypto library; websock is direct and inherits the
    # exposure. websock has two rows (manifest + lockfile), so 3 flagged rows
    assert summary["crypto_bearing_packages"] == 3
    assert summary["crypto_bearing_transitive"] == 1
    assert summary["crypto_bearing_direct"] == 2
    assert summary["crypto_dependency_paths"] == 1
    assert summary["crypto_dependency_coverage"]["ecosystems_with_parent_edges"] == ["npm"]

    # websock (direct) is exposed through crypto-js (transitive)
    packages = {(p["ecosystem"], p["name"]): p for p in cascade["package_dependencies"]}
    crypto_js = packages[("npm", "crypto-js")]
    websock = packages[("npm", "websock")]
    assert crypto_js["crypto_bearing"] is True
    assert websock["crypto_bearing"] is True, "direct dep inherits transitive crypto exposure"
    assert packages[("npm", "left-pad")]["crypto_bearing"] is False

    path = cascade["crypto_dependency_paths"][0]
    assert path["crypto_package"] == "crypto-js"
    assert path["direct_entry"] == "websock"
    assert path["chain"] == ["crypto-js", "websock"]
    assert path["library"] == "crypto-js"
    assert result.statistics.cascade_providers == summary["providers"]
