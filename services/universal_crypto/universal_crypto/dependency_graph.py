"""§16 Crypto dependency graph.

The differentiator: ZELNX knows the *relationship*, not just the existence
of an algorithm.

    Application
      ├── OpenSSL
      │     └── TLS
      │           └── ECDSA
      └── Certificate
            └── RSA-2048

Uses CycloneDX CBOM relationship semantics (dependsOn / contains / serves /
uses / validates) so the graph is CBOM-compatible.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

RELATIONSHIPS = ("dependsOn", "contains", "serves", "uses", "validates", "invokes")


class CryptoDependencyGraph:
    """Directed graph of crypto assets with CBOM relationship labels."""

    def __init__(self) -> None:
        self._nodes: dict[str, dict[str, Any]] = {}
        self._edges: list[dict[str, str]] = []

    def add_node(self, node_id: str, *, kind: str,
                 algorithm: str = "", extra: Optional[dict[str, Any]] = None) -> None:
        self._nodes.setdefault(node_id, {
            "id": node_id, "kind": kind, "algorithm": algorithm,
            **(extra or {}),
        })

    def add_edge(self, source: str, target: str, relationship: str) -> None:
        if relationship not in RELATIONSHIPS:
            raise ValueError(f"unknown relationship {relationship!r}")
        edge = {"source": source, "target": target, "relationship": relationship}
        if edge not in self._edges:
            self._edges.append(edge)

    # -- §16 builders ------------------------------------------------------

    def build_application(
        self,
        *,
        application: str,
        libraries: Optional[Iterable[str]] = None,
        protocols: Optional[Iterable[str]] = None,
        algorithms: Optional[Iterable[str]] = None,
        certificates: Optional[Iterable[str]] = None,
        certificate_algorithms: Optional[dict[str, str]] = None,
    ) -> "CryptoDependencyGraph":
        """Application → library → protocol → algorithm + certificate chain."""
        self.add_node(application, kind="application")
        for lib in libraries or []:
            self.add_node(lib, kind="crypto_library")
            self.add_edge(application, lib, "dependsOn")
            for protocol in protocols or []:
                self.add_node(protocol, kind="protocol")
                self.add_edge(lib, protocol, "uses")
                for algorithm in algorithms or []:
                    self.add_node(algorithm, kind="algorithm")
                    self.add_edge(protocol, algorithm, "uses")
        for cert_id in certificates or []:
            self.add_node(cert_id, kind="certificate")
            self.add_edge(application, cert_id, "uses")
            cert_alg = (certificate_algorithms or {}).get(cert_id, "")
            if cert_alg:
                self.add_node(cert_alg, kind="algorithm")
                self.add_edge(cert_id, cert_alg, "uses")
        return self

    def affected(self, node_id: str, max_depth: int = 6) -> list[dict[str, Any]]:
        """Everything downstream of a node (e.g. certificate → RSA-2048)."""
        out: list[dict[str, Any]] = []
        seen: set[str] = set()

        def walk(current: str, depth: int) -> None:
            if depth > max_depth or current in seen:
                return
            seen.add(current)
            for edge in self._edges:
                if edge["source"] == current:
                    out.append({"node": edge["target"],
                                "relationship": edge["relationship"],
                                "depth": depth})
                    walk(edge["target"], depth + 1)
        walk(node_id, 1)
        return out

    def dependency_count(self, node_id: str) -> int:
        """How many assets depend on this node (inverse edges)."""
        return sum(1 for e in self._edges if e["target"] == node_id)

    def paths(self, source: str, target: str, max_depth: int = 8) -> list[list[str]]:
        found: list[list[str]] = []

        def _walk(current: str, path: list[str], seen: set[str]) -> None:
            if len(path) > max_depth:
                return
            if current == target:
                found.append(list(path))
                return
            for edge in self._edges:
                if edge["source"] == current and edge["target"] not in seen:
                    seen.add(edge["target"])
                    _walk(edge["target"], path + [edge["target"]], seen)
                    seen.discard(edge["target"])

        _walk(source, [source], {source})
        return found

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": list(self._nodes.values()), "edges": list(self._edges)}

    def to_cbom_relationships(self) -> list[dict[str, str]]:
        """CBOM-format relationships (CycloneDX shape)."""
        return [{"source": e["source"], "target": e["target"],
                 "relationship": e["relationship"]} for e in self._edges]
