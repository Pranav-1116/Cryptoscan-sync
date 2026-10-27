"""Build graph nodes/edges from inventory rows."""

from __future__ import annotations

from typing import Any, Iterable

from graph_engine.builders import payload
from graph_engine.core.engine import GraphEngine


class NodeBuilder:
    def __init__(self, engine: GraphEngine | None = None) -> None:
        self.engine = engine or GraphEngine()

    def add_systems(self, systems: Iterable[dict[str, Any]]) -> None:
        for row in payload.systems_rows(systems):
            self.engine.add_node(
                f"system:{row['system_id']}",
                kind="System",
                name=row.get("name"),
                environment=row.get("environment"),
                owner=row.get("owner"),
                criticality=row.get("criticality"),
                compliance_scopes=row.get("compliance_scopes") or [],
            )

    def add_assets(self, assets: Iterable[dict[str, Any]]) -> None:
        for row in payload.asset_rows(assets):
            self.engine.add_node(
                f"asset:{row['asset_id']}",
                kind="CryptoAsset",
                algorithm=row.get("algorithm"),
                key_size=row.get("key_size"),
                purpose=row.get("purpose"),
                confidence=row.get("confidence"),
                file_path=row.get("file_path"),
            )
            if row.get("system_id"):
                self.engine.add_edge(f"system:{row['system_id']}", f"asset:{row['asset_id']}", "USES")

    def add_calls(self, edges: Iterable[dict[str, Any]]) -> None:
        for row in payload.call_rows(edges):
            self.engine.add_edge(
                f"system:{row['parent_id']}",
                f"system:{row['child_id']}",
                row.get("protocol") or "CALLS",
            )

    def build(
        self,
        *,
        systems: Iterable[dict[str, Any]] = (),
        assets: Iterable[dict[str, Any]] = (),
        edges: Iterable[dict[str, Any]] = (),
        processes: Iterable[dict[str, Any]] = (),
        owners: Iterable[dict[str, Any]] = (),
        vendors: Iterable[dict[str, Any]] = (),
        certificates: Iterable[dict[str, Any]] = (),
        cloud_resources: Iterable[dict[str, Any]] = (),
        network_resources: Iterable[dict[str, Any]] = (),
    ) -> GraphEngine:
        return self.engine.build(
            systems=systems,
            assets=assets,
            edges=edges,
            processes=processes,
            owners=owners,
            vendors=vendors,
            certificates=certificates,
            cloud_resources=cloud_resources,
            network_resources=network_resources,
        )
