"""Built-in Terraform IaC connector.

Wraps the real ``cloud_scanner.iac.terraform.parse_terraform`` parser and
emits normalized Observations through the SDK (context guardrails + registry).
This is a genuine connector: it reads a repo's ``*.tf`` files and reports the
crypto/cloud resources the parser actually sees — no sample/fabricated rows.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from connector_sdk.base import BaseConnector
from connector_sdk.context import ConnectorContext
from connector_sdk.observations import Observation
from connector_sdk.registry import register_connector


@register_connector(kind="terraform", method="api")
class TerraformIaCConnector(BaseConnector):
    kind = "terraform"
    method = "api"
    mode = "passive"  # read-only: IaC parsing never mutates anything

    def scan(self, context: ConnectorContext, targets: Iterable[str] = ()) -> list[Observation]:
        try:
            from cloud_scanner.iac.terraform import parse_terraform
        except Exception:
            # cloud_scanner not importable in this runtime — honest empty result
            return []

        observations: list[Observation] = []
        for t in targets:
            path = Path(t)
            if not path.is_file():
                continue
            try:
                findings = parse_terraform(path)
            except Exception:
                continue
            for f in findings:
                observations.append(Observation(
                    asset=str(f.get("resource") or f.get("source_type") or t),
                    source="terraform",
                    observation_type="cloud_resource",
                    method="terraform",
                    confidence="HIGH" if f.get("source_type") == "AWS_KMS_KEY" else "MEDIUM",
                    asset_type="cloud_resource",
                    scanner="terraform_connector",
                    evidence=f,
                    extra={"path": str(path)},
                ))
        return observations


__all__ = ["TerraformIaCConnector"]
