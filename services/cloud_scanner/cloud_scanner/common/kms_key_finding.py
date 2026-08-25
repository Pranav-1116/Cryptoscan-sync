"""KMS / CMK observation built on CloudFinding."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cloud_scanner.common.cloud_finding import CloudFinding


@dataclass
class KMSKeyFinding(CloudFinding):
    rotation_enabled: bool | None = None
    customer_managed: bool | None = None
    key_spec: str | None = None

    def to_dict(self) -> dict[str, Any]:
        extra = dict(self.extra or {})
        if self.rotation_enabled is not None:
            extra["rotation_enabled"] = self.rotation_enabled
        if self.customer_managed is not None:
            extra["customer_managed"] = self.customer_managed
        if self.key_spec:
            extra["key_spec"] = self.key_spec
        finding = CloudFinding(
            source_type=self.source_type,
            resource=self.resource,
            purpose=self.purpose,
            file_path=self.file_path,
            algorithm=self.algorithm,
            line_number=self.line_number,
            provider=self.provider,
            issue=self.issue,
            extra=extra,
            key_size=self.key_size,
            mode=self.mode,
        ).to_dict()
        finding["finding_kind"] = "kms_key"
        return finding
