"""Cloud certificate observation built on CloudFinding."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cloud_scanner.common.cloud_finding import CloudFinding


@dataclass
class CertificateFinding(CloudFinding):
    not_after: str | None = None
    subject: str | None = None
    issuer: str | None = None
    san: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        extra = dict(self.extra or {})
        if self.not_after:
            extra["not_after"] = self.not_after
        if self.subject:
            extra["subject"] = self.subject
        if self.issuer:
            extra["issuer"] = self.issuer
        if self.san:
            extra["san"] = list(self.san)
        finding = CloudFinding(
            source_type=self.source_type,
            resource=self.resource,
            purpose=self.purpose or "TLS",
            file_path=self.file_path,
            algorithm=self.algorithm,
            line_number=self.line_number,
            provider=self.provider,
            issue=self.issue,
            extra=extra,
            key_size=self.key_size,
            mode=self.mode,
        ).to_dict()
        finding["finding_kind"] = "certificate"
        return finding


CloudCertFinding = CertificateFinding
