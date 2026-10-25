"""One immutable AWS key/version operation, with pre-reviewed public verification key."""

import re
from typing import Literal
from pydantic import Field, model_validator
from shared_models.host_common import Strict
from shared_models.operation_evidence_v2 import OperationApprovalV2


class HsmOperationRequest(Strict):
    schema_version: Literal["cryptoscan.hsm-operation-request/v1"] = "cryptoscan.hsm-operation-request/v1"
    provider: Literal["aws_kms"] = "aws_kms"
    region: str = Field(pattern=r"^[a-z]{2}(?:-[a-z]+){1,3}-[0-9]$")
    approval: OperationApprovalV2

    @model_validator(mode="after")
    def immutable_key(self):
        match = re.fullmatch(
            r"arn:aws(?:-us-gov|-cn)?:kms:([^:]+):[0-9]{12}:key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            self.approval.provider_key_id,
        )
        if not match or match[1] != self.region:
            raise ValueError("Exact immutable key ARN and same reviewed region required; no aliases/endpoints")
        return self
