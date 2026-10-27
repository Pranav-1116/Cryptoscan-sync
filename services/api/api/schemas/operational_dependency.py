"""Strict operational declarations, separate from runtime availability facts."""

from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator
from shared_models.operational_dependencies import validate_assertion

Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]
Identifier = Annotated[str, StringConstraints(min_length=1, max_length=36)]


class OperationalDependency(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["UNKNOWN", "HARD", "OPTIONAL", "FAILOVER", "ASYNC_BUFFERED"]
    assumptions: list[Text] = Field(default_factory=list, max_length=20)
    evidence_ref: Text | None = None
    failover_system_ids: list[Identifier] = Field(default_factory=list, max_length=20)
    buffer_capacity_messages: int | None = Field(None, strict=True, ge=0, le=2**53 - 1)
    buffer_retention_seconds: float | None = Field(None, strict=True, gt=0, le=2**53 - 1, allow_inf_nan=False)

    @model_validator(mode="after")
    def consistent_mode(self):
        validate_assertion(self.model_dump(exclude_none=True))
        return self

    def assertion(self):
        return validate_assertion(self.model_dump(exclude_none=True))


class OperationalDependencyChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: int = Field(ge=0)
    operational_dependency: OperationalDependency | None
    reason: Text
    evidence_ref: Text
