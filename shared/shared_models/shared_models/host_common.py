"""Stable strict base shared by host metadata contracts."""

from pydantic import BaseModel, ConfigDict


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
