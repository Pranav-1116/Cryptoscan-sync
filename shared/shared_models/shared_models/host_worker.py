"""Local worker candidate contracts; no authorization from queue hints."""

from pydantic import Field
from shared_models.host_collection import Strict, Token, Digest


class WorkerPin(Strict):
    binding_id: Token
    source_lock_sha256: Digest


class LocalWorkerBinding(WorkerPin):
    tenant_id: str | None = Field(max_length=36)
    system_id: Token
    target_id: str = Field(min_length=36, max_length=36)
    host_id: Token
    release_public_key: str = Field(min_length=44, max_length=44)
