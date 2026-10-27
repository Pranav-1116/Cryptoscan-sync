"""Product intake/assignment contracts; never remote execution authorization."""

from typing import Literal
from pydantic import Field, model_validator
from shared_models.host_common import Strict
from shared_models.host_collection import Token
from shared_models.qualification_acceptance import AcceptancePolicy, EvidenceIndex, SignedReview

Role = Literal["linux_operator", "windows_operator", "verifier", "independent_assessor", "bank_acceptor"]


class CampaignCreate(Strict):
    policy: AcceptancePolicy
    return_channel_reference: Token
    evidence_reference: Token


class ExpectedRevision(Strict):
    expected_revision: int = Field(ge=1, le=320)
    evidence_reference: Token


class Assignee(Strict):
    user_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    reviewer_id: Token | None = None


class Assignments(ExpectedRevision):
    assignments: dict[Role, Assignee] = Field(min_length=1, max_length=5)

    @model_validator(mode="after")
    def reviewer_mapping(self):
        for role, assignee in self.assignments.items():
            if (role in {"independent_assessor", "bank_acceptor"}) != (assignee.reviewer_id is not None):
                raise ValueError("Only reviewer assignments require a pinned reviewer ID")
        return self


class FreezeEvidence(ExpectedRevision):
    index: EvidenceIndex


class SubmitReview(ExpectedRevision):
    review: SignedReview
