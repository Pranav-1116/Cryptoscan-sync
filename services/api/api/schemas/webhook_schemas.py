from pydantic import BaseModel


class WebhookAck(BaseModel):
    accepted: bool
    job_id: str | None = None
    message: str
