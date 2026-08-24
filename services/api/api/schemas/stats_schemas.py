from pydantic import BaseModel


class SummaryStats(BaseModel):
    total_scans: int
    total_findings: int
    compliant: int
    non_compliant: int
    open_drift: dict
    algorithms: list[dict]
