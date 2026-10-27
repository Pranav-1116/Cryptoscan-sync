"""Truth-preserving readiness projections for the API."""

from .assurance import build_readiness_summary, normalize_status

__all__ = ["build_readiness_summary", "normalize_status"]
