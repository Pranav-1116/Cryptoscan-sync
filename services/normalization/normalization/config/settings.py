"""
Normalization service configuration.
All values configurable via environment variables.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class NormalizationSettings(BaseSettings):
    """
    Configuration for the normalization engine.

    Environment variable prefix: NORMALIZATION_
    """

    model_config = SettingsConfigDict(
        env_prefix="NORMALIZATION_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Rule Definitions ─────────────────────────────────────────────
    rule_definitions_dir: Path = Field(
        default=Path(__file__).parent.parent / "rule_definitions",
        description="Directory containing YAML normalization rule files.",
    )

    # ── Normalization Behavior ────────────────────────────────────────
    normalization_version: str = Field(
        default="1.0",
        description="Version tag applied to all normalization results.",
    )

    # ── Unknown Algorithm Handling ────────────────────────────────────
    flag_unknown_for_review: bool = Field(
        default=True,
        description="Flag unrecognized algorithms for human review.",
    )

    # ── Caching ───────────────────────────────────────────────────────
    enable_result_cache: bool = Field(
        default=True,
        description="Cache normalization results for repeated raw algorithm strings.",
    )
    cache_max_size: int = Field(
        default=512,
        ge=0,
        description="Maximum number of entries in the LRU result cache.",
    )

    # ── Logging ──────────────────────────────────────────────────────
    log_level: str = Field(
        default="INFO",
        description="Logging level for normalization service.",
    )

    # ── Database (for update mode) ────────────────────────────────────
    database_url: str = Field(
        default="postgresql+psycopg2://cryptoscan:secret@localhost:5432/cryptoscan",
        description="PostgreSQL connection string for updating evidence_records.",
    )
    db_batch_size: int = Field(
        default=500,
        ge=1,
        le=5000,
        description="Number of evidence records to normalize per DB batch.",
    )

    @field_validator("rule_definitions_dir")
    @classmethod
    def validate_rule_dir(cls, v: Path) -> Path:
        if not v.exists():
            raise ValueError(f"Rule definitions directory does not exist: {v}")
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return upper


@lru_cache(maxsize=1)
def get_settings() -> NormalizationSettings:
    """Return cached settings singleton."""
    return NormalizationSettings()