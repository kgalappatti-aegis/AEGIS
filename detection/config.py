"""
AEGIS Detection Agent – Configuration
"""

from __future__ import annotations

import os

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# ── Stream / queue names ────────────────────────────────────────────────────

DETECTION_QUEUE  = "aegis:queue:detection"
ADVISORY_QUEUE   = "aegis:queue:advisory"
CONSUMER_GROUP   = "orchestrator-group"

# ── Settings ────────────────────────────────────────────────────────────────


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        populate_by_name=True,
        extra="ignore",
    )

    redis_url:         str   = Field(default="redis://localhost:6379", alias="REDIS_URL")
    anthropic_api_key: str   = Field(default="",                       alias="ANTHROPIC_API_KEY")
    log_level:         str   = Field(default="INFO",                   alias="LOG_LEVEL")

    # Skip low-severity findings (set DETECTION_SKIP_LOW=true to enable)
    skip_low_severity: bool  = Field(default=False, alias="DETECTION_SKIP_LOW")

    # Consumer identity
    consumer_name:    str    = Field(default="detection-agent-0", alias="DETECTION_CONSUMER_NAME")

    # Batching / timing (seconds / milliseconds)
    batch_size:       int    = Field(default=5,    alias="BATCH_SIZE")
    block_ms:         int    = Field(default=5000, alias="BLOCK_MS")
    claim_min_idle_ms: int   = Field(default=60_000, alias="CLAIM_MIN_IDLE_MS")


settings = Settings()
