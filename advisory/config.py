"""
AEGIS Advisory Agent – Configuration
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# ── Stream / channel names ──────────────────────────────────────────────────

ADVISORY_QUEUE    = "aegis:queue:advisory"
ADVISORY_STREAM   = "aegis:stream:advisories"   # persistent stream for UI catchup
BROADCAST_CHANNEL = "aegis:broadcast"
CONSUMER_GROUP    = "orchestrator-group"

# ── DB schema ───────────────────────────────────────────────────────────────

DDL = """
CREATE TABLE IF NOT EXISTS advisories (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id           TEXT        NOT NULL,
    cve_id             TEXT,
    priority           TEXT,
    severity           TEXT,
    p_breach           FLOAT,
    risk_score         INT,
    title              TEXT,
    executive_summary  TEXT,
    technical_summary  TEXT,
    affected_assets    JSONB,
    immediate_actions  JSONB,
    detection_actions  JSONB,
    sigma_rules        JSONB,
    coverage_gaps      JSONB,
    tlp                TEXT,
    confidence         TEXT,
    mitre_techniques   JSONB,
    source_type        TEXT,
    ext_references     JSONB,
    finding_json       JSONB,
    simulated_at       TIMESTAMPTZ,
    detected_at        TIMESTAMPTZ,
    created_at         TIMESTAMPTZ DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS advisories_event_id_unique ON advisories (event_id);
CREATE INDEX IF NOT EXISTS advisories_cve_id_idx  ON advisories (cve_id);
CREATE INDEX IF NOT EXISTS advisories_created_idx ON advisories (created_at DESC);
CREATE INDEX IF NOT EXISTS advisories_priority_idx ON advisories (priority);

ALTER TABLE advisories ADD COLUMN IF NOT EXISTS finding_json JSONB;
"""


# ── Settings ────────────────────────────────────────────────────────────────

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        populate_by_name=True,
        extra="ignore",
    )

    redis_url:         str = Field(default="redis://localhost:6379",                    alias="REDIS_URL")
    anthropic_api_key: str = Field(default="",                                          alias="ANTHROPIC_API_KEY")
    database_url:      str = Field(default="postgresql://aegis:aegis@localhost:5432/aegis", alias="DATABASE_URL")
    log_level:         str = Field(default="INFO",                                      alias="LOG_LEVEL")

    # Consumer identity
    consumer_name:     str = Field(default="advisory-agent-0", alias="ADVISORY_CONSUMER_NAME")

    # Batching / timing
    batch_size:        int = Field(default=5,      alias="BATCH_SIZE")
    block_ms:          int = Field(default=5000,   alias="BLOCK_MS")
    claim_min_idle_ms: int = Field(default=60_000, alias="CLAIM_MIN_IDLE_MS")


settings = Settings()
