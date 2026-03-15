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

CREATE TABLE IF NOT EXISTS workspace_config (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    description TEXT,
    updated_at  TIMESTAMPTZ DEFAULT now()
);

INSERT INTO workspace_config (key, value, description)
VALUES
    ('triage_threshold', '0.4', 'Minimum relevance score for simulation routing'),
    ('sim_threshold', '0.55', 'Monte Carlo breach probability threshold'),
    ('detection_skip_low', 'false', 'Skip detection for P3 events'),
    ('sim_iterations', '10000', 'Monte Carlo iteration count'),
    ('advisory_model', 'claude-sonnet-4-6', 'LLM model for advisory generation'),
    ('detection_model', 'claude-haiku-4-5-20251001', 'LLM model for per-TTP detection')
ON CONFLICT (key) DO NOTHING;

CREATE TABLE IF NOT EXISTS approval_queue (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    advisory_id  UUID        NOT NULL REFERENCES advisories(id),
    event_id     TEXT        NOT NULL,
    priority     TEXT        NOT NULL,
    title        TEXT,
    status       TEXT        NOT NULL DEFAULT 'pending',
    requested_at TIMESTAMPTZ DEFAULT now(),
    decided_at   TIMESTAMPTZ,
    decided_by   TEXT,
    comment      TEXT
);

CREATE INDEX IF NOT EXISTS approval_queue_status_idx ON approval_queue (status);
CREATE INDEX IF NOT EXISTS approval_queue_event_idx  ON approval_queue (event_id);

CREATE TABLE IF NOT EXISTS feedback (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    advisory_id  UUID        NOT NULL REFERENCES advisories(id),
    event_id     TEXT        NOT NULL,
    rating       INT         NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment      TEXT,
    created_at   TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS feedback_advisory_idx ON feedback (advisory_id);

ALTER TABLE advisories ADD COLUMN IF NOT EXISTS approval_status TEXT DEFAULT 'auto_approved';
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
