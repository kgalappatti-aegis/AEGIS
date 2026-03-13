"""
AEGIS Orchestrator Configuration
Priority and routing matrices, Redis keys, env-var loading.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()


# ---------------------------------------------------------------------------
# Priority matrix  (source_type → P0..P3)
# ---------------------------------------------------------------------------
# P0 – Actively exploited / live endpoint telemetry  → drop everything
# P1 – High-confidence threat intel / live SIEM hits → urgent review
# P2 – Vulnerability advisories                      → scheduled review
# P3 – Contextual / structured intel bundles         → background enrichment

PRIORITY_MATRIX: dict[str, str] = {
    "cisa_kev":  "P0",   # CISA Known Exploited Vulnerabilities – active exploitation confirmed
    "edr":       "P0",   # Endpoint Detection & Response – live endpoint alert
    "siem":      "P1",   # SIEM correlation rule hit
    "threatfox": "P1",   # Active IOC / malware intel feed
    "nvd":       "P2",   # NVD vulnerability disclosure
    "stix":      "P3",   # Structured threat intel bundle (STIX/TAXII)
    "misp":      "P1",   # MISP threat intel (inherits MISP threat_level)
}


# ---------------------------------------------------------------------------
# Routing matrix  (source_type → routing_target)
# ---------------------------------------------------------------------------
# triage     – human/agent must assess and classify immediately
# detection  – feeds automated detection rule pipeline
# simulation – threat modeling / adversary simulation
# advisory   – vulnerability advisory enrichment / patching guidance

ROUTING_MATRIX: dict[str, str] = {
    "cisa_kev":  "triage",      # Known-exploited needs immediate triage
    "edr":       "detection",   # EDR hits feed detection correlation
    "siem":      "triage",      # SIEM alerts need analyst triage
    "threatfox": "triage",      # Active IOCs need immediate review
    "nvd":       "advisory",    # CVE disclosures → advisory queue
    "stix":      "simulation",  # STIX bundles → adversary simulation
    "misp":      "triage",     # MISP events → triage for relevance scoring
}


# ---------------------------------------------------------------------------
# Redis stream / queue keys
# ---------------------------------------------------------------------------

INBOUND_STREAM = "aegis:events:inbound"
CONSUMER_GROUP = "aegis-orchestrator"
CONSUMER_NAME = "orchestrator-0"

QUEUE_KEYS: dict[str, str] = {
    "triage":     "aegis:queue:triage",
    "detection":  "aegis:queue:detection",
    "simulation": "aegis:queue:simulation",
    "advisory":   "aegis:queue:advisory",
}

# Dead-letter stream for events that fail validation or dispatch
DLQ_STREAM = "aegis:events:dlq"


# ---------------------------------------------------------------------------
# Environment-driven settings
# ---------------------------------------------------------------------------

@dataclass
class Settings:
    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379")
    )
    # How many messages to pull per XREADGROUP call
    batch_size: int = field(
        default_factory=lambda: int(os.getenv("BATCH_SIZE", "10"))
    )
    # Block timeout in ms (0 = indefinite)
    block_ms: int = field(
        default_factory=lambda: int(os.getenv("BLOCK_MS", "5000"))
    )
    # Pending-entry claim timeout (ms) – reclaim stale messages
    claim_min_idle_ms: int = field(
        default_factory=lambda: int(os.getenv("CLAIM_MIN_IDLE_MS", "30000"))
    )
    log_level: str = field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "INFO")
    )


settings = Settings()
