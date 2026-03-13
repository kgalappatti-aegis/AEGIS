"""
AEGIS Triage Agent – Configuration
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Redis stream / queue keys
# ---------------------------------------------------------------------------

TRIAGE_QUEUE_KEY     = "aegis:queue:triage"
SIMULATION_QUEUE_KEY = "aegis:queue:simulation"
ADVISORY_QUEUE_KEY   = "aegis:queue:advisory"

# Consumer group shared with the orchestrator that populated these queues.
CONSUMER_GROUP = "orchestrator-group"

# ---------------------------------------------------------------------------
# Relevance scoring weights  (must sum to 1.0)
# ---------------------------------------------------------------------------

WEIGHTS: dict[str, float] = {
    "infrastructure_match": 0.40,
    "threat_actor_history": 0.25,
    "exploitability":       0.20,
    "temporal_urgency":     0.15,
}

# How many days since CVE publication before temporal urgency falls off
TEMPORAL_URGENCY_WINDOW_DAYS = 7

# ---------------------------------------------------------------------------
# Environment-driven settings
# ---------------------------------------------------------------------------

@dataclass
class TriageSettings:
    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379")
    )
    # Neo4j (optional – score_threat_actor_history falls back to 0.5 when absent)
    neo4j_url:      str = field(default_factory=lambda: os.getenv("NEO4J_URL",      "bolt://neo4j:7687"))
    neo4j_user:     str = field(default_factory=lambda: os.getenv("NEO4J_USER",     "neo4j"))
    neo4j_password: str = field(default_factory=lambda: os.getenv("NEO4J_PASSWORD", ""))
    triage_threshold: float = field(
        default_factory=lambda: float(os.getenv("TRIAGE_THRESHOLD", "0.4"))
    )
    # Consumer identity – override per-replica to avoid competing reads
    consumer_name: str = field(
        default_factory=lambda: os.getenv("TRIAGE_CONSUMER_NAME", "triage-agent-0")
    )
    batch_size: int = field(
        default_factory=lambda: int(os.getenv("BATCH_SIZE", "10"))
    )
    # XREADGROUP block timeout in ms (0 = indefinite)
    block_ms: int = field(
        default_factory=lambda: int(os.getenv("BLOCK_MS", "5000"))
    )
    # XAUTOCLAIM: reclaim messages idle longer than this (ms)
    claim_min_idle_ms: int = field(
        default_factory=lambda: int(os.getenv("CLAIM_MIN_IDLE_MS", "30000"))
    )
    log_level: str = field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "INFO")
    )
    # abuse.ch Auth-Key (free from https://auth.abuse.ch/)
    # Enables ThreatFox IOC + MalwareBazaar hash lookups
    abusech_auth_key: str = field(
        default_factory=lambda: os.getenv("ABUSECH_AUTH_KEY", "")
    )


settings = TriageSettings()
