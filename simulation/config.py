"""
AEGIS Simulation Agent – Configuration
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Redis stream keys
# ---------------------------------------------------------------------------

SIMULATION_QUEUE  = "aegis:queue:simulation"
DETECTION_QUEUE   = "aegis:queue:detection"
BROADCAST_CHANNEL = "aegis:broadcast"
CONSUMER_GROUP    = "orchestrator-group"

# ---------------------------------------------------------------------------
# Monte Carlo constants
# ---------------------------------------------------------------------------

DETECTION_PENALTY    = 0.15   # P(blocked per detected TTP step)
BETA_ALPHA_PRIOR     = 2.0    # Beta distribution shape prior
BETA_BETA_PRIOR      = 2.0
BETA_EFFECTIVE_N     = 8.0    # effective observations used to set Beta params
DETECTION_COVERAGE_STUB = 0.5 # Phase 3 stub; Phase 4 uses real coverage data
MAX_PATHS_PER_TASK   = 20     # cap to keep task duration predictable

# ---------------------------------------------------------------------------
# Valid strategy names
# ---------------------------------------------------------------------------

ALL_STRATEGIES = frozenset({
    "shortest_path",
    "evasion_first",
    "vuln_amplified",
    "lateral_movement",
    "full_landscape",
})

# TTPs whose tactic is Lateral Movement (used by lateral_movement strategy)
LATERAL_MOVEMENT_TTPS = frozenset({
    "T1021.001", "T1021.002", "T1021.006",
    "T1550.002", "T1550.003",
    "T1080", "T1210",
})

# ---------------------------------------------------------------------------
# Environment-driven settings
# ---------------------------------------------------------------------------

def _celery_url(base: str, db: int) -> str:
    """Append a Redis DB index to a URL that has none."""
    stripped = base.rstrip("/")
    # If the path segment already looks like a number, don't add another
    if stripped.split("/")[-1].isdigit():
        return stripped
    return f"{stripped}/{db}"


@dataclass
class SimulationSettings:
    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379")
    )
    neo4j_url: str = field(
        default_factory=lambda: os.getenv("NEO4J_URL", "bolt://localhost:7687")
    )
    neo4j_user: str = field(
        default_factory=lambda: os.getenv("NEO4J_USER", "neo4j")
    )
    neo4j_password: str = field(
        default_factory=lambda: os.getenv("NEO4J_PASSWORD", "")
    )
    anthropic_api_key: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", "")
    )
    sim_threshold: float = field(
        default_factory=lambda: float(os.getenv("SIM_THRESHOLD", "0.55"))
    )
    celery_concurrency: int = field(
        default_factory=lambda: int(os.getenv("CELERY_CONCURRENCY", "4"))
    )
    consumer_name: str = field(
        default_factory=lambda: os.getenv("SIM_CONSUMER_NAME", "simulation-agent-0")
    )
    batch_size: int = field(
        default_factory=lambda: int(os.getenv("BATCH_SIZE", "5"))
    )
    block_ms: int = field(
        default_factory=lambda: int(os.getenv("BLOCK_MS", "5000"))
    )
    claim_min_idle_ms: int = field(
        default_factory=lambda: int(os.getenv("CLAIM_MIN_IDLE_MS", "60000"))
    )
    log_level: str = field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "INFO")
    )

    @property
    def celery_broker_url(self) -> str:
        return os.getenv("CELERY_BROKER_URL", _celery_url(self.redis_url, 1))

    @property
    def celery_backend_url(self) -> str:
        return os.getenv("CELERY_BACKEND_URL", _celery_url(self.redis_url, 2))


settings = SimulationSettings()
