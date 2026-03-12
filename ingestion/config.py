"""
AEGIS Ingestion – Configuration
All settings are driven by environment variables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Redis keys
# ---------------------------------------------------------------------------

NVD_CURSOR_KEY  = "aegis:cursor:nvd"    # ISO-8601 UTC string of last poll end
INBOUND_STREAM  = "aegis:events:inbound"

# ---------------------------------------------------------------------------
# NVD API
# ---------------------------------------------------------------------------

NVD_BASE_URL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DATE_FMT    = "%Y-%m-%dT%H:%M:%S.000"   # NVD v2 query param format (UTC)

# Rate-limit windows (requests per 30-second rolling window)
NVD_RATE_ANON   = 5
NVD_RATE_KEYED  = 50
NVD_RATE_WINDOW = 30.0   # seconds

# Exponential backoff: sleep = min(BASE * 2^attempt, MAX) ± JITTER fraction
BACKOFF_BASE_S  = 2.0
BACKOFF_MAX_S   = 60.0
BACKOFF_JITTER  = 0.2   # ±20 %

# ---------------------------------------------------------------------------
# Settings dataclass
# ---------------------------------------------------------------------------

@dataclass
class IngestionSettings:
    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379")
    )
    nvd_api_key: str | None = field(
        default_factory=lambda: os.getenv("NVD_API_KEY")
    )
    poll_interval_seconds: int = field(
        default_factory=lambda: int(os.getenv("POLL_INTERVAL_SECONDS", "300"))
    )
    log_level: str = field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "INFO")
    )
    # Maximum CVEs per page – NVD caps at 2 000; lower values ease memory
    nvd_results_per_page: int = field(
        default_factory=lambda: int(os.getenv("NVD_RESULTS_PER_PAGE", "2000"))
    )


settings = IngestionSettings()
