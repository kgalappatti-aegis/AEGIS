"""
AEGIS Ingestion Agent – NVD Poller

Lifecycle
---------
1. On startup, read the cursor from Redis (``aegis:cursor:nvd``).
   If absent, seed it to ``now - poll_interval`` so the first run catches
   any CVEs published in the last polling window.
2. Fetch all CVEs published between cursor and now via the NVD API.
3. Map each CVE → AEGISEvent (Pydantic model).
4. XADD each event to ``aegis:events:inbound`` (Redis Stream).
5. Persist the new cursor (the ``end`` timestamp used for this batch).
6. Sleep until the next poll interval, then repeat.

CVSS → Priority mapping
-----------------------
  baseScore ≥ 9.0  →  P0  (Critical)
  baseScore ≥ 7.0  →  P1  (High)
  baseScore ≥ 4.0  →  P2  (Medium)
  else             →  P3  (Low / no score)

routing_target is always "triage" for NVD events ingested here.
"""

from __future__ import annotations

import asyncio
import logging
import pathlib
import signal
import sys
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis

# ---------------------------------------------------------------------------
# Resolve the orchestrator package so we can import AEGISEvent directly.
# Supports both repo layouts:
#   AEGIS/ingestion/agent.py  →  AEGIS/orchestrator/schema.py  (monorepo)
#   Stand-alone deployment where PYTHONPATH already contains the schema.
# ---------------------------------------------------------------------------
_INGESTION    = pathlib.Path(__file__).parent
_ORCHESTRATOR = _INGESTION.parent / "orchestrator"
# Ingestion's own directory must come first so its config.py takes precedence
# over orchestrator/config.py when both are on the path.
for _p in (_ORCHESTRATOR, _INGESTION):
    _ps = str(_p)
    if _ps not in sys.path:
        sys.path.insert(0, _ps)
# After the two inserts the list is: [ingestion, orchestrator, ...]

from schema import AEGISEvent  # noqa: E402  (after sys.path manipulation)

from config import (  # noqa: E402
    INBOUND_STREAM,
    NVD_CURSOR_KEY,
    NVD_DATE_FMT,
    settings,
)
from nvd_client import NVDClient  # noqa: E402


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("aegis.ingestion.agent")


# ---------------------------------------------------------------------------
# CVSS → Priority
# ---------------------------------------------------------------------------

def _cvss_priority(cve: dict[str, Any]) -> str:
    """
    Derive AEGIS priority from the highest-available CVSS v3 / v2 base score.

    Preference order: CVSSv3.1 → CVSSv3.0 → CVSSv2.
    Falls back to P3 when no CVSS data is present (e.g. RESERVED CVEs).
    """
    metrics = cve.get("metrics", {})

    score: float | None = None
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_key, [])
        # NVD lists primary source first; prefer type="Primary"
        primary = next(
            (e for e in entries if e.get("type") == "Primary"),
            entries[0] if entries else None,
        )
        if primary:
            score = primary.get("cvssData", {}).get("baseScore")
            break

    if score is None:
        return "P3"
    if score >= 9.0:
        return "P0"
    if score >= 7.0:
        return "P1"
    if score >= 4.0:
        return "P2"
    return "P3"


# ---------------------------------------------------------------------------
# CVE → AEGISEvent
# ---------------------------------------------------------------------------

def _cve_to_event(cve: dict[str, Any]) -> AEGISEvent:
    """Map a raw NVD CVE object to a validated AEGISEvent."""
    priority = _cvss_priority(cve)

    # Extract a concise raw_payload (full object preserved for downstream agents)
    raw_payload: dict[str, Any] = {
        "cve_id":        cve.get("id"),
        "published":     cve.get("published"),
        "lastModified":  cve.get("lastModified"),
        "vulnStatus":    cve.get("vulnStatus"),
        "descriptions":  [
            d for d in cve.get("descriptions", []) if d.get("lang") == "en"
        ],
        "metrics":       cve.get("metrics", {}),
        "weaknesses":    cve.get("weaknesses", []),
        "references":    cve.get("references", []),
        "configurations": cve.get("configurations", []),
    }

    return AEGISEvent(
        source_type="nvd",
        raw_payload=raw_payload,
        priority=priority,
        routing_target="triage",
    )


# ---------------------------------------------------------------------------
# Cursor helpers
# ---------------------------------------------------------------------------

async def _read_cursor(redis: aioredis.Redis, interval: int) -> datetime:
    """
    Return the cursor datetime for the start of this poll window.

    If no cursor exists in Redis (first run), seeds to now − interval so
    the first fetch covers the most recent polling window.
    """
    raw = await redis.get(NVD_CURSOR_KEY)
    if raw:
        ts = raw.decode() if isinstance(raw, bytes) else raw
        try:
            dt = datetime.strptime(ts, NVD_DATE_FMT).replace(tzinfo=timezone.utc)
            logger.debug("Loaded NVD cursor: %s", dt.isoformat())
            return dt
        except ValueError:
            logger.warning("Unparseable cursor '%s', resetting.", ts)

    # No cursor – seed to one interval ago
    from datetime import timedelta
    seed = datetime.now(timezone.utc) - timedelta(seconds=interval)
    logger.info("No cursor found. Seeding to %s.", seed.isoformat())
    return seed


async def _write_cursor(redis: aioredis.Redis, dt: datetime) -> None:
    """Persist the cursor to Redis (no TTL – survives restarts)."""
    await redis.set(NVD_CURSOR_KEY, dt.strftime(NVD_DATE_FMT))
    logger.debug("Cursor updated to %s.", dt.isoformat())


# ---------------------------------------------------------------------------
# Single poll cycle
# ---------------------------------------------------------------------------

async def _poll_once(
    redis: aioredis.Redis,
    nvd: NVDClient,
    interval: int,
) -> int:
    """
    Fetch CVEs for one window, publish to Redis Stream.
    Returns the number of events published.
    """
    start = await _read_cursor(redis, interval)
    end   = datetime.now(timezone.utc)

    if end <= start:
        logger.debug("Clock skew detected (end ≤ start). Skipping poll.")
        return 0

    published = 0
    pipeline  = redis.pipeline(transaction=False)

    async for cve in nvd.cves_published_between(start, end):
        try:
            event = _cve_to_event(cve)
        except Exception as exc:  # noqa: BLE001
            cve_id = cve.get("id", "<unknown>")
            logger.warning("Skipping CVE %s – mapping error: %s", cve_id, exc)
            continue

        stream_data = event.to_redis_stream()
        pipeline.xadd(INBOUND_STREAM, stream_data)
        published += 1

        # Flush in batches of 100 to avoid huge pipeline buffers
        if published % 100 == 0:
            await pipeline.execute()
            pipeline = redis.pipeline(transaction=False)
            logger.debug("Flushed 100 events to stream.")

    if published % 100 != 0:
        await pipeline.execute()

    await _write_cursor(redis, end)

    logger.info(
        "Poll complete: %d CVE(s) published to '%s'. Window: %s → %s.",
        published,
        INBOUND_STREAM,
        start.strftime(NVD_DATE_FMT),
        end.strftime(NVD_DATE_FMT),
    )
    return published


# ---------------------------------------------------------------------------
# Main polling loop
# ---------------------------------------------------------------------------

async def run(shutdown: asyncio.Event) -> None:
    interval = settings.poll_interval_seconds

    redis = aioredis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=False,
        socket_keepalive=True,
    )

    logger.info(
        "AEGIS NVD Ingestion Agent started. "
        "Interval: %ds. API key: %s. Redis: %s.",
        interval,
        "present" if settings.nvd_api_key else "absent (anon rate limit)",
        settings.redis_url,
    )

    async with NVDClient(settings) as nvd:
        while not shutdown.is_set():
            try:
                await _poll_once(redis, nvd, interval)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Poll cycle failed: %s", exc)

            # Wait for the next interval or until a shutdown signal
            try:
                await asyncio.wait_for(
                    shutdown.wait(),
                    timeout=float(interval),
                )
            except asyncio.TimeoutError:
                pass  # Normal – time to poll again

    await redis.aclose()
    logger.info("AEGIS NVD Ingestion Agent stopped.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    shutdown = asyncio.Event()

    def _handle_signal(sig: signal.Signals) -> None:
        logger.info("Received %s – shutting down gracefully…", sig.name)
        shutdown.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal, sig)

    await run(shutdown)


if __name__ == "__main__":
    asyncio.run(main())
