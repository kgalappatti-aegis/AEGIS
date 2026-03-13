"""
AEGIS MISP Ingestion Agent

Async poll loop that fetches events from a MISP instance via the REST API,
normalizes them to AEGIS event dicts, deduplicates by UUID, and publishes
to ``aegis:events:inbound``.

Lifecycle
---------
1. On startup, read the timestamp cursor from Redis (``aegis:cursor:misp``).
   If absent, seed to ``now - poll_interval``.
2. POST to ``/events/restSearch`` with ``timestamp`` filter for new/updated events.
3. For each event, check UUID-based dedup set (``aegis:misp:seen``).
4. Normalize via ``normalizer.normalize_misp_event()``.
5. XADD to ``aegis:events:inbound``.
6. Persist cursor and sleep until next poll.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone

import httpx
import redis.asyncio as aioredis
from dotenv import load_dotenv

from normalizer import normalize_misp_event, misp_event_dedup_key

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REDIS_URL           = os.getenv("REDIS_URL", "redis://localhost:6379")
MISP_URL            = os.getenv("MISP_URL", "https://localhost")
MISP_API_KEY        = os.getenv("MISP_API_KEY", "")
MISP_VERIFY_SSL     = os.getenv("MISP_VERIFY_SSL", "false").lower() in ("true", "1", "yes")
POLL_INTERVAL       = int(os.getenv("MISP_POLL_INTERVAL_SECONDS", "300"))
MISP_PAGE_LIMIT     = int(os.getenv("MISP_PAGE_LIMIT", "100"))
LOG_LEVEL           = os.getenv("LOG_LEVEL", "INFO")

INBOUND_STREAM      = "aegis:events:inbound"
CURSOR_KEY          = "aegis:cursor:misp"
DEDUP_SET           = "aegis:misp:seen"
DEDUP_TTL           = 7 * 86_400   # 7-day dedup window

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("aegis.misp.agent")


# ---------------------------------------------------------------------------
# Cursor helpers
# ---------------------------------------------------------------------------

async def _read_cursor(r: aioredis.Redis) -> int:
    """Return the Unix timestamp cursor for the MISP poll window."""
    raw = await r.get(CURSOR_KEY)
    if raw:
        ts = raw.decode() if isinstance(raw, bytes) else raw
        try:
            return int(ts)
        except ValueError:
            logger.warning("Unparseable MISP cursor '%s', resetting.", ts)
    # Seed to one interval ago
    seed = int(time.time()) - POLL_INTERVAL
    logger.info("No MISP cursor found. Seeding to %d.", seed)
    return seed


async def _write_cursor(r: aioredis.Redis, ts: int) -> None:
    """Persist the MISP poll cursor (Unix timestamp)."""
    await r.set(CURSOR_KEY, str(ts))


# ---------------------------------------------------------------------------
# MISP API client
# ---------------------------------------------------------------------------

async def _fetch_misp_events(
    client: httpx.AsyncClient,
    timestamp: int,
    page: int = 1,
) -> list[dict]:
    """
    Fetch a page of MISP events updated since ``timestamp``.

    Uses POST to ``/events/restSearch`` which supports complex filters.
    """
    body = {
        "timestamp": str(timestamp),
        "limit": MISP_PAGE_LIMIT,
        "page": page,
        "published": True,
    }
    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    resp = await client.post(
        f"{MISP_URL.rstrip('/')}/events/restSearch",
        json=body,
        headers=headers,
        timeout=30.0,
    )
    resp.raise_for_status()

    data = resp.json()
    # MISP wraps results in {"response": [...]}
    response = data.get("response", [])
    return response


# ---------------------------------------------------------------------------
# Single poll cycle
# ---------------------------------------------------------------------------

async def _poll_once(
    r: aioredis.Redis,
    client: httpx.AsyncClient,
) -> int:
    """
    Fetch MISP events, deduplicate, normalize, publish.
    Returns the number of events published.
    """
    cursor = await _read_cursor(r)
    now_ts = int(time.time())

    published = 0
    page = 1

    while True:
        events = await _fetch_misp_events(client, cursor, page=page)
        if not events:
            break

        pipeline = r.pipeline(transaction=False)

        for misp_event in events:
            # Dedup by MISP UUID
            dedup_key = misp_event_dedup_key(misp_event)
            if not dedup_key:
                logger.debug("Skipping MISP event with no UUID.")
                continue

            # Check if already seen (SISMEMBER is O(1))
            already_seen = await r.sismember(DEDUP_SET, dedup_key)
            if already_seen:
                continue

            try:
                stream_data = normalize_misp_event(misp_event)
            except Exception as exc:
                misp_id = misp_event.get("Event", {}).get("id", "?")
                logger.warning("Skipping MISP event %s – normalization error: %s", misp_id, exc)
                continue

            pipeline.xadd(INBOUND_STREAM, stream_data)
            pipeline.sadd(DEDUP_SET, dedup_key)
            published += 1

            # Flush in batches of 50
            if published % 50 == 0:
                await pipeline.execute()
                pipeline = r.pipeline(transaction=False)

        # Flush remaining
        if published % 50 != 0:
            await pipeline.execute()

        # If we got fewer than the page limit, we've exhausted results
        if len(events) < MISP_PAGE_LIMIT:
            break
        page += 1

    # Expire old dedup entries (trim set to keep memory bounded)
    # We use a key-level TTL on the set — entries older than DEDUP_TTL
    # are pruned by Redis when the key expires and is recreated.
    await r.expire(DEDUP_SET, DEDUP_TTL)

    await _write_cursor(r, now_ts)

    logger.info(
        "MISP poll complete: %d event(s) published. Cursor: %d → %d.",
        published, cursor, now_ts,
    )
    return published


# ---------------------------------------------------------------------------
# Main polling loop
# ---------------------------------------------------------------------------

async def run(shutdown: asyncio.Event) -> None:
    r = aioredis.from_url(
        REDIS_URL,
        encoding="utf-8",
        decode_responses=False,
        socket_keepalive=True,
    )

    logger.info(
        "AEGIS MISP Ingestion Agent started. "
        "Interval: %ds. MISP URL: %s. SSL verify: %s.",
        POLL_INTERVAL, MISP_URL, MISP_VERIFY_SSL,
    )

    async with httpx.AsyncClient(verify=MISP_VERIFY_SSL) as client:
        while not shutdown.is_set():
            try:
                await _poll_once(r, client)
            except httpx.HTTPStatusError as exc:
                logger.error("MISP API error: %s %s", exc.response.status_code, exc.response.text[:200])
            except Exception as exc:
                logger.exception("MISP poll cycle failed: %s", exc)

            try:
                await asyncio.wait_for(
                    shutdown.wait(),
                    timeout=float(POLL_INTERVAL),
                )
            except asyncio.TimeoutError:
                pass

    await r.aclose()
    logger.info("AEGIS MISP Ingestion Agent stopped.")


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
