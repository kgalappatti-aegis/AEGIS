"""
AEGIS Dashboard – API Server

Endpoints
---------
GET  /api/events         Recent events from aegis:events:inbound (XREVRANGE)
GET  /api/stats          Priority / routing / queue-depth aggregates
GET  /api/events/stream  SSE: push each new inbound event to all viewers
GET  /                   Serves the static dashboard (index.html)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import redis.asyncio as aioredis
from dotenv import load_dotenv
from fastapi import FastAPI, Query, Request
from fastapi.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REDIS_URL        = os.getenv("REDIS_URL", "redis://localhost:6379")
INBOUND_STREAM   = "aegis:events:inbound"
SIMULATION_QUEUE = "aegis:queue:simulation"
ADVISORY_QUEUE   = "aegis:queue:advisory"
TRIAGE_QUEUE     = "aegis:queue:triage"

STATS_SAMPLE     = int(os.getenv("STATS_SAMPLE", "2000"))  # events to scan for stats

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s – %(message)s")
logger = logging.getLogger("aegis.dashboard")

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

_redis: aioredis.Redis | None = None

# Fan-out SSE broadcast: one asyncio.Queue per connected viewer
_subscribers: list[asyncio.Queue[dict]] = []


def _broadcast(event: dict) -> None:
    for q in _subscribers:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass  # slow viewer — drop rather than block the watcher


# ---------------------------------------------------------------------------
# Background stream watcher
# ---------------------------------------------------------------------------

async def _watch_inbound() -> None:
    """Tail aegis:events:inbound and broadcast each new event to SSE clients."""
    assert _redis is not None
    last_id = "$"   # only new events from this point forward
    while True:
        try:
            results = await _redis.xread({INBOUND_STREAM: last_id}, block=2000, count=20)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Stream watcher error: %s", exc)
            await asyncio.sleep(2)
            continue

        if not results:
            continue

        for _stream, messages in results:
            for raw_id, raw_fields in messages:
                last_id = raw_id.decode() if isinstance(raw_id, bytes) else raw_id
                event = _decode_event(raw_id, raw_fields)
                if _subscribers:
                    _broadcast(event)


# ---------------------------------------------------------------------------
# Redis field helpers
# ---------------------------------------------------------------------------

def _decode_event(raw_id: bytes | str, raw_fields: dict) -> dict[str, Any]:
    """Flatten raw Redis bytes into a JSON-serialisable dict."""
    decoded: dict[str, Any] = {
        (k.decode() if isinstance(k, bytes) else k): (
            v.decode() if isinstance(v, bytes) else v
        )
        for k, v in raw_fields.items()
    }

    # Extract stream entry ID as a readable timestamp
    sid = raw_id.decode() if isinstance(raw_id, bytes) else str(raw_id)
    decoded["stream_id"] = sid

    # Pull CVE ID out of raw_payload for display without deserialising everything
    raw_payload_str = decoded.get("raw_payload", "{}")
    try:
        payload = json.loads(raw_payload_str)
        decoded["cve_id"] = payload.get("cve_id")
        decoded["vuln_status"] = payload.get("vulnStatus")
        # Pull top-level English description
        descriptions = payload.get("descriptions", [])
        en = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)
        decoded["description"] = (en[:120] + "…") if en and len(en) > 120 else en
    except (json.JSONDecodeError, TypeError):
        decoded["cve_id"] = None
        decoded["description"] = None
        decoded["vuln_status"] = None

    # Remove raw_payload – not needed by the frontend and can be large
    decoded.pop("raw_payload", None)

    # Coerce numeric fields
    for key in ("ttl", "relevance_score", "infrastructure_match",
                "threat_actor_history", "exploitability", "temporal_urgency"):
        if key in decoded:
            try:
                decoded[key] = float(decoded[key])
            except (ValueError, TypeError):
                decoded[key] = None

    return decoded


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    global _redis
    _redis = aioredis.from_url(
        REDIS_URL,
        encoding="utf-8",
        decode_responses=False,
        socket_keepalive=True,
    )
    watcher = asyncio.create_task(_watch_inbound())
    logger.info("AEGIS Dashboard started. Redis: %s", REDIS_URL)
    try:
        yield
    finally:
        watcher.cancel()
        await _redis.aclose()
        logger.info("Dashboard stopped.")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="AEGIS Dashboard", lifespan=lifespan)


# ---------------------------------------------------------------------------
# API routes  (must be registered before the static file catch-all)
# ---------------------------------------------------------------------------

@app.get("/api/events")
async def get_events(limit: int = Query(default=100, le=500)) -> list[dict]:
    """Return the most recent *limit* events from the inbound stream."""
    assert _redis is not None
    raw = await _redis.xrevrange(INBOUND_STREAM, count=limit)
    return [_decode_event(raw_id, fields) for raw_id, fields in raw]


@app.get("/api/stats")
async def get_stats() -> dict[str, Any]:
    """
    Aggregated stats built from a recent sample of the inbound stream plus
    live queue depths.  Designed for a 10-second polling interval.
    """
    assert _redis is not None

    # Totals
    total_ingested = await _redis.xlen(INBOUND_STREAM)

    # Queue depths
    queue_depths = {
        "triage":     await _redis.xlen(TRIAGE_QUEUE),
        "simulation": await _redis.xlen(SIMULATION_QUEUE),
        "advisory":   await _redis.xlen(ADVISORY_QUEUE),
    }

    # Priority / routing distribution – sampled from recent events
    by_priority: dict[str, int] = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    by_routing:  dict[str, int] = {}
    relevance_scores: list[float] = []

    sample = await _redis.xrevrange(INBOUND_STREAM, count=STATS_SAMPLE)
    for _raw_id, fields in sample:
        f = {
            (k.decode() if isinstance(k, bytes) else k): (
                v.decode() if isinstance(v, bytes) else v
            )
            for k, v in fields.items()
        }
        p = f.get("priority")
        if p in by_priority:
            by_priority[p] += 1

        r = f.get("routing_target")
        if r:
            by_routing[r] = by_routing.get(r, 0) + 1

    # Relevance scores come from triaged events (simulation + advisory queues)
    for queue in (SIMULATION_QUEUE, ADVISORY_QUEUE):
        triaged = await _redis.xrevrange(queue, count=200)
        for _raw_id, fields in triaged:
            f = {
                (k.decode() if isinstance(k, bytes) else k): (
                    v.decode() if isinstance(v, bytes) else v
                )
                for k, v in fields.items()
            }
            rs = f.get("relevance_score")
            if rs:
                try:
                    relevance_scores.append(float(rs))
                except ValueError:
                    pass

    avg_relevance = (
        round(sum(relevance_scores) / len(relevance_scores), 3)
        if relevance_scores else None
    )

    return {
        "total_ingested": total_ingested,
        "by_priority":    by_priority,
        "by_routing":     by_routing,
        "avg_relevance":  avg_relevance,
        "triaged_count":  len(relevance_scores),
        "queue_depths":   queue_depths,
    }


@app.get("/api/events/stream")
async def events_stream(request: Request) -> EventSourceResponse:
    """SSE endpoint – pushes each new inbound event to connected viewers."""
    q: asyncio.Queue[dict] = asyncio.Queue(maxsize=200)
    _subscribers.append(q)

    async def generator() -> AsyncIterator[dict]:
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15)
                    yield {"data": json.dumps(event)}
                except asyncio.TimeoutError:
                    yield {"comment": "keepalive"}  # prevents proxy timeouts
        finally:
            try:
                _subscribers.remove(q)
            except ValueError:
                pass

    return EventSourceResponse(generator())


# ---------------------------------------------------------------------------
# Static files — registered last so /api/* routes take precedence
# ---------------------------------------------------------------------------

app.mount("/", StaticFiles(directory="static", html=True), name="static")
