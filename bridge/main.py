"""
AEGIS WebSocket Bridge

Background tasks push data to all connected WebSocket clients:

  _tail_inbound_loop    – XREAD-tails aegis:events:inbound and emits
                          type:"ingestion" messages for the Ingestion tab.

  _tail_detection_loop  – XREAD-tails aegis:queue:detection and emits
                          type:"event" messages with stage:"detected".

  _subscribe_loop       – SUBSCRIBEs to aegis:broadcast pub/sub and emits
                          type:"advisory" messages published by the advisory
                          agent.

All tasks normalise their output into the envelope the UI expects:
  { "type": "event"|"advisory"|"ingestion", "payload": {...}, "ts": <epoch ms> }

Endpoints
---------
GET  /ws                    WebSocket — live event + advisory + ingestion push
GET  /api/events/inbound    Recent inbound events (XREVRANGE)
GET  /api/attack-matrix     TTP hit counts
GET  /api/simulation/:id    Simulation finding
GET  /healthz               Liveness probe
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

import asyncpg
import redis.asyncio as aioredis
from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REDIS_URL         = os.getenv("REDIS_URL", "redis://localhost:6379")
DATABASE_URL      = os.getenv("DATABASE_URL", "postgresql://aegis:aegis@localhost:5432/aegis")
INBOUND_STREAM    = "aegis:events:inbound"
DETECTION_QUEUE   = "aegis:queue:detection"
TRIAGE_QUEUE      = "aegis:queue:triage"
SIMULATION_QUEUE  = "aegis:queue:simulation"
ADVISORY_QUEUE    = "aegis:queue:advisory"
ADVISORY_STREAM   = "aegis:stream:advisories"
BROADCAST_CHANNEL = "aegis:broadcast"
CATCHUP_LIMIT     = int(os.getenv("STATS_SAMPLE", "200"))
STATS_INTERVAL_S  = 10
LOG_LEVEL         = os.getenv("LOG_LEVEL", "INFO")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("aegis.bridge")


# ---------------------------------------------------------------------------
# Connection registry
# ---------------------------------------------------------------------------

class _ConnectionManager:
    """Asyncio-safe set of active WebSocket connections."""

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.add(ws)
        logger.info("WebSocket connected. Total: %d", len(self._connections))

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.discard(ws)
        logger.info("WebSocket disconnected. Total: %d", len(self._connections))

    async def broadcast(self, message: str) -> None:
        """Send *message* to all clients; silently prune dead sockets."""
        dead: list[WebSocket] = []
        for ws in list(self._connections):
            try:
                await ws.send_text(message)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        for ws in dead:
            self._connections.discard(ws)

    @property
    def count(self) -> int:
        return len(self._connections)


manager = _ConnectionManager()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_ms() -> int:
    return int(time.time() * 1000)


def _decode(raw: dict[bytes | str, bytes | str]) -> dict[str, str]:
    return {
        (k.decode() if isinstance(k, bytes) else k): (
            v.decode() if isinstance(v, bytes) else v
        )
        for k, v in raw.items()
    }


def _envelope(msg_type: str, payload: dict) -> str:
    return json.dumps({"type": msg_type, "payload": payload, "ts": _now_ms()})


# ---------------------------------------------------------------------------
# Task 0: tail aegis:events:inbound (Ingestion tab)
# ---------------------------------------------------------------------------

def _decode_inbound_event(raw_id: bytes | str, raw_fields: dict) -> dict:
    """Flatten raw inbound event into a JSON-serialisable dict for the UI."""
    decoded: dict[str, str] = _decode(raw_fields)

    sid = raw_id.decode() if isinstance(raw_id, bytes) else str(raw_id)
    decoded["stream_id"] = sid

    raw_payload_str = decoded.get("raw_payload", "{}")
    try:
        payload = json.loads(raw_payload_str)
        decoded["cve_id"] = payload.get("cve_id") or payload.get("id")
        decoded["vuln_status"] = payload.get("vulnStatus")
        descriptions = payload.get("descriptions", [])
        en = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)
        decoded["description"] = (en[:120] + "…") if en and len(en) > 120 else en
        # MISP events
        if not decoded.get("description") and payload.get("info"):
            decoded["description"] = str(payload["info"])[:120]
    except (json.JSONDecodeError, TypeError):
        decoded["cve_id"] = None
        decoded["description"] = None
        decoded["vuln_status"] = None

    decoded.pop("raw_payload", None)

    for key in ("relevance_score", "infrastructure_match",
                "exploitability", "temporal_urgency"):
        if key in decoded:
            try:
                decoded[key] = float(decoded[key])
            except (ValueError, TypeError):
                decoded[key] = None

    return decoded


async def _tail_inbound_loop(redis: aioredis.Redis) -> None:
    """
    XREAD-tail ``aegis:events:inbound`` and push each new entry to all
    WebSocket clients as a type:"ingestion" message for the Ingestion tab.
    """
    last_id = "$"
    logger.info("Inbound tail started. Stream: '%s'", INBOUND_STREAM)

    try:
        while True:
            try:
                results = await redis.xread(
                    {INBOUND_STREAM: last_id}, block=2_000, count=20
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("XREAD error on inbound stream: %s", exc)
                await asyncio.sleep(2)
                continue

            if not results:
                continue

            for _stream, messages in results:
                for raw_id, raw_fields in messages:
                    last_id = raw_id.decode() if isinstance(raw_id, bytes) else raw_id
                    payload = _decode_inbound_event(raw_id, raw_fields)

                    msg = _envelope("ingestion", payload)
                    if manager.count:
                        await manager.broadcast(msg)
                        logger.debug(
                            "Pushed inbound event %s to %d client(s).",
                            payload.get("event_id", "?"), manager.count,
                        )

    except asyncio.CancelledError:
        pass
    finally:
        logger.info("Inbound tail stopped.")


# ---------------------------------------------------------------------------
# Task 1: tail aegis:queue:detection
# ---------------------------------------------------------------------------

async def _tail_detection_loop(redis: aioredis.Redis) -> None:
    """
    XREAD-tail ``aegis:queue:detection`` from the current tip and push each
    new entry to all WebSocket clients as a type:"event" message.

    Fields forwarded (subset — raw_payload is excluded to keep payloads
    small; cve_id is extracted from it):
        event_id, source_type, priority, stage="detected",
        routing_target, ingested_at, relevance_score,
        infrastructure_match, exploitability, temporal_urgency,
        p_breach, delta_p_breach, severity, summary,
        highest_risk_path, blind_spots, simulated_at, cve_id
    """
    last_id = "$"  # only new messages from this point forward
    logger.info("Detection tail started. Stream: '%s'", DETECTION_QUEUE)

    try:
        while True:
            try:
                results = await redis.xread(
                    {DETECTION_QUEUE: last_id}, block=2_000, count=20
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("XREAD error on detection queue: %s", exc)
                await asyncio.sleep(2)
                continue

            if not results:
                continue

            for _stream, messages in results:
                for raw_id, raw_fields in messages:
                    last_id = raw_id.decode() if isinstance(raw_id, bytes) else raw_id
                    fields  = _decode(raw_fields)

                    # Extract cve_id from the embedded raw_payload JSON
                    cve_id: str | None = None
                    raw_payload_str = fields.get("raw_payload", "{}")
                    try:
                        rp     = json.loads(raw_payload_str)
                        cve_id = rp.get("id") or rp.get("cve_id")
                    except (json.JSONDecodeError, TypeError):
                        pass

                    payload = {
                        "event_id":             fields.get("event_id",    ""),
                        "source_type":          fields.get("source_type", ""),
                        "priority":             fields.get("priority",    "P3"),
                        "stage":                "detected",
                        "routing_target":       fields.get("routing_target", "detection"),
                        "ingested_at":          fields.get("ingested_at",  ""),
                        "simulated_at":         fields.get("simulated_at", ""),
                        "relevance_score":      fields.get("relevance_score"),
                        "infrastructure_match": fields.get("infrastructure_match"),
                        "exploitability":       fields.get("exploitability"),
                        "temporal_urgency":     fields.get("temporal_urgency"),
                        "p_breach":             fields.get("p_breach"),
                        "delta_p_breach":       fields.get("delta_p_breach"),
                        "severity":             fields.get("severity",  "medium"),
                        "summary":              fields.get("summary",   ""),
                        "cve_id":               cve_id,
                        # Keep list fields as parsed JSON so the UI can render them
                        "highest_risk_path":    _try_json(fields.get("highest_risk_path", "[]")),
                        "blind_spots":          _try_json(fields.get("blind_spots",        "[]")),
                    }

                    msg = _envelope("event", payload)
                    if manager.count:
                        await manager.broadcast(msg)
                        logger.debug(
                            "Pushed detection event %s to %d client(s).",
                            fields.get("event_id", "?"), manager.count,
                        )

    except asyncio.CancelledError:
        pass
    finally:
        logger.info("Detection tail stopped.")


def _try_json(s: str):
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return []


# ---------------------------------------------------------------------------
# Task 2: subscribe to aegis:broadcast (advisory pub/sub)
# ---------------------------------------------------------------------------

async def _subscribe_loop(redis: aioredis.Redis) -> None:
    """
    Subscribe to ``aegis:broadcast`` and fan out each advisory to all
    connected WebSocket clients.

    The advisory agent publishes a flat JSON object with a "type" key.
    This function normalises it into the standard envelope:
      { "type": "advisory", "payload": {...}, "ts": <epoch ms> }
    """
    pubsub = redis.pubsub()
    await pubsub.subscribe(BROADCAST_CHANNEL)
    logger.info("Subscribed to Redis channel '%s'.", BROADCAST_CHANNEL)

    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue

            raw  = message["data"]
            text = raw.decode() if isinstance(raw, bytes) else str(raw)

            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                logger.warning("Non-JSON on broadcast channel — skipped.")
                continue

            # Normalise into the { type, payload, ts } envelope.
            # The advisory agent already sets "type": "advisory" at the root;
            # move everything except "type" into payload.
            msg_type = data.pop("type", "advisory")
            msg      = _envelope(msg_type, data)

            if manager.count:
                await manager.broadcast(msg)
                logger.debug(
                    "Broadcast %s to %d client(s).", msg_type, manager.count
                )

    except asyncio.CancelledError:
        pass
    finally:
        await pubsub.unsubscribe(BROADCAST_CHANNEL)
        await pubsub.aclose()
        logger.info("Pub/sub listener stopped.")


# ---------------------------------------------------------------------------
# Task 3: periodic stats broadcast
# ---------------------------------------------------------------------------

async def _stats_loop(redis: aioredis.Redis) -> None:
    """
    Every STATS_INTERVAL_S seconds, compute pipeline stats from Redis
    and broadcast a type:"stats" message to all WebSocket clients.
    """
    logger.info("Stats loop started (interval=%ds).", STATS_INTERVAL_S)
    try:
        while True:
            await asyncio.sleep(STATS_INTERVAL_S)
            if not manager.count:
                continue

            try:
                total_ingested = await redis.xlen(INBOUND_STREAM)

                triage_depth = await redis.xlen(TRIAGE_QUEUE)
                sim_depth    = await redis.xlen(SIMULATION_QUEUE)
                adv_depth    = await redis.xlen(ADVISORY_QUEUE)

                # Sample recent inbound events for priority distribution
                by_priority = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
                by_routing: dict[str, int] = {}
                relevance_scores = []

                sample = await redis.xrevrange(INBOUND_STREAM, count=2000)
                for _raw_id, fields in (sample or []):
                    f = _decode(fields)
                    p = f.get("priority")
                    if p in by_priority:
                        by_priority[p] += 1
                    r = f.get("routing_target")
                    if r:
                        by_routing[r] = by_routing.get(r, 0) + 1

                # Relevance scores from triaged events
                for queue in (SIMULATION_QUEUE, ADVISORY_QUEUE):
                    triaged = await redis.xrevrange(queue, count=200)
                    for _raw_id, fields in (triaged or []):
                        f = _decode(fields)
                        rs = f.get("relevance_score")
                        if rs:
                            try:
                                relevance_scores.append(float(rs))
                            except (ValueError, TypeError):
                                pass

                avg_relevance = (
                    round(sum(relevance_scores) / len(relevance_scores), 3)
                    if relevance_scores else None
                )

                payload = {
                    "total_ingested": total_ingested,
                    "by_priority":    by_priority,
                    "by_routing":     by_routing,
                    "avg_relevance":  avg_relevance,
                    "triaged_count":  len(relevance_scores),
                    "queue_depths": {
                        "triage":     triage_depth,
                        "simulation": sim_depth,
                        "advisory":   adv_depth,
                    },
                }

                await manager.broadcast(_envelope("stats", payload))

            except Exception as exc:  # noqa: BLE001
                logger.warning("Stats computation failed: %s", exc)

    except asyncio.CancelledError:
        pass
    finally:
        logger.info("Stats loop stopped.")


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Separate Redis connections: pub/sub requires a dedicated connection;
    # the stream-tail connection is used for regular XREAD commands.
    # A third connection (decode_responses=True) serves the REST API endpoints.
    redis_stream = aioredis.from_url(
        REDIS_URL,
        encoding="utf-8",
        decode_responses=False,
        socket_keepalive=True,
    )
    redis_pubsub = aioredis.from_url(
        REDIS_URL,
        encoding="utf-8",
        decode_responses=False,
        socket_keepalive=True,
    )
    redis_api = aioredis.from_url(
        REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
        socket_keepalive=True,
    )
    app.state.redis_api = redis_api

    # PostgreSQL pool for advisory/finding fallback queries
    try:
        db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=3)
        logger.info("PostgreSQL pool created: %s", DATABASE_URL.split("@")[-1])
    except Exception as exc:
        logger.warning("PostgreSQL unavailable (%s) — finding fallback disabled.", exc)
        db_pool = None
    app.state.db_pool = db_pool

    # Inbound tail needs its own connection (it blocks on XREAD independently)
    redis_inbound = aioredis.from_url(
        REDIS_URL,
        encoding="utf-8",
        decode_responses=False,
        socket_keepalive=True,
    )

    inbound_task   = asyncio.create_task(_tail_inbound_loop(redis_inbound))
    tail_task      = asyncio.create_task(_tail_detection_loop(redis_stream))
    subscribe_task = asyncio.create_task(_subscribe_loop(redis_pubsub))
    stats_task     = asyncio.create_task(_stats_loop(redis_stream))

    logger.info("AEGIS WebSocket Bridge started. Redis: %s", REDIS_URL)
    try:
        yield
    finally:
        inbound_task.cancel()
        tail_task.cancel()
        subscribe_task.cancel()
        stats_task.cancel()
        await asyncio.gather(inbound_task, tail_task, subscribe_task, stats_task, return_exceptions=True)
        await redis_inbound.aclose()
        await redis_stream.aclose()
        await redis_pubsub.aclose()
        await redis_api.aclose()
        if db_pool:
            await db_pool.close()
        logger.info("Bridge stopped.")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="AEGIS WebSocket Bridge", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    """
    Hold each WebSocket connection open.  On connect, replay recent events
    and advisories so the UI shows historical data immediately.
    """
    await manager.connect(ws)
    try:
        # Send catchup batch of recent events + advisories
        r: aioredis.Redis = app.state.redis_api
        await _send_catchup(ws, r)

        while True:
            await ws.receive_text()   # keepalive / client ping
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(ws)


async def _send_catchup(ws: WebSocket, redis: aioredis.Redis) -> None:
    """
    Replay recent events from the detection stream and advisories from
    the persistent advisory stream so a newly connected UI has context.
    """
    try:
        # Recent inbound events (for Ingestion tab)
        raw_inbound = await redis.xrevrange(
            INBOUND_STREAM, count=CATCHUP_LIMIT,
        )
        inbound = list(reversed(raw_inbound or []))

        for raw_id, raw_fields in inbound:
            payload = _decode_inbound_event(raw_id, raw_fields)
            await ws.send_text(_envelope("ingestion", payload))

        # Recent detection events (newest first, reversed to chronological)
        raw_events = await redis.xrevrange(
            DETECTION_QUEUE, count=CATCHUP_LIMIT,
        )
        events = list(reversed(raw_events or []))

        for raw_id, raw_fields in events:
            fields = _decode(raw_fields)
            cve_id: str | None = None
            try:
                rp = json.loads(fields.get("raw_payload", "{}"))
                cve_id = rp.get("id") or rp.get("cve_id")
            except (json.JSONDecodeError, TypeError):
                pass

            payload = {
                "event_id":             fields.get("event_id",    ""),
                "source_type":          fields.get("source_type", ""),
                "priority":             fields.get("priority",    "P3"),
                "stage":                "detected",
                "routing_target":       fields.get("routing_target", "detection"),
                "ingested_at":          fields.get("ingested_at",  ""),
                "simulated_at":         fields.get("simulated_at", ""),
                "relevance_score":      fields.get("relevance_score"),
                "infrastructure_match": fields.get("infrastructure_match"),
                "exploitability":       fields.get("exploitability"),
                "temporal_urgency":     fields.get("temporal_urgency"),
                "p_breach":             fields.get("p_breach"),
                "delta_p_breach":       fields.get("delta_p_breach"),
                "severity":             fields.get("severity",  "medium"),
                "summary":              fields.get("summary",   ""),
                "cve_id":               cve_id,
                "highest_risk_path":    _try_json(fields.get("highest_risk_path", "[]")),
                "blind_spots":          _try_json(fields.get("blind_spots",        "[]")),
            }
            await ws.send_text(_envelope("event", payload))

        # Recent advisories from persistent stream
        raw_advisories = await redis.xrevrange(
            ADVISORY_STREAM, count=CATCHUP_LIMIT,
        )
        advisories = list(reversed(raw_advisories or []))

        for raw_id, raw_fields in advisories:
            fields = _decode(raw_fields)
            data_str = fields.get("data", "{}")
            try:
                data = json.loads(data_str)
            except (json.JSONDecodeError, TypeError):
                continue
            msg_type = data.pop("type", "advisory")
            await ws.send_text(_envelope(msg_type, data))

        # Send cached event stages for the ingestion tab
        stages = await redis.hgetall("aegis:event:stages")
        if stages:
            await ws.send_text(_envelope("stages", stages))

        logger.info(
            "Catchup sent: %d inbound, %d detection events, %d advisories, %d stages to new client.",
            len(inbound), len(events), len(advisories), len(stages),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Catchup failed: %s — client will only see live data.", exc)


# ---------------------------------------------------------------------------
# REST API endpoints
# ---------------------------------------------------------------------------

@app.get("/api/events/inbound")
async def get_inbound_events(limit: int = 200) -> list[dict]:
    """Return the most recent *limit* events from the inbound stream."""
    r: aioredis.Redis = app.state.redis_api
    raw = await r.xrevrange(INBOUND_STREAM, count=min(limit, 500))
    results = []
    for raw_id, raw_fields in (raw or []):
        # redis_api has decode_responses=True, so keys/values are already str
        fields = dict(raw_fields)
        sid = raw_id if isinstance(raw_id, str) else raw_id.decode()
        fields["stream_id"] = sid

        raw_payload_str = fields.get("raw_payload", "{}")
        try:
            payload = json.loads(raw_payload_str)
            fields["cve_id"] = payload.get("cve_id") or payload.get("id")
            fields["vuln_status"] = payload.get("vulnStatus")
            descriptions = payload.get("descriptions", [])
            en = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)
            fields["description"] = (en[:120] + "…") if en and len(en) > 120 else en
            if not fields.get("description") and payload.get("info"):
                fields["description"] = str(payload["info"])[:120]
        except (json.JSONDecodeError, TypeError):
            fields["cve_id"] = None
            fields["description"] = None
            fields["vuln_status"] = None

        fields.pop("raw_payload", None)
        results.append(fields)

    return results


@app.get("/api/attack-matrix")
async def attack_matrix() -> dict:
    """
    Return TTP hit counts and priority data aggregated from Redis.

    Redis hashes written by the Simulation Agent:
      aegis:ttp:hits       { "T1190": "12", ... }
      aegis:ttp:priority   { "T1190": "P0", ... }
      aegis:ttp:actors     { "T1190": "APT29,Volt Typhoon", ... }
      aegis:ttp:updated_at  (plain key, ISO timestamp)
    """
    r: aioredis.Redis = app.state.redis_api

    (hits_raw, priority_raw, actors_raw, names_raw,
     tactics_raw, platforms_raw, updated_at, infra_profile) = (
        await asyncio.gather(
            r.hgetall("aegis:ttp:hits"),
            r.hgetall("aegis:ttp:priority"),
            r.hgetall("aegis:ttp:actors"),
            r.hgetall("aegis:ttp:name"),
            r.hgetall("aegis:ttp:tactic"),
            r.hgetall("aegis:ttp:platforms"),
            r.get("aegis:ttp:updated_at"),
            r.smembers("aegis:infra:platforms"),
        )
    )

    techniques: dict[str, dict] = {}
    all_ids = (set(hits_raw) | set(priority_raw) | set(actors_raw)
               | set(names_raw) | set(tactics_raw) | set(platforms_raw))
    for tid in all_ids:
        hit_val = hits_raw.get(tid)
        plat_str = platforms_raw.get(tid, "")
        techniques[tid] = {
            "hits": int(hit_val) if hit_val else 0,
            "maxPriority": priority_raw.get(tid) or None,
            "actors": [
                a.strip()
                for a in (actors_raw.get(tid, "")).split(",")
                if a.strip()
            ],
            "name": names_raw.get(tid) or None,
            "tactic": tactics_raw.get(tid) or None,
            "platforms": [p.strip() for p in plat_str.split(",") if p.strip()] if plat_str else [],
        }

    return {
        "techniques": techniques,
        "lastUpdated": updated_at or None,
        "infraProfile": sorted(infra_profile) if infra_profile else [],
    }


# Expected finding shape stored at aegis:sim:findings:{event_id}:
# {
#   "event_id": "EVT-1247",
#   "cve": "CVE-2026-1337",
#   "title": "...",
#   "actor": "APT29",
#   "strategy": "evasion_first",
#   "p_breach": 0.87,
#   "risk_score": 94,
#   "paths": [
#     {
#       "label": "Evasion-first",
#       "p_breach": 0.87,
#       "nodes": [
#         {
#           "id": "T1190", "name": "Exploit Public App",
#           "tactic": "Initial Access", "prob": 0.92,
#           "cov": "none", "penalty": false,
#           "sig": "Detect web exploit patterns",
#           "x": 150, "y": 90, "w": 130, "h": 36
#         },
#         {
#           "id": "ASSET-DC", "name": "Domain Controller",
#           "type": "asset", "x": 150, "y": 190, "w": 130, "h": 36
#         }
#       ],
#       "edges": [
#         { "from": "ASSET-EXT", "to": "T1190", "p": 0.92 }
#       ],
#       "blindSpots": ["T1027"]
#     }
#   ]
# }

@app.get("/api/simulation/{event_id}")
async def get_simulation(event_id: str) -> JSONResponse:
    """
    Fetch a simulation finding for a specific event.

    Tries Redis first (aegis:sim:findings:{event_id}, 24h TTL),
    then falls back to PostgreSQL (advisories.finding_json column)
    for older findings that have expired from the cache.
    """
    r: aioredis.Redis = app.state.redis_api

    # Try Redis first (fast path)
    raw = await r.get(f"aegis:sim:findings:{event_id}")
    if raw is not None:
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            pass

    # Fall back to PostgreSQL
    db_pool: asyncpg.Pool | None = app.state.db_pool
    if db_pool is not None:
        try:
            async with db_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT finding_json FROM advisories WHERE event_id = $1",
                    event_id,
                )
            if row and row["finding_json"]:
                finding = row["finding_json"]
                # finding_json is stored as JSONB, asyncpg returns it as a dict/str
                if isinstance(finding, str):
                    finding = json.loads(finding)
                return finding
        except Exception as exc:  # noqa: BLE001
            logger.warning("PostgreSQL finding lookup failed for %s: %s", event_id, exc)

    return JSONResponse(status_code=404, content={"error": "not found"})
