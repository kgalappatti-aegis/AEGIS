"""
AEGIS WebSocket Bridge

Two background tasks push data to all connected WebSocket clients:

  _tail_detection_loop  – XREAD-tails aegis:queue:detection and emits
                          type:"event" messages with stage:"detected".

  _subscribe_loop       – SUBSCRIBEs to aegis:broadcast pub/sub and emits
                          type:"advisory" messages published by the advisory
                          agent.

Both tasks normalise their output into the envelope the UI expects:
  { "type": "event"|"advisory", "payload": {...}, "ts": <epoch ms> }

Endpoints
---------
GET  /ws       WebSocket — live event + advisory push
GET  /healthz  Liveness probe
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
DETECTION_QUEUE   = "aegis:queue:detection"
BROADCAST_CHANNEL = "aegis:broadcast"
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

    tail_task      = asyncio.create_task(_tail_detection_loop(redis_stream))
    subscribe_task = asyncio.create_task(_subscribe_loop(redis_pubsub))

    logger.info("AEGIS WebSocket Bridge started. Redis: %s", REDIS_URL)
    try:
        yield
    finally:
        tail_task.cancel()
        subscribe_task.cancel()
        await asyncio.gather(tail_task, subscribe_task, return_exceptions=True)
        await redis_stream.aclose()
        await redis_pubsub.aclose()
        await redis_api.aclose()
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
    Hold each WebSocket connection open.  All data is pushed by the two
    background tasks; this coroutine only needs to handle disconnects.
    """
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()   # keepalive / client ping
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(ws)


# ---------------------------------------------------------------------------
# REST API endpoints
# ---------------------------------------------------------------------------

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

    hits_raw, priority_raw, actors_raw, updated_at = await asyncio.gather(
        r.hgetall("aegis:ttp:hits"),
        r.hgetall("aegis:ttp:priority"),
        r.hgetall("aegis:ttp:actors"),
        r.get("aegis:ttp:updated_at"),
    )

    techniques: dict[str, dict] = {}
    all_ids = set(hits_raw) | set(priority_raw) | set(actors_raw)
    for tid in all_ids:
        hit_val = hits_raw.get(tid)
        techniques[tid] = {
            "hits": int(hit_val) if hit_val else 0,
            "maxPriority": priority_raw.get(tid, "P3"),
            "actors": [
                a.strip()
                for a in (actors_raw.get(tid, "")).split(",")
                if a.strip()
            ],
        }

    return {
        "techniques": techniques,
        "lastUpdated": updated_at or None,
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
    Fetch a simulation finding for a specific event from Redis.

    Key: aegis:sim:findings:{event_id} (JSON string, 24h TTL)
    """
    r: aioredis.Redis = app.state.redis_api
    raw = await r.get(f"aegis:sim:findings:{event_id}")
    if raw is None:
        return JSONResponse(status_code=404, content={"error": "not found"})
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return JSONResponse(status_code=500, content={"error": "corrupt finding data"})
