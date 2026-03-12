"""
AEGIS LangGraph Nodes
Each function receives OrchestratorState and returns a partial state update.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
from pydantic import ValidationError

from config import (
    DLQ_STREAM,
    PRIORITY_MATRIX,
    QUEUE_KEYS,
    ROUTING_MATRIX,
    settings,
)
from schema import AEGISEvent, OrchestratorState

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Node 1: validate
# ---------------------------------------------------------------------------

def validate(state: OrchestratorState) -> OrchestratorState:
    """
    Parse raw state fields into an AEGISEvent for schema validation.
    Flags unknown source types or malformed payloads without hard-failing
    (the graph uses conditional edges to route errors to DLQ).
    """
    try:
        event = AEGISEvent(
            event_id=state.get("event_id", ""),
            source_type=state["source_type"],
            raw_payload=state.get("raw_payload", {}),
            ingested_at=state.get("ingested_at", datetime.now(timezone.utc).isoformat()),
            ttl=state.get("ttl", 86400),
        )
        logger.debug("Validated event %s (source=%s)", event.event_id, event.source_type)
        return {
            "event_id": event.event_id,
            "source_type": event.source_type,
            "ingested_at": event.ingested_at.isoformat(),
            "ttl": event.ttl,
            "validation_error": None,
        }
    except (ValidationError, KeyError) as exc:
        logger.warning("Validation failed for event: %s", exc)
        return {"validation_error": str(exc)}


# ---------------------------------------------------------------------------
# Node 2: classify
# ---------------------------------------------------------------------------

def classify(state: OrchestratorState) -> OrchestratorState:
    """
    Assigns priority and routing_target using the static matrices.
    Falls back to P3 / advisory for unknown source types so no event
    is silently dropped – it will still land in a queue.
    """
    src = state.get("source_type", "").lower()

    priority = PRIORITY_MATRIX.get(src, "P3")
    routing_target = ROUTING_MATRIX.get(src, "advisory")

    logger.info(
        "Classified event %s: source=%s → priority=%s, routing=%s",
        state.get("event_id", "?"),
        src,
        priority,
        routing_target,
    )

    return {
        "priority": priority,
        "routing_target": routing_target,
        "dispatch_key": QUEUE_KEYS[routing_target],
    }


# ---------------------------------------------------------------------------
# Node 3: dispatch
# ---------------------------------------------------------------------------

async def dispatch(state: OrchestratorState, redis: aioredis.Redis) -> OrchestratorState:
    """
    Pushes the fully-classified event onto the target Redis stream.
    Uses XADD so each queue is itself a Redis Stream (consumers can
    use XREADGROUP for reliable, at-least-once delivery).
    """
    dispatch_key = state.get("dispatch_key")
    if not dispatch_key:
        return {"dispatched": False, "dispatch_error": "No dispatch_key resolved"}

    payload: dict[str, Any] = {
        "event_id":      state.get("event_id", ""),
        "source_type":   state.get("source_type", ""),
        "priority":      state.get("priority", "P3"),
        "routing_target": state.get("routing_target", "advisory"),
        "ingested_at":   state.get("ingested_at", ""),
        "ttl":           str(state.get("ttl", 86400)),
        "raw_payload":   json.dumps(state.get("raw_payload", {})),
    }

    try:
        msg_id = await redis.xadd(dispatch_key, payload, maxlen=10_000, approximate=True)
        logger.info(
            "Dispatched event %s → %s (stream_id=%s)",
            state.get("event_id"),
            dispatch_key,
            msg_id,
        )
        return {"dispatched": True, "dispatch_error": None}
    except Exception as exc:  # noqa: BLE001
        logger.error("Dispatch failed for event %s: %s", state.get("event_id"), exc)
        return {"dispatched": False, "dispatch_error": str(exc)}


# ---------------------------------------------------------------------------
# Node 4: send_to_dlq
# ---------------------------------------------------------------------------

async def send_to_dlq(state: OrchestratorState, redis: aioredis.Redis) -> OrchestratorState:
    """
    Routes invalid or un-dispatchable events to the dead-letter queue.
    Preserves the original raw_payload for later inspection / replay.
    """
    reason = state.get("validation_error") or state.get("dispatch_error") or "unknown"

    dlq_payload: dict[str, str] = {
        "event_id":    state.get("event_id", ""),
        "source_type": state.get("source_type", "unknown"),
        "raw_payload": json.dumps(state.get("raw_payload", {})),
        "ingested_at": state.get("ingested_at", ""),
        "reason":      reason,
    }

    try:
        await redis.xadd(DLQ_STREAM, dlq_payload, maxlen=5_000, approximate=True)
        logger.warning(
            "Event %s sent to DLQ: %s", state.get("event_id", "?"), reason
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("DLQ write failed: %s", exc)

    return {"dispatched": False}
