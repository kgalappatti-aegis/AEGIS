"""
AEGIS Orchestrator – Entry Point
Runs a Redis Streams consumer loop, feeding each event through the
LangGraph pipeline for priority classification and queue routing.

Consumer group semantics (XREADGROUP) guarantee at-least-once delivery:
  • Each message is ACKed only after the graph finishes successfully.
  • On restart, un-ACKed messages are reclaimed via XAUTOCLAIM.
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
from typing import Any

import redis.asyncio as aioredis

from config import (
    CONSUMER_GROUP,
    CONSUMER_NAME,
    INBOUND_STREAM,
    settings,
)
from graph import build_graph

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("aegis.main")


# ---------------------------------------------------------------------------
# Stream bootstrapping
# ---------------------------------------------------------------------------

async def _ensure_consumer_group(redis: aioredis.Redis) -> None:
    """Create the consumer group if it doesn't exist yet (MKSTREAM = True)."""
    try:
        await redis.xgroup_create(
            INBOUND_STREAM, CONSUMER_GROUP, id="0", mkstream=True
        )
        logger.info(
            "Consumer group '%s' created on stream '%s'",
            CONSUMER_GROUP,
            INBOUND_STREAM,
        )
    except aioredis.ResponseError as exc:
        if "BUSYGROUP" in str(exc):
            logger.debug("Consumer group already exists – continuing.")
        else:
            raise


# ---------------------------------------------------------------------------
# Message → OrchestratorState conversion
# ---------------------------------------------------------------------------

def _message_to_state(fields: dict[bytes | str, bytes | str]) -> dict[str, Any]:
    """
    Decode raw Redis stream fields into an OrchestratorState-compatible dict.
    All values arrive as bytes; raw_payload is stored as JSON string in Redis.
    """
    decoded = {
        (k.decode() if isinstance(k, bytes) else k): (
            v.decode() if isinstance(v, bytes) else v
        )
        for k, v in fields.items()
    }

    raw_payload = decoded.get("raw_payload", "{}")
    try:
        raw_payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        raw_payload = {"_raw": raw_payload}

    return {
        "event_id":    decoded.get("event_id", ""),
        "source_type": decoded.get("source_type", ""),
        "raw_payload": raw_payload,
        "ingested_at": decoded.get("ingested_at", ""),
        "ttl":         int(decoded.get("ttl", 86400)),
        # Internal fields – cleared for fresh processing
        "validation_error": None,
        "dispatch_key":     None,
        "dispatched":       False,
        "dispatch_error":   None,
    }


# ---------------------------------------------------------------------------
# Agent queue bootstrapping
# ---------------------------------------------------------------------------

async def initialize_streams(redis_client: aioredis.Redis) -> None:
    """
    Ensure every agent queue exists as a Redis Stream with a consumer group.
    mkstream=True creates the stream atomically inside XGROUP_CREATE, so no
    prior XADD is needed or wanted — writing a placeholder message would
    pollute the queue with entries that downstream agents cannot parse.
    """
    from config import QUEUE_KEYS

    for queue in QUEUE_KEYS.values():
        try:
            await redis_client.xgroup_create(
                queue, "orchestrator-group", id="0", mkstream=True
            )
            logger.info("Initialized stream and group for %s", queue)
        except aioredis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise


# ---------------------------------------------------------------------------
# Main consumer loop
# ---------------------------------------------------------------------------

async def consume(redis: aioredis.Redis, shutdown: asyncio.Event) -> None:
    graph = build_graph(redis)

    logger.info(
        "AEGIS Orchestrator started. Listening on stream '%s' (group='%s', consumer='%s')",
        INBOUND_STREAM,
        CONSUMER_GROUP,
        CONSUMER_NAME,
    )

    while not shutdown.is_set():
        # --- 1. Reclaim stale pending messages from dead consumers ----------
        try:
            _next_id, claimed, *_ = await redis.xautoclaim(
                INBOUND_STREAM,
                CONSUMER_GROUP,
                CONSUMER_NAME,
                min_idle_time=settings.claim_min_idle_ms,
                start_id="0-0",
                count=settings.batch_size,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("XAUTOCLAIM failed: %s", exc)
            claimed = []

        # --- 2. Read new messages -------------------------------------------
        try:
            response = await redis.xreadgroup(
                groupname=CONSUMER_GROUP,
                consumername=CONSUMER_NAME,
                streams={INBOUND_STREAM: ">"},
                count=settings.batch_size,
                block=settings.block_ms,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("XREADGROUP error: %s", exc)
            await asyncio.sleep(1)
            continue

        # Normalise: xreadgroup returns [(stream, [(id, fields), ...]), ...]
        new_messages: list[tuple[bytes, dict]] = []
        if response:
            for _stream, entries in response:
                new_messages.extend(entries)

        all_messages = list(claimed) + new_messages
        if not all_messages:
            continue

        # --- 3. Process each message through the LangGraph ------------------
        for msg_id, fields in all_messages:
            msg_id_str = msg_id.decode() if isinstance(msg_id, bytes) else msg_id
            logger.debug("Processing message %s", msg_id_str)

            initial_state = _message_to_state(fields)
            initial_state["redis_stream_id"] = msg_id_str

            try:
                final_state = await graph.ainvoke(initial_state)
            except Exception as exc:  # noqa: BLE001
                logger.exception(
                    "Graph execution error for message %s: %s", msg_id_str, exc
                )
                # Don't ACK – will be reclaimed after idle timeout
                continue

            # --- 4. ACK successfully processed messages ---------------------
            if final_state.get("dispatched") or final_state.get("validation_error"):
                # ACK even DLQ-routed events: they've been handled
                await redis.xack(INBOUND_STREAM, CONSUMER_GROUP, msg_id_str)
                logger.debug("ACKed message %s", msg_id_str)


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------

async def main() -> None:
    redis = aioredis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=False,
        socket_keepalive=True,
    )

    shutdown = asyncio.Event()

    def _handle_signal(sig: signal.Signals) -> None:
        logger.info("Received %s – shutting down gracefully…", sig.name)
        shutdown.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal, sig)

    try:
        await _ensure_consumer_group(redis)
        await initialize_streams(redis)
        await consume(redis, shutdown)
    finally:
        await redis.aclose()
        logger.info("Redis connection closed. AEGIS Orchestrator stopped.")


if __name__ == "__main__":
    asyncio.run(main())
