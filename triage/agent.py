"""
AEGIS Triage Agent

Consumer loop topology
----------------------
                    ┌─────────────────────────────────────────────────────┐
                    │  aegis:queue:triage  (XREADGROUP / XAUTOCLAIM)       │
                    └──────────────────────┬──────────────────────────────┘
                                           │
                                    parse AEGISEvent
                                    compute TriageScores
                                    enrich + re-validate
                                           │
                         ┌─────────────────┴─────────────────┐
                  score ≥ threshold                   score < threshold
                         │                                    │
                  routing_target=simulation          priority  → P3
                         │                          routing_target=advisory
                         ▼                                    ▼
               aegis:queue:simulation              aegis:queue:advisory
                                           │
                              XACK  aegis:queue:triage

Guarantees
----------
* At-least-once delivery: XACK is sent only after the enriched event has
  been written to the downstream queue.
* Stale pending messages (from crashed consumers) are reclaimed via
  XAUTOCLAIM on each loop iteration.
* The consumer group and output streams are bootstrapped on startup so
  the agent is self-contained.
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
from neo4j import AsyncGraphDatabase

# ---------------------------------------------------------------------------
# Resolve shared schema (orchestrator package) from the monorepo root.
# Supports running as `python agent.py` from the triage/ directory and
# also as a Docker entrypoint with PYTHONPATH set externally.
# ---------------------------------------------------------------------------
_TRIAGE       = pathlib.Path(__file__).parent
_ORCHESTRATOR = _TRIAGE.parent / "orchestrator"
for _p in (_ORCHESTRATOR, _TRIAGE):
    _ps = str(_p)
    if _ps not in sys.path:
        sys.path.insert(0, _ps)

from schema import AEGISEvent  # noqa: E402

from config import (  # noqa: E402
    ADVISORY_QUEUE_KEY,
    CONSUMER_GROUP,
    SIMULATION_QUEUE_KEY,
    TRIAGE_QUEUE_KEY,
    settings,
)
from scorer import TriageScores, compute_scores  # noqa: E402


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("aegis.triage.agent")


# ---------------------------------------------------------------------------
# Stream / consumer-group bootstrapping
# ---------------------------------------------------------------------------

async def _ensure_group(redis: aioredis.Redis, stream: str) -> None:
    """Create *stream* and its consumer group if they don't exist yet."""
    try:
        await redis.xgroup_create(stream, CONSUMER_GROUP, id="0", mkstream=True)
        logger.info("Consumer group '%s' created on '%s'.", CONSUMER_GROUP, stream)
    except aioredis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


async def bootstrap(redis: aioredis.Redis) -> None:
    """
    Ensure the triage input queue has a consumer group.
    Output queues (simulation, advisory) are created on first XADD
    automatically — no pre-seeding needed or wanted.
    """
    await _ensure_group(redis, TRIAGE_QUEUE_KEY)


# ---------------------------------------------------------------------------
# Message decoding
# ---------------------------------------------------------------------------

def _decode_fields(
    raw: dict[bytes | str, bytes | str],
) -> dict[str, str]:
    """Decode byte keys/values from Redis into plain strings."""
    return {
        (k.decode() if isinstance(k, bytes) else k): (
            v.decode() if isinstance(v, bytes) else v
        )
        for k, v in raw.items()
    }


# ---------------------------------------------------------------------------
# Core triage logic  (pure – no Redis I/O, easy to unit-test)
# ---------------------------------------------------------------------------

def apply_triage(event: AEGISEvent, scores: TriageScores, threshold: float) -> AEGISEvent:
    """
    Merge triage scores into *event* and set the downstream routing.

    Rules
    -----
    relevance_score ≥ threshold  →  routing_target = "simulation"
                                     priority unchanged
    relevance_score < threshold  →  routing_target = "advisory"
                                     priority downgraded to "P3"

    Returns a new, fully-validated AEGISEvent instance (model_validate
    re-runs all validators, including triage_fields_all_or_none).
    """
    high_relevance = scores.relevance_score >= threshold

    new_priority       = event.priority      if high_relevance else "P3"
    new_routing_target = "simulation"        if high_relevance else "advisory"
    new_dispatch_key   = SIMULATION_QUEUE_KEY if high_relevance else ADVISORY_QUEUE_KEY

    data = event.model_dump(mode="python")
    data.update(
        relevance_score=scores.relevance_score,
        infrastructure_match=scores.infrastructure_match,
        threat_actor_history=scores.threat_actor_history,
        exploitability=scores.exploitability,
        temporal_urgency=scores.temporal_urgency,
        triage_completed_at=datetime.now(timezone.utc),
        priority=new_priority,
        routing_target=new_routing_target,
    )

    enriched = AEGISEvent.model_validate(data)
    return enriched, new_dispatch_key


# ---------------------------------------------------------------------------
# Single-message processor
# ---------------------------------------------------------------------------

async def _process_message(
    redis: aioredis.Redis,
    msg_id: str,
    fields: dict[bytes | str, bytes | str],
    threshold: float,
    neo4j_driver: Any | None = None,
) -> None:
    """
    Full triage pipeline for one stream message:
      decode → parse → score → enrich → forward → ACK
    """
    decoded = _decode_fields(fields)

    # --- 1. Guard: skip non-event messages --------------------------------
    # Stream bootstrapping used to write {"type": "sentinel", "init": "true"}
    # entries; existing deployments may still have them.  Any message that
    # lacks source_type cannot be a valid AEGISEvent — ACK and discard.
    if "source_type" not in decoded:
        logger.debug("Skipping non-event message %s: %s", msg_id, decoded)
        await redis.xack(TRIAGE_QUEUE_KEY, CONSUMER_GROUP, msg_id)
        return

    # --- 2. Parse --------------------------------------------------------
    try:
        event = AEGISEvent.from_redis_stream(decoded)
    except Exception as exc:  # noqa: BLE001
        logger.error("Could not parse event from message %s: %s", msg_id, exc)
        # ACK to prevent infinite redelivery of a permanently malformed message.
        await redis.xack(TRIAGE_QUEUE_KEY, CONSUMER_GROUP, msg_id)
        return

    # --- 2. Score --------------------------------------------------------
    scores = await compute_scores(event.raw_payload, neo4j_driver=neo4j_driver)

    # --- 3. Enrich + route -----------------------------------------------
    try:
        enriched, dest_key = apply_triage(event, scores, threshold)
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Triage enrichment failed for event %s: %s", event.event_id, exc
        )
        await redis.xack(TRIAGE_QUEUE_KEY, CONSUMER_GROUP, msg_id)
        return

    # --- 4. Forward ------------------------------------------------------
    stream_data = enriched.to_redis_stream()
    await redis.xadd(dest_key, stream_data, maxlen=50_000, approximate=True)

    logger.info(
        "Triaged event %s (src=%s, priority=%s): %s → %s",
        enriched.event_id,
        enriched.source_type,
        enriched.priority,
        scores,
        dest_key,
    )

    # --- 5. ACK (only after successful forward) --------------------------
    await redis.xack(TRIAGE_QUEUE_KEY, CONSUMER_GROUP, msg_id)


# ---------------------------------------------------------------------------
# Main consumer loop
# ---------------------------------------------------------------------------

async def consume(
    redis: aioredis.Redis,
    shutdown: asyncio.Event,
    neo4j_driver: Any | None = None,
) -> None:
    threshold     = settings.triage_threshold
    consumer_name = settings.consumer_name

    logger.info(
        "Triage Agent started. Queue: '%s', group: '%s', consumer: '%s'. "
        "Threshold: %.2f.",
        TRIAGE_QUEUE_KEY,
        CONSUMER_GROUP,
        consumer_name,
        threshold,
    )

    while not shutdown.is_set():
        # --- Reclaim stale pending messages from dead consumers ----------
        try:
            _next_id, claimed, *_ = await redis.xautoclaim(
                TRIAGE_QUEUE_KEY,
                CONSUMER_GROUP,
                consumer_name,
                min_idle_time=settings.claim_min_idle_ms,
                start_id="0-0",
                count=settings.batch_size,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("XAUTOCLAIM failed: %s", exc)
            claimed = []

        # --- Read new messages -------------------------------------------
        try:
            response = await redis.xreadgroup(
                groupname=CONSUMER_GROUP,
                consumername=consumer_name,
                streams={TRIAGE_QUEUE_KEY: ">"},
                count=settings.batch_size,
                block=settings.block_ms,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("XREADGROUP error: %s", exc)
            await asyncio.sleep(1)
            continue

        new_messages: list[tuple[Any, dict]] = []
        if response:
            for _stream, entries in response:
                new_messages.extend(entries)

        all_messages = list(claimed) + new_messages
        if not all_messages:
            continue

        # --- Process each message ----------------------------------------
        for raw_id, raw_fields in all_messages:
            msg_id = raw_id.decode() if isinstance(raw_id, bytes) else raw_id
            try:
                await _process_message(redis, msg_id, raw_fields, threshold, neo4j_driver)
            except Exception as exc:  # noqa: BLE001
                logger.exception(
                    "Unhandled error processing message %s: %s", msg_id, exc
                )
                # Do not ACK – will be reclaimed after idle timeout.


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    redis = aioredis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=False,
        socket_keepalive=True,
    )

    # Neo4j driver is optional: if password is not set the triage agent
    # runs without it and score_threat_actor_history returns the 0.5 stub.
    neo4j_driver = None
    if settings.neo4j_password:
        try:
            neo4j_driver = AsyncGraphDatabase.driver(
                settings.neo4j_url,
                auth=(settings.neo4j_user, settings.neo4j_password),
            )
            await neo4j_driver.verify_connectivity()
            logger.info("Neo4j connected: %s", settings.neo4j_url)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Neo4j unavailable (%s) — threat_actor_history will use 0.5 fallback.", exc
            )
            neo4j_driver = None

    shutdown = asyncio.Event()

    def _handle_signal(sig: signal.Signals) -> None:
        logger.info("Received %s – shutting down gracefully…", sig.name)
        shutdown.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal, sig)

    try:
        await bootstrap(redis)
        await consume(redis, shutdown, neo4j_driver)
    finally:
        if neo4j_driver is not None:
            await neo4j_driver.close()
        await redis.aclose()
        logger.info("Connections closed. Triage Agent stopped.")


if __name__ == "__main__":
    asyncio.run(main())
