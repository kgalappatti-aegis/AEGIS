"""
AEGIS Triage Agent

Consumer loop topology
----------------------
                    +-----------------------------------------------------+
                    |  aegis:queue:triage  (XREADGROUP / XAUTOCLAIM)       |
                    +----------------------+------------------------------+
                                           |
                                    parse AEGISEvent
                                    enrich (EPSS + KEV + CIRCL)
                                    compute TriageScores
                                    enrich + re-validate
                                           |
                         +-----------------+-----------------+
                  score >= threshold                  score < threshold
                         |                                    |
                  routing_target=simulation          priority  -> P3
                         |                          routing_target=advisory
                         v                                    v
               aegis:queue:simulation              aegis:queue:advisory
                                           |
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
import json
import logging
import pathlib
import signal
import sys
from datetime import datetime, timezone
from typing import Any

import httpx
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
from enrichment import EnrichmentData, enrich_event  # noqa: E402
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

# Priority ranking: lower index = more severe
_PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
_RANK_PRIORITY = {v: k for k, v in _PRIORITY_RANK.items()}


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
# KEV priority bump
# ---------------------------------------------------------------------------

def _kev_priority_bump(priority: str) -> str:
    """Bump priority up one tier when CVE is in CISA KEV."""
    rank = _PRIORITY_RANK.get(priority, 3)
    bumped = max(0, rank - 1)  # P3→P2, P2→P1, P1→P0, P0→P0
    return _RANK_PRIORITY.get(bumped, "P0")


# ---------------------------------------------------------------------------
# Core triage logic  (pure – no Redis I/O, easy to unit-test)
# ---------------------------------------------------------------------------

def apply_triage(
    event: AEGISEvent,
    scores: TriageScores,
    threshold: float,
    enrichment: EnrichmentData | None = None,
) -> AEGISEvent:
    """
    Merge triage scores into *event* and set the downstream routing.

    Rules
    -----
    relevance_score >= threshold  ->  routing_target = "simulation"
                                       priority unchanged
    relevance_score < threshold   ->  routing_target = "advisory"
                                       priority downgraded to "P3"

    KEV override: if the CVE is in CISA KEV, bump priority up one tier
    regardless of routing decision.

    Returns a new, fully-validated AEGISEvent instance (model_validate
    re-runs all validators, including triage_fields_all_or_none).
    """
    high_relevance = scores.relevance_score >= threshold

    new_priority       = event.priority      if high_relevance else "P3"
    new_routing_target = "simulation"        if high_relevance else "advisory"
    new_dispatch_key   = SIMULATION_QUEUE_KEY if high_relevance else ADVISORY_QUEUE_KEY

    # KEV hit → bump priority up a tier
    if enrichment and enrichment.in_kev:
        new_priority = _kev_priority_bump(new_priority)
        logger.info(
            "KEV priority bump for %s: %s → %s (added %s, ransomware=%s)",
            event.event_id,
            event.priority,
            new_priority,
            enrichment.kev_date_added or "?",
            enrichment.kev_ransomware or "?",
        )

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
    http_client: httpx.AsyncClient | None = None,
) -> None:
    """
    Full triage pipeline for one stream message:
      decode -> parse -> enrich (EPSS+KEV+CIRCL) -> score -> route -> ACK
    """
    decoded = _decode_fields(fields)

    # --- 1. Guard: skip non-event messages --------------------------------
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

    # --- 3. External enrichment (EPSS + KEV + CIRCL + ThreatFox + MalwareBazaar + OSV)
    raw_payload = event.raw_payload or {}
    cve_id = raw_payload.get("cve_id")
    enrichment = EnrichmentData()
    if http_client:
        try:
            enrichment = await enrich_event(
                http_client, cve_id, raw_payload, event.source_type,
                abusech_auth_key=settings.abusech_auth_key,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Enrichment failed for %s: %s — using defaults.", cve_id, exc)

    # --- 4. Score --------------------------------------------------------
    scores = await compute_scores(
        event.raw_payload,
        neo4j_driver=neo4j_driver,
        enrichment=enrichment,
    )

    # --- 5. Enrich + route -----------------------------------------------
    try:
        enriched, dest_key = apply_triage(event, scores, threshold, enrichment)
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Triage enrichment failed for event %s: %s", event.event_id, exc
        )
        await redis.xack(TRIAGE_QUEUE_KEY, CONSUMER_GROUP, msg_id)
        return

    # --- 6. Forward ------------------------------------------------------
    stream_data = enriched.to_redis_stream()
    await redis.xadd(dest_key, stream_data, maxlen=50_000, approximate=True)

    # Publish stage update for live UI tracking
    if enriched.event_id:
        await redis.hset("aegis:event:stages", enriched.event_id, "triaged")
        await redis.publish("aegis:broadcast", json.dumps({
            "type": "stage_update",
            "event_id": enriched.event_id,
            "stage": "triaged",
        }))

    epss_str = f"EPSS={enrichment.epss_score:.4f}" if enrichment.epss_score is not None else "EPSS=n/a"
    kev_str = "KEV=YES" if enrichment.in_kev else "KEV=no"

    logger.info(
        "Triaged event %s (src=%s, priority=%s, %s, %s): %s -> %s",
        enriched.event_id,
        enriched.source_type,
        enriched.priority,
        epss_str,
        kev_str,
        scores,
        dest_key,
    )

    # --- 7. ACK (only after successful forward) --------------------------
    await redis.xack(TRIAGE_QUEUE_KEY, CONSUMER_GROUP, msg_id)


# ---------------------------------------------------------------------------
# Main consumer loop
# ---------------------------------------------------------------------------

async def consume(
    redis: aioredis.Redis,
    shutdown: asyncio.Event,
    neo4j_driver: Any | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> None:
    threshold     = settings.triage_threshold
    consumer_name = settings.consumer_name

    logger.info(
        "Triage Agent started. Queue: '%s', group: '%s', consumer: '%s'. "
        "Threshold: %.2f. Enrichment: %s.",
        TRIAGE_QUEUE_KEY,
        CONSUMER_GROUP,
        consumer_name,
        threshold,
        "enabled" if http_client else "disabled",
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
                await _process_message(
                    redis, msg_id, raw_fields, threshold,
                    neo4j_driver, http_client,
                )
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

    # httpx client for external enrichment (EPSS, KEV, CIRCL)
    http_client = httpx.AsyncClient(
        headers={"User-Agent": "AEGIS-Triage/1.0"},
        follow_redirects=True,
    )

    shutdown = asyncio.Event()

    def _handle_signal(sig: signal.Signals) -> None:
        logger.info("Received %s – shutting down gracefully…", sig.name)
        shutdown.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal, sig)

    try:
        await bootstrap(redis)
        await consume(redis, shutdown, neo4j_driver, http_client)
    finally:
        await http_client.aclose()
        if neo4j_driver is not None:
            await neo4j_driver.close()
        await redis.aclose()
        logger.info("Connections closed. Triage Agent stopped.")


if __name__ == "__main__":
    asyncio.run(main())
