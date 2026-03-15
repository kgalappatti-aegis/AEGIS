"""
AEGIS Detection Agent – Entry Point

Runs a Redis Streams consumer loop (XREADGROUP + XAUTOCLAIM) feeding each
simulation finding through the LangGraph detection pipeline.

Reads from:  aegis:queue:detection
Writes to:   aegis:queue:advisory
"""

from __future__ import annotations

import asyncio
import logging
import pathlib
import signal
import sys
from typing import Any

import redis.asyncio as aioredis
from anthropic import AsyncAnthropic

# ---------------------------------------------------------------------------
# Ensure orchestrator/schema.py and detection/ are importable
# ---------------------------------------------------------------------------
_DET  = pathlib.Path(__file__).parent
_ORCH = _DET.parent / "orchestrator"
for _p in (_ORCH, _DET):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from config import (   # noqa: E402
    CONSUMER_GROUP,
    DETECTION_QUEUE,
    settings,
)
from graph import build_graph  # noqa: E402


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("aegis.detection.agent")


# ---------------------------------------------------------------------------
# Stream bootstrapping
# ---------------------------------------------------------------------------

async def _ensure_consumer_group(redis: aioredis.Redis) -> None:
    try:
        await redis.xgroup_create(
            DETECTION_QUEUE, CONSUMER_GROUP, id="0", mkstream=True
        )
        logger.info(
            "Consumer group '%s' created on '%s'.",
            CONSUMER_GROUP, DETECTION_QUEUE,
        )
    except aioredis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


# ---------------------------------------------------------------------------
# Message decoding
# ---------------------------------------------------------------------------

def _decode_fields(
    raw: dict[bytes | str, bytes | str],
) -> dict[str, str]:
    return {
        (k.decode() if isinstance(k, bytes) else k): (
            v.decode() if isinstance(v, bytes) else v
        )
        for k, v in raw.items()
    }


# ---------------------------------------------------------------------------
# Consumer loop
# ---------------------------------------------------------------------------

async def consume(
    redis: aioredis.Redis,
    shutdown: asyncio.Event,
) -> None:
    graph    = build_graph(
        redis_client=redis,
        anthropic_client=AsyncAnthropic(api_key=settings.anthropic_api_key),
    )
    consumer = settings.consumer_name

    logger.info(
        "Detection Agent started. Stream: '%s'  group: '%s'  consumer: '%s'",
        DETECTION_QUEUE, CONSUMER_GROUP, consumer,
    )

    while not shutdown.is_set():
        # ── Kill Switch: pause check ─────────────────────────────────────
        try:
            if await redis.get("aegis:system:paused") == b"true":
                await asyncio.sleep(2)
                continue
        except Exception:
            pass

        # ── Reclaim stale pending messages ──────────────────────────────
        try:
            _next, claimed, *_ = await redis.xautoclaim(
                DETECTION_QUEUE,
                CONSUMER_GROUP,
                consumer,
                min_idle_time=settings.claim_min_idle_ms,
                start_id="0-0",
                count=settings.batch_size,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("XAUTOCLAIM failed: %s", exc)
            claimed = []

        # ── Read new messages ────────────────────────────────────────────
        try:
            response = await redis.xreadgroup(
                groupname=CONSUMER_GROUP,
                consumername=consumer,
                streams={DETECTION_QUEUE: ">"},
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

        # ── Process each message ─────────────────────────────────────────
        for raw_id, raw_fields in all_messages:
            msg_id = raw_id.decode() if isinstance(raw_id, bytes) else raw_id
            logger.debug("Processing message %s", msg_id)

            initial_state = {
                "msg_id":     msg_id,
                "raw_fields": _decode_fields(raw_fields),
            }

            try:
                await graph.ainvoke(initial_state)
            except Exception as exc:  # noqa: BLE001
                logger.exception(
                    "Graph execution error for message %s: %s", msg_id, exc
                )
                # Do not ACK — will be reclaimed after idle timeout


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

    shutdown = asyncio.Event()

    def _handle_signal(sig: signal.Signals) -> None:
        logger.info("Received %s – shutting down gracefully…", sig.name)
        shutdown.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal, sig)

    try:
        await _ensure_consumer_group(redis)
        await consume(redis, shutdown)
    finally:
        await redis.aclose()
        logger.info("Redis connection closed. Detection Agent stopped.")


if __name__ == "__main__":
    asyncio.run(main())
