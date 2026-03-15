"""
AEGIS Advisory Agent – Entry Point

Runs a Redis Streams consumer loop (XREADGROUP + XAUTOCLAIM) feeding each
fully-enriched event through the LangGraph advisory pipeline.

Reads from:  aegis:queue:advisory
Writes to:   PostgreSQL advisories table
Publishes:   aegis:broadcast  (consumed by the WebSocket bridge)
"""

from __future__ import annotations

import asyncio
import logging
import pathlib
import signal
import sys
from typing import Any

import asyncpg
import redis.asyncio as aioredis
from anthropic import AsyncAnthropic

# ---------------------------------------------------------------------------
# Ensure advisory/ is importable (monorepo layout)
# ---------------------------------------------------------------------------
_ADV  = pathlib.Path(__file__).parent
_ORCH = _ADV.parent / "orchestrator"
for _p in (_ORCH, _ADV):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from config import (   # noqa: E402
    ADVISORY_QUEUE,
    CONSUMER_GROUP,
    DDL,
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
logger = logging.getLogger("aegis.advisory.agent")


# ---------------------------------------------------------------------------
# Bootstrap helpers
# ---------------------------------------------------------------------------

async def _ensure_consumer_group(redis: aioredis.Redis) -> None:
    try:
        await redis.xgroup_create(
            ADVISORY_QUEUE, CONSUMER_GROUP, id="0", mkstream=True
        )
        logger.info(
            "Consumer group '%s' created on '%s'.",
            CONSUMER_GROUP, ADVISORY_QUEUE,
        )
    except aioredis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


async def _ensure_schema(pool: asyncpg.Pool) -> None:
    """Apply DDL idempotently on startup."""
    async with pool.acquire() as conn:
        # DDL may contain multiple statements — execute each separately
        for statement in DDL.strip().split(";"):
            stmt = statement.strip()
            if stmt:
                await conn.execute(stmt)
    logger.info("PostgreSQL schema ready.")


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
    db_pool: asyncpg.Pool,
    shutdown: asyncio.Event,
) -> None:
    graph    = build_graph(
        redis_client=redis,
        anthropic_client=AsyncAnthropic(api_key=settings.anthropic_api_key),
        db_pool=db_pool,
    )
    consumer = settings.consumer_name

    logger.info(
        "Advisory Agent started. Stream: '%s'  group: '%s'  consumer: '%s'",
        ADVISORY_QUEUE, CONSUMER_GROUP, consumer,
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
                ADVISORY_QUEUE,
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
                streams={ADVISORY_QUEUE: ">"},
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
                # acknowledge node is always last — if graph crashes before
                # it, the message will be reclaimed after idle timeout


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

    db_pool = await asyncpg.create_pool(
        settings.database_url,
        min_size=2,
        max_size=10,
        command_timeout=30,
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
        await _ensure_schema(db_pool)
        await consume(redis, db_pool, shutdown)
    finally:
        await db_pool.close()
        await redis.aclose()
        logger.info("Connections closed. Advisory Agent stopped.")


if __name__ == "__main__":
    asyncio.run(main())
