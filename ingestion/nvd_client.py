"""
AEGIS Ingestion – NVD API v2 Client

Responsibilities
----------------
* Enforce the NVD rate-limit window via an async token-bucket limiter.
* Fetch CVEs within a (pubStartDate, pubEndDate) range, handling pagination.
* Retry on 429 / transient 5xx with capped exponential back-off + jitter.

NVD v2 constraints
------------------
* Max date range per request: 120 days (we poll ≤ 5-minute windows so fine).
* Max results per page: 2 000. Pagination via ``startIndex``.
* Rate limit: 5 req / 30 s (anon) or 50 req / 30 s (API-key).
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import deque
from datetime import datetime
from typing import Any, AsyncIterator

import httpx

from config import (
    BACKOFF_BASE_S,
    BACKOFF_JITTER,
    BACKOFF_MAX_S,
    NVD_BASE_URL,
    NVD_DATE_FMT,
    NVD_RATE_ANON,
    NVD_RATE_KEYED,
    NVD_RATE_WINDOW,
    IngestionSettings,
)

logger = logging.getLogger("aegis.ingestion.nvd")


# ---------------------------------------------------------------------------
# Async sliding-window rate limiter
# ---------------------------------------------------------------------------

class SlidingWindowRateLimiter:
    """
    Allows at most ``capacity`` calls per ``window`` seconds.

    Implemented as a deque of timestamps: before each call, evict entries
    older than ``window``, then block if the deque is full.
    """

    def __init__(self, capacity: int, window: float) -> None:
        self._capacity = capacity
        self._window   = window
        self._slots: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            # Evict timestamps outside the rolling window
            while self._slots and now - self._slots[0] >= self._window:
                self._slots.popleft()

            if len(self._slots) >= self._capacity:
                # Sleep until the oldest slot falls out of the window
                sleep_for = self._window - (now - self._slots[0])
                if sleep_for > 0:
                    logger.debug(
                        "Rate limit reached (%d/%d). Sleeping %.2fs.",
                        len(self._slots),
                        self._capacity,
                        sleep_for,
                    )
                    await asyncio.sleep(sleep_for)
                # Re-evict after sleeping
                now = time.monotonic()
                while self._slots and now - self._slots[0] >= self._window:
                    self._slots.popleft()

            self._slots.append(time.monotonic())


# ---------------------------------------------------------------------------
# Exponential back-off helper
# ---------------------------------------------------------------------------

async def _backoff(attempt: int) -> None:
    """Sleep for BASE * 2^attempt seconds, capped at MAX, with ±JITTER."""
    delay = min(BACKOFF_BASE_S * (2 ** attempt), BACKOFF_MAX_S)
    jitter = delay * BACKOFF_JITTER * (2 * random.random() - 1)
    sleep_for = max(0.0, delay + jitter)
    logger.warning("Back-off attempt %d: sleeping %.2fs.", attempt + 1, sleep_for)
    await asyncio.sleep(sleep_for)


# ---------------------------------------------------------------------------
# NVD API client
# ---------------------------------------------------------------------------

class NVDClient:
    """
    Async NVD CVE API v2 client.

    Usage
    -----
    async with NVDClient(settings) as client:
        async for cve in client.cves_published_between(start, end):
            ...  # cve is the raw NVD ``cve`` object dict
    """

    # Retryable status codes (besides 429)
    _RETRYABLE = frozenset({500, 502, 503, 504})
    _MAX_RETRIES = 6

    def __init__(self, settings: IngestionSettings) -> None:
        capacity = NVD_RATE_KEYED if settings.nvd_api_key else NVD_RATE_ANON
        self._limiter    = SlidingWindowRateLimiter(capacity, NVD_RATE_WINDOW)
        self._api_key    = settings.nvd_api_key
        self._per_page   = settings.nvd_results_per_page
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> NVDClient:
        headers = {"User-Agent": "AEGIS-Ingestion/1.0"}
        if self._api_key:
            headers["apiKey"] = self._api_key
        self._client = httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(30.0),
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client:
            await self._client.aclose()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def cves_published_between(
        self,
        start: datetime,
        end: datetime,
    ) -> AsyncIterator[dict[str, Any]]:
        """
        Yield raw NVD ``cve`` dicts for all CVEs published in [start, end).

        Handles NVD pagination transparently; respects rate limits and
        retries on 429 / transient 5xx.
        """
        start_str = start.strftime(NVD_DATE_FMT)
        end_str   = end.strftime(NVD_DATE_FMT)
        start_idx = 0

        logger.info(
            "Fetching CVEs published %s → %s", start_str, end_str
        )

        while True:
            params: dict[str, Any] = {
                "pubStartDate":   start_str,
                "pubEndDate":     end_str,
                "resultsPerPage": self._per_page,
                "startIndex":     start_idx,
            }

            data = await self._get(params)
            total    = data.get("totalResults", 0)
            vulns    = data.get("vulnerabilities", [])

            logger.info(
                "NVD page startIndex=%d: %d/%d results",
                start_idx,
                start_idx + len(vulns),
                total,
            )

            for entry in vulns:
                yield entry.get("cve", entry)

            start_idx += len(vulns)
            if start_idx >= total or not vulns:
                break

            # Small courtesy pause between pages (still governed by limiter)
            await asyncio.sleep(0.1)

    # ------------------------------------------------------------------
    # HTTP internals
    # ------------------------------------------------------------------

    async def _get(self, params: dict[str, Any]) -> dict[str, Any]:
        """Execute a single GET with rate-limiting and retry logic."""
        assert self._client is not None, "Use NVDClient as an async context manager."

        for attempt in range(self._MAX_RETRIES):
            await self._limiter.acquire()

            try:
                resp = await self._client.get(NVD_BASE_URL, params=params)
            except httpx.TransportError as exc:
                logger.warning("Transport error (attempt %d): %s", attempt + 1, exc)
                await _backoff(attempt)
                continue

            if resp.status_code == 200:
                return resp.json()

            if resp.status_code == 429 or resp.status_code in self._RETRYABLE:
                retry_after = int(resp.headers.get("Retry-After", 0))
                if retry_after:
                    logger.warning(
                        "HTTP %d – Retry-After: %ds. Sleeping.",
                        resp.status_code,
                        retry_after,
                    )
                    await asyncio.sleep(retry_after)
                else:
                    await _backoff(attempt)
                continue

            # Non-retryable HTTP error
            resp.raise_for_status()

        raise RuntimeError(
            f"NVD request failed after {self._MAX_RETRIES} attempts. "
            f"Params: {params}"
        )
