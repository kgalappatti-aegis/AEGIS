"""
AEGIS Atomic Red Team Loader

Downloads the Atomic Red Team index from GitHub, parses technique tests,
and stores structured test metadata in Redis for use by the detection and
advisory agents.

Redis keys written:
    aegis:atomic:tests         Hash  {technique_id} → JSON array of test summaries
    aegis:atomic:count         Hash  {technique_id} → number of tests
    aegis:atomic:platforms     Hash  {technique_id} → comma-joined platforms
    aegis:atomic:loaded_at     String  ISO timestamp of last load

Usage:
    python scripts/atomic_loader.py                 # load from GitHub
    python scripts/atomic_loader.py --verify        # verify Redis keys
    python scripts/atomic_loader.py --stats         # print coverage stats
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from typing import Any

import httpx
import redis
import yaml
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("aegis.atomic_loader")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# Atomic Red Team consolidated index (YAML, ~15 MB)
ATOMIC_INDEX_URL = os.getenv(
    "ATOMIC_INDEX_URL",
    "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml",
)

# Redis key prefixes
KEY_TESTS      = "aegis:atomic:tests"
KEY_COUNT      = "aegis:atomic:count"
KEY_PLATFORMS  = "aegis:atomic:platforms"
KEY_LOADED_AT  = "aegis:atomic:loaded_at"

# GitHub raw URL template for linking to individual test files
ATOMIC_RAW_URL = (
    "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/{tid}/{tid}.yaml"
)


# ---------------------------------------------------------------------------
# Download + parse
# ---------------------------------------------------------------------------

def download_index(url: str) -> dict[str, Any]:
    """Download and parse the Atomic Red Team index YAML."""
    logger.info("Downloading Atomic Red Team index from %s …", url)
    t0 = time.monotonic()

    with httpx.Client(timeout=120.0, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()

    raw = resp.text
    logger.info(
        "Downloaded %.1f MB in %.1fs. Parsing YAML…",
        len(raw) / 1_048_576,
        time.monotonic() - t0,
    )

    data = yaml.safe_load(raw)
    return data


def extract_tests(index: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """
    Walk the tactic → technique → atomic_tests hierarchy and extract
    a flat mapping of technique_id → list of test summaries.

    Each test summary contains:
        name, auto_generated_guid, description (truncated),
        supported_platforms, executor_name, elevation_required,
        has_cleanup, has_dependencies, github_url
    """
    result: dict[str, list[dict[str, Any]]] = {}

    for tactic_name, techniques in index.items():
        if not isinstance(techniques, dict):
            continue

        for technique_id, technique_data in techniques.items():
            if not isinstance(technique_data, dict):
                continue

            atomic_tests = technique_data.get("atomic_tests", [])
            if not isinstance(atomic_tests, list):
                continue

            tests: list[dict[str, Any]] = []
            for test in atomic_tests:
                if not isinstance(test, dict):
                    continue

                executor = test.get("executor", {})
                executor_name = executor.get("name", "manual") if isinstance(executor, dict) else "manual"
                elevation = executor.get("elevation_required", False) if isinstance(executor, dict) else False
                has_cleanup = bool(executor.get("cleanup_command")) if isinstance(executor, dict) else False

                platforms = test.get("supported_platforms", [])
                if not isinstance(platforms, list):
                    platforms = []

                desc = test.get("description", "")
                if len(desc) > 300:
                    desc = desc[:297] + "…"

                tests.append({
                    "name":                test.get("name", ""),
                    "guid":                test.get("auto_generated_guid", ""),
                    "description":         desc,
                    "supported_platforms":  platforms,
                    "executor":            executor_name,
                    "elevation_required":  elevation,
                    "has_cleanup":         has_cleanup,
                    "has_dependencies":    bool(test.get("dependencies")),
                    "github_url":          ATOMIC_RAW_URL.format(tid=technique_id),
                })

            if tests:
                # Merge if technique appears under multiple tactics
                if technique_id in result:
                    existing_guids = {t["guid"] for t in result[technique_id]}
                    for t in tests:
                        if t["guid"] not in existing_guids:
                            result[technique_id].append(t)
                else:
                    result[technique_id] = tests

    return result


# ---------------------------------------------------------------------------
# Redis write
# ---------------------------------------------------------------------------

def write_to_redis(
    r: redis.Redis,
    tests_by_technique: dict[str, list[dict[str, Any]]],
) -> None:
    """Write parsed Atomic tests to Redis hashes."""
    logger.info("Writing %d techniques to Redis…", len(tests_by_technique))

    pipe = r.pipeline(transaction=False)
    batch = 0

    for tid, tests in tests_by_technique.items():
        pipe.hset(KEY_TESTS, tid, json.dumps(tests, separators=(",", ":")))
        pipe.hset(KEY_COUNT, tid, str(len(tests)))

        all_platforms: set[str] = set()
        for t in tests:
            all_platforms.update(t.get("supported_platforms", []))
        pipe.hset(KEY_PLATFORMS, tid, ",".join(sorted(all_platforms)))

        batch += 1
        if batch % 200 == 0:
            pipe.execute()
            pipe = r.pipeline(transaction=False)

    from datetime import datetime, timezone
    pipe.set(KEY_LOADED_AT, datetime.now(timezone.utc).isoformat())
    pipe.execute()

    total_tests = sum(len(t) for t in tests_by_technique.values())
    logger.info(
        "Loaded %d Atomic tests across %d techniques into Redis.",
        total_tests,
        len(tests_by_technique),
    )


# ---------------------------------------------------------------------------
# Verify + stats
# ---------------------------------------------------------------------------

def verify(r: redis.Redis) -> bool:
    loaded_at = r.get(KEY_LOADED_AT)
    if not loaded_at:
        logger.error("No atomic data found in Redis (key %s missing).", KEY_LOADED_AT)
        return False

    loaded_at_str = loaded_at.decode() if isinstance(loaded_at, bytes) else loaded_at
    count = r.hlen(KEY_TESTS)
    logger.info("Atomic data loaded at %s — %d techniques in Redis.", loaded_at_str, count)

    # Spot-check a common technique
    for spot in ("T1059.001", "T1053.005", "T1190"):
        raw = r.hget(KEY_TESTS, spot)
        if raw:
            tests = json.loads(raw)
            logger.info("  %s: %d test(s) — %s", spot, len(tests), tests[0]["name"][:60])
        else:
            logger.warning("  %s: no tests found", spot)

    return True


def print_stats(r: redis.Redis) -> None:
    """Print coverage overlap between Atomic tests and simulation TTP hits."""
    atomic_tids = set(
        k.decode() if isinstance(k, bytes) else k
        for k in r.hkeys(KEY_TESTS)
    )
    sim_tids = set(
        k.decode() if isinstance(k, bytes) else k
        for k in r.hkeys("aegis:ttp:hits")
    )
    detection_tids = set(
        k.decode() if isinstance(k, bytes) else k
        for k in r.hkeys("aegis:detection:coverage")
    )

    overlap_sim = atomic_tids & sim_tids
    overlap_det = atomic_tids & detection_tids
    sim_no_atomic = sim_tids - atomic_tids

    print(f"\nAtomic Red Team Coverage Report")
    print(f"{'─' * 40}")
    print(f"Atomic tests loaded:         {len(atomic_tids)} techniques")
    print(f"Simulation TTPs seen:        {len(sim_tids)} techniques")
    print(f"Detection coverage:          {len(detection_tids)} techniques")
    print(f"")
    print(f"Sim TTPs with Atomic tests:  {len(overlap_sim)} ({len(overlap_sim)/max(1,len(sim_tids)):.0%})")
    print(f"Detection with Atomic tests: {len(overlap_det)} ({len(overlap_det)/max(1,len(detection_tids)):.0%})")
    print(f"Sim TTPs without Atomic:     {len(sim_no_atomic)}")

    if sim_no_atomic:
        print(f"\nTTPs in simulation paths with no Atomic test:")
        for tid in sorted(sim_no_atomic)[:20]:
            print(f"  {tid}")
        if len(sim_no_atomic) > 20:
            print(f"  … and {len(sim_no_atomic) - 20} more")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="AEGIS Atomic Red Team Loader")
    parser.add_argument("--verify", action="store_true", help="Verify Redis keys")
    parser.add_argument("--stats", action="store_true", help="Print coverage stats")
    parser.add_argument("--url", default=ATOMIC_INDEX_URL, help="Override index URL")
    args = parser.parse_args()

    r = redis.from_url(REDIS_URL, decode_responses=False)

    if args.verify:
        ok = verify(r)
        sys.exit(0 if ok else 1)

    if args.stats:
        verify(r)
        print_stats(r)
        sys.exit(0)

    # Full load
    index = download_index(args.url)
    tests = extract_tests(index)
    write_to_redis(r, tests)
    verify(r)


if __name__ == "__main__":
    main()
