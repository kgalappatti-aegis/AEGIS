#!/usr/bin/env python3
"""
AEGIS v5 — Infrastructure Sync Loader

Reads a ServiceNow CMDB CSV export, writes Asset nodes to Neo4j,
creates TARGETS relationships against existing TTP nodes,
and writes summary data to Redis.

Usage:
    python loader.py --csv /path/to/cmdb_export.csv
    python loader.py --csv /path/to/cmdb_export.csv --dry-run
    python loader.py --csv /path/to/cmdb_export.csv --skip-relationships
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import logging
import os
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path

import redis as Redis
from dotenv import load_dotenv
from neo4j import AsyncGraphDatabase

from mapper import map_row
from neo4j_writer import create_indexes, create_targets_relationships, upsert_assets
from redis_writer import write_asset_summary

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("aegis.infra_sync")

_REQUIRED_COLS = {
    "sys_id",
    "sys_class_name",
    "name",
    "u_asset_subtype",
    "u_criticality_score",
    "operational_status",
    "install_status",
}


def parse_csv(path: str) -> tuple[list[dict], list[str]]:
    """
    Read CSV, return (valid_records, skipped_reasons).
    Validates required columns are present.
    """
    records: list[dict] = []
    skipped: list[str] = []

    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)

        missing = _REQUIRED_COLS - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                f"CSV missing required columns: {missing}\n"
                f"Found columns: {list(reader.fieldnames)}"
            )

        for i, row in enumerate(reader, start=2):  # row 1 = header
            record = map_row(row)
            if record is None:
                skipped.append(
                    f"Row {i} ({row.get('name', '?')}): "
                    f"status={row.get('operational_status')} "
                    f"install={row.get('install_status')}"
                )
            else:
                records.append(asdict(record))

    return records, skipped


async def run(csv_path: str, dry_run: bool, skip_relationships: bool) -> None:
    neo4j_uri = os.environ["NEO4J_URI"]
    neo4j_user = os.environ.get("NEO4J_USER", "neo4j")
    neo4j_pass = os.environ["NEO4J_PASSWORD"]
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")

    logger.info("Reading CSV: %s", csv_path)
    records, skipped = parse_csv(csv_path)
    logger.info(
        "Parsed %d operational assets, skipped %d", len(records), len(skipped)
    )

    if skipped:
        logger.info("Skipped assets:")
        for s in skipped[:10]:
            logger.info("  %s", s)
        if len(skipped) > 10:
            logger.info("  ... and %d more", len(skipped) - 10)

    # Print distribution summary
    subtypes = Counter(r["subtype"] for r in records)
    logger.info("Asset distribution:")
    for subtype, count in sorted(subtypes.items(), key=lambda x: -x[1]):
        logger.info("  %-30s %5d", subtype, count)

    if dry_run:
        logger.info("DRY RUN — no writes performed.")
        return

    # ── Neo4j ─────────────────────────────────────────────────────────────
    driver = AsyncGraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
    try:
        logger.info("Creating Neo4j indexes...")
        await create_indexes(driver)

        logger.info("Upserting %d Asset nodes to Neo4j...", len(records))
        await upsert_assets(driver, records)
        logger.info("Asset nodes written.")

        if not skip_relationships:
            logger.info(
                "Creating TARGETS relationships (TTP → Asset by tactic + subtype)..."
            )
            await create_targets_relationships(driver)
            logger.info("TARGETS relationships created.")
        else:
            logger.info("Skipping TARGETS relationship creation.")
    finally:
        await driver.close()

    # ── Redis ─────────────────────────────────────────────────────────────
    r = Redis.from_url(redis_url, decode_responses=True)
    logger.info("Writing asset summary to Redis...")
    write_asset_summary(r, records)
    logger.info("Redis summary written.")

    logger.info(
        "Sync complete — %d assets loaded, %d skipped, %d subtypes.",
        len(records),
        len(skipped),
        len(subtypes),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="AEGIS infra_sync loader")
    parser.add_argument(
        "--csv", required=True, help="Path to ServiceNow CMDB CSV export"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and validate only, no writes",
    )
    parser.add_argument(
        "--skip-relationships",
        action="store_true",
        help="Skip TARGETS relationship creation (faster re-sync)",
    )
    args = parser.parse_args()

    if not Path(args.csv).exists():
        logger.error("CSV not found: %s", args.csv)
        sys.exit(1)

    asyncio.run(run(args.csv, args.dry_run, args.skip_relationships))


if __name__ == "__main__":
    main()
