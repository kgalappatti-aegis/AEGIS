"""
AEGIS Infrastructure Sync — Redis Writer

Writes asset inventory summary keys to Redis for dashboard display,
advisory agent enrichment, and simulation agent weighting.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import datetime, timezone

import redis as Redis

logger = logging.getLogger("aegis.infra_sync.redis")


def write_asset_summary(r: Redis.Redis, records: list[dict]) -> None:
    """
    Write asset inventory summary to Redis for dashboard and agent use.

    Keys written:
      aegis:infra:asset:{sys_id}       — per-asset metadata hash (7-day TTL)
      aegis:infra:subtype_counts       — hash of subtype → count
      aegis:infra:criticality_dist     — hash of score → count
      aegis:infra:high_value_targets   — JSON list of assets with criticality >= 7
      aegis:infra:last_sync            — ISO timestamp of last sync
      aegis:infra:asset_count          — total operational asset count
      aegis:infra:source               — data source identifier
    """
    # Per-asset metadata hash (for advisory agent enrichment)
    pipe = r.pipeline()
    for rec in records:
        key = f"aegis:infra:asset:{rec['sys_id']}"
        pipe.hset(
            key,
            mapping={
                "name": rec["name"],
                "subtype": rec["subtype"],
                "criticality": rec["criticality"],
                "department": rec["department"],
                "owner_email": rec["owner_email"],
                "support_group": rec["support_group"],
                "location": rec["location"],
                "environment": rec["environment"],
                "classification": rec["classification"],
                "last_discovered": rec["last_discovered"],
                "business_criticality": rec["business_criticality"],
            },
        )
        pipe.expire(key, 86400 * 7)  # 7-day TTL; re-sync refreshes
    pipe.execute()
    logger.info("Wrote %d per-asset Redis hashes.", len(records))

    # Aggregate counts by subtype (for dashboard stat bar)
    subtype_counts = Counter(rec["subtype"] for rec in records)
    r.delete("aegis:infra:subtype_counts")
    if subtype_counts:
        r.hset(
            "aegis:infra:subtype_counts",
            mapping={k: str(v) for k, v in subtype_counts.items()},
        )

    # Criticality distribution (for simulation weighting)
    crit_dist = Counter(str(rec["criticality"]) for rec in records)
    r.delete("aegis:infra:criticality_dist")
    if crit_dist:
        r.hset("aegis:infra:criticality_dist", mapping=dict(crit_dist))

    # High-value target index — assets criticality >= 7
    hvt = [
        {
            "sys_id": rec["sys_id"],
            "name": rec["name"],
            "subtype": rec["subtype"],
            "criticality": rec["criticality"],
        }
        for rec in records
        if rec["criticality"] >= 7
    ]
    r.set("aegis:infra:high_value_targets", json.dumps(hvt))

    # Sync metadata
    r.set("aegis:infra:last_sync", datetime.now(timezone.utc).isoformat())
    r.set("aegis:infra:asset_count", str(len(records)))
    r.set("aegis:infra:source", "cmdb_csv")

    logger.info(
        "Redis summary written: %d subtypes, %d HVTs, %d total assets.",
        len(subtype_counts),
        len(hvt),
        len(records),
    )
