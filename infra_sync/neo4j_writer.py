"""
AEGIS Infrastructure Sync — Neo4j Writer

Batched upserts of Asset nodes and TARGETS relationship creation
between TTP nodes and Asset nodes based on tactic/subtype rules.
"""

from __future__ import annotations

import logging

from neo4j import AsyncGraphDatabase

logger = logging.getLogger("aegis.infra_sync.neo4j")

BATCH_SIZE = 100

# Tactic → asset targeting rules for [:TARGETS] edges
_TACTIC_RULES: list[dict] = [
    {
        "tactic": "initial-access",
        "asset_types": ["endpoint", "cloud"],
        "asset_subtypes": [],
        "min_criticality": 0,
    },
    {
        "tactic": "lateral-movement",
        "asset_types": ["server", "network"],
        "asset_subtypes": [],
        "min_criticality": 0,
    },
    {
        "tactic": "credential-access",
        "asset_types": [],
        "asset_subtypes": [
            "Domain Controller", "Database Server", "Application Server",
        ],
        "min_criticality": 0,
    },
    {
        "tactic": "impact",
        "asset_types": ["server", "cloud"],
        "asset_subtypes": [],
        "min_criticality": 7,
    },
    {
        "tactic": "exfiltration",
        "asset_types": [],
        "asset_subtypes": [
            "Cloud Storage", "Database Server", "Cloud Database", "File Server",
        ],
        "min_criticality": 0,
    },
    {
        "tactic": "persistence",
        "asset_types": ["server"],
        "asset_subtypes": [],
        "min_criticality": 0,
    },
    {
        "tactic": "privilege-escalation",
        "asset_types": [],
        "asset_subtypes": [
            "Domain Controller", "Application Server", "Database Server",
        ],
        "min_criticality": 0,
    },
    {
        "tactic": "discovery",
        "asset_types": ["network", "server", "cloud"],
        "asset_subtypes": [],
        "min_criticality": 0,
    },
    {
        "tactic": "collection",
        "asset_types": [],
        "asset_subtypes": [
            "File Server", "Database Server", "Cloud Storage", "Cloud Database",
        ],
        "min_criticality": 0,
    },
]


async def upsert_assets(driver, records: list[dict]) -> None:
    """
    Merge Asset nodes into Neo4j in batches.
    Uses sys_id as the stable unique identifier.
    """
    async with driver.session() as session:
        for i in range(0, len(records), BATCH_SIZE):
            batch = records[i : i + BATCH_SIZE]
            await session.run(
                """
                UNWIND $batch AS row
                MERGE (a:Asset {sys_id: row.sys_id})
                SET
                  a.name           = row.name,
                  a.fqdn           = row.fqdn,
                  a.ip_address     = row.ip_address,
                  a.type           = row.asset_type,
                  a.subtype        = row.subtype,
                  a.criticality    = row.criticality,
                  a.os             = row.os,
                  a.os_version     = row.os_version,
                  a.environment    = row.environment,
                  a.location       = row.location,
                  a.department     = row.department,
                  a.classification = row.classification,
                  a.manufacturer   = row.manufacturer,
                  a.model          = row.model,
                  a.sys_class      = row.sys_class,
                  a.description    = row.description,
                  a.source         = 'cmdb'
                """,
                batch=batch,
            )
            logger.debug("Upserted batch %d–%d", i, i + len(batch))


async def create_targets_relationships(driver) -> None:
    """
    Create [:TARGETS] edges between TTP nodes and Asset nodes based on
    asset type and subtype. This enriches simulation traversal paths.
    """
    async with driver.session() as session:
        for rule in _TACTIC_RULES:
            if rule["asset_types"]:
                await session.run(
                    """
                    MATCH (t:TTP {tactic: $tactic})
                    MATCH (a:Asset)
                    WHERE a.type IN $asset_types
                      AND a.criticality >= $min_criticality
                      AND a.source = 'cmdb'
                    MERGE (t)-[:TARGETS]->(a)
                    """,
                    tactic=rule["tactic"],
                    asset_types=rule["asset_types"],
                    min_criticality=rule["min_criticality"],
                )

            if rule["asset_subtypes"]:
                await session.run(
                    """
                    MATCH (t:TTP {tactic: $tactic})
                    MATCH (a:Asset)
                    WHERE a.subtype IN $subtypes
                      AND a.criticality >= $min_criticality
                      AND a.source = 'cmdb'
                    MERGE (t)-[:TARGETS]->(a)
                    """,
                    tactic=rule["tactic"],
                    subtypes=rule["asset_subtypes"],
                    min_criticality=rule["min_criticality"],
                )

            logger.debug("TARGETS edges created for tactic: %s", rule["tactic"])


async def create_indexes(driver) -> None:
    """Create Neo4j indexes for Asset query performance."""
    async with driver.session() as session:
        for stmt in [
            "CREATE INDEX asset_sys_id IF NOT EXISTS FOR (a:Asset) ON (a.sys_id)",
            "CREATE INDEX asset_type IF NOT EXISTS FOR (a:Asset) ON (a.type)",
            "CREATE INDEX asset_subtype IF NOT EXISTS FOR (a:Asset) ON (a.subtype)",
            "CREATE INDEX asset_criticality IF NOT EXISTS FOR (a:Asset) ON (a.criticality)",
            "CREATE INDEX asset_location IF NOT EXISTS FOR (a:Asset) ON (a.location)",
        ]:
            await session.run(stmt)
        logger.info("Neo4j indexes created/verified.")
