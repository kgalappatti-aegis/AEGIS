"""
AEGIS Simulation Agent – Neo4j Query Functions

Two flavours:
  async_*  – used by LangGraph nodes running in the asyncio event loop
  sync_*   – used by Celery tasks (separate process, sync driver)

All queries use MERGE-safe read-only patterns.
"""

from __future__ import annotations

import logging
from typing import Any

from neo4j import AsyncDriver, Driver

logger = logging.getLogger("aegis.simulation.neo4j")


# ---------------------------------------------------------------------------
# Strategy-specific Cypher queries  (Part 2)
# ---------------------------------------------------------------------------

_CYPHER_EVASION_FIRST = """
MATCH path = (entry:TTP)-[:PRECEDES*3..8]->(exit:TTP)
WHERE entry.tactic IN ['initial-access', 'execution']
  AND exit.tactic IN ['impact', 'exfiltration']
  AND ALL(r IN relationships(path) WHERE r.transition_probability > 0.3)
OPTIONAL MATCH (a:ThreatActor {name: $actor_name})-[:USES]->(t:TTP)
  WHERE t IN nodes(path)
WITH path,
     [n IN nodes(path) WHERE n.tactic IN
       ['defense-evasion','credential-access'] | n] AS evasion_nodes,
     COUNT(DISTINCT t) AS actor_overlap
WHERE SIZE(evasion_nodes) >= 1
RETURN path, actor_overlap
ORDER BY actor_overlap DESC, SIZE(nodes(path)) ASC
LIMIT 3
"""

_CYPHER_SHORTEST_PATH = """
MATCH path = shortestPath(
  (entry:TTP)-[:PRECEDES*]->(exit:TTP)
)
WHERE entry.tactic IN ['initial-access']
  AND exit.tactic IN ['impact', 'exfiltration']
OPTIONAL MATCH (a:ThreatActor {name: $actor_name})-[:USES]->(t:TTP)
  WHERE t IN nodes(path)
WITH path, COUNT(DISTINCT t) AS actor_overlap
RETURN path, actor_overlap
ORDER BY SIZE(nodes(path)) ASC, actor_overlap DESC
LIMIT 3
"""

_CYPHER_LATERAL_MOVEMENT = """
MATCH path = (entry:TTP)-[:PRECEDES*4..10]->(exit:TTP)
WHERE entry.tactic IN ['initial-access']
  AND exit.tactic IN ['impact', 'exfiltration']
  AND ANY(n IN nodes(path) WHERE n.tactic = 'lateral-movement')
  AND ANY(n IN nodes(path) WHERE n.tactic = 'discovery')
OPTIONAL MATCH (a:ThreatActor {name: $actor_name})-[:USES]->(t:TTP)
  WHERE t IN nodes(path)
WITH path, COUNT(DISTINCT t) AS actor_overlap
RETURN path, actor_overlap
ORDER BY actor_overlap DESC
LIMIT 3
"""

_CYPHER_VULN_AMPLIFIED = """
MATCH path = (entry:TTP)-[:PRECEDES*3..8]->(exit:TTP)
WHERE entry.tactic IN ['initial-access', 'execution']
  AND exit.tactic IN ['impact', 'exfiltration']
  AND ALL(r IN relationships(path) WHERE r.transition_probability > 0.3)
  AND ANY(n IN nodes(path) WHERE n.tactic IN
    ['privilege-escalation', 'impact'])
OPTIONAL MATCH (a:ThreatActor {name: $actor_name})-[:USES]->(t:TTP)
  WHERE t IN nodes(path)
WITH path, COUNT(DISTINCT t) AS actor_overlap
RETURN path, actor_overlap
ORDER BY SIZE(nodes(path)) DESC, actor_overlap DESC
LIMIT 3
"""

_CYPHER_ACTOR_EMULATION = """
MATCH (a:ThreatActor {name: $actor_name})-[:USES]->(t:TTP)
WITH COLLECT(t.mitre_id) AS actor_ttps
MATCH path = (entry:TTP)-[:PRECEDES*3..8]->(exit:TTP)
WHERE entry.tactic IN ['initial-access']
  AND exit.tactic IN ['impact', 'exfiltration']
  AND ALL(n IN nodes(path) WHERE n.mitre_id IN actor_ttps)
RETURN path, SIZE(nodes(path)) AS actor_overlap
ORDER BY actor_overlap DESC
LIMIT 3
"""

_STRATEGY_CYPHER: dict[str, str] = {
    "evasion_first":    _CYPHER_EVASION_FIRST,
    "shortest_path":    _CYPHER_SHORTEST_PATH,
    "lateral_movement": _CYPHER_LATERAL_MOVEMENT,
    "vuln_amplified":   _CYPHER_VULN_AMPLIFIED,
    "full_landscape":   _CYPHER_SHORTEST_PATH,   # full_landscape uses shortest_path query
    "actor_emulation":  _CYPHER_ACTOR_EMULATION,
}


def _extract_path_data(record: Any) -> dict[str, Any] | None:
    """Convert a Neo4j path record into a plain dict of TTP nodes and transitions."""
    path = record.get("path") if hasattr(record, "get") else record["path"]
    if path is None:
        return None

    nodes = []
    for node in path.nodes:
        props = dict(node)
        nodes.append({
            "mitre_id": props.get("mitre_id", ""),
            "name":     props.get("name", ""),
            "tactic":   props.get("tactic", ""),
            "platform": props.get("platform", []),
        })

    transitions: dict[str, float] = {}
    for rel in path.relationships:
        start_props = dict(rel.start_node)
        from_id = start_props.get("mitre_id", "")
        prob = rel.get("transition_probability", 0.5) if hasattr(rel, "get") else dict(rel).get("transition_probability", 0.5)
        if prob is None:
            prob = 0.5
        transitions[from_id] = float(prob)

    actor_overlap = record.get("actor_overlap", 0) if hasattr(record, "get") else record["actor_overlap"]

    return {
        "nodes":         nodes,
        "transitions":   transitions,
        "actor_overlap": int(actor_overlap) if actor_overlap else 0,
    }


async def async_query_paths(
    driver: AsyncDriver,
    actor_name: str | None,
    strategy: str,
) -> list[dict[str, Any]]:
    """
    Run strategy-specific Cypher to fetch attack paths from Neo4j.

    Returns a list of path dicts, each containing:
      nodes:       [{ mitre_id, name, tactic, platform }]
      transitions: { mitre_id: transition_probability }
      actor_overlap: int

    Falls back to shortest_path if actor_name is None or the query
    returns empty results.
    """
    cypher = _STRATEGY_CYPHER.get(strategy, _CYPHER_SHORTEST_PATH)

    # If no actor, skip actor-dependent strategies
    effective_actor = actor_name or "__NO_ACTOR__"

    paths: list[dict[str, Any]] = []
    try:
        async with driver.session() as session:
            result = await session.run(cypher, actor_name=effective_actor)
            records = [r async for r in result]
            for rec in records:
                data = _extract_path_data(rec)
                if data and data["nodes"]:
                    paths.append(data)
    except Exception as exc:
        logger.warning("Path query failed for strategy=%s: %s", strategy, exc)

    # Fallback: if empty and not already shortest_path, try shortest_path
    if not paths and cypher != _CYPHER_SHORTEST_PATH:
        logger.debug(
            "No paths for strategy=%s; falling back to shortest_path.", strategy,
        )
        try:
            async with driver.session() as session:
                result = await session.run(
                    _CYPHER_SHORTEST_PATH, actor_name=effective_actor,
                )
                records = [r async for r in result]
                for rec in records:
                    data = _extract_path_data(rec)
                    if data and data["nodes"]:
                        paths.append(data)
        except Exception as exc:
            logger.warning("Fallback shortest_path query failed: %s", exc)

    return paths


async def async_get_top_actor(
    driver: AsyncDriver,
    ttp_ids: list[str],
) -> str | None:
    """Return the name of the threat actor with most overlap with given TTPs."""
    if not ttp_ids:
        return None
    try:
        async with driver.session() as session:
            result = await session.run(
                """
                MATCH (a:ThreatActor)-[:USES]->(t:TTP)
                WHERE t.mitre_id IN $ttp_ids
                RETURN a.name AS name, COUNT(DISTINCT t) AS overlap
                ORDER BY overlap DESC
                LIMIT 1
                """,
                ttp_ids=ttp_ids,
            )
            record = await result.single()
            return record["name"] if record else None
    except Exception as exc:
        logger.warning("Top actor query failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Async queries  (LangGraph nodes)
# ---------------------------------------------------------------------------

async def async_get_threat_actors_for_ttps(
    driver: AsyncDriver,
    ttp_ids: list[str],
) -> list[dict[str, Any]]:
    """Return threat actors known to use any of the given TTPs."""
    async with driver.session() as session:
        result = await session.run(
            """
            MATCH (a:ThreatActor)-[:USES]->(t:TTP)
            WHERE t.mitre_id IN $ttp_ids
            RETURN a.name        AS name,
                   a.aliases     AS aliases,
                   a.nation_state AS nation_state,
                   collect(DISTINCT t.mitre_id) AS matched_ttps
            ORDER BY size(collect(DISTINCT t.mitre_id)) DESC
            LIMIT 5
            """,
            ttp_ids=ttp_ids,
        )
        return [dict(r) async for r in result]


async def async_get_asset_context(
    driver: AsyncDriver,
    asset_ids: list[str],
) -> list[dict[str, Any]]:
    """Return name, type, criticality, and known CVEs for a list of asset IDs."""
    async with driver.session() as session:
        result = await session.run(
            """
            MATCH (a:Asset)
            WHERE a.id IN $asset_ids
            OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN a.id          AS id,
                   a.name        AS name,
                   a.type        AS type,
                   a.criticality AS criticality,
                   a.os          AS os,
                   collect(DISTINCT v.cve_id) AS cve_ids
            """,
            asset_ids=asset_ids,
        )
        return [dict(r) async for r in result]


# ---------------------------------------------------------------------------
# Sync queries  (Celery tasks)
# ---------------------------------------------------------------------------

def sync_get_attack_paths(
    driver: Driver,
    cve_id: str | None,
    min_criticality: int = 4,
) -> list[dict[str, Any]]:
    """
    Return all attack paths whose target assets have criticality >=
    ``min_criticality``.

    If ``cve_id`` is supplied the result is filtered to paths that target
    assets carrying that vulnerability, with a fallback to all high-criticality
    paths when no CVE-specific paths exist (so the simulation never returns
    empty-handed).
    """
    with driver.session() as session:
        # Base query: paths to critical assets
        base_result = session.run(
            """
            MATCH (ap:AttackPath)-[:TARGETS]->(target:Asset)
            WHERE target.criticality >= $min_criticality
            WITH ap, collect(DISTINCT target.id) AS target_ids
            RETURN ap.id                  AS path_id,
                   ap.name               AS path_name,
                   ap.steps              AS steps,
                   ap.success_probability AS base_prob,
                   target_ids
            """,
            min_criticality=min_criticality,
        )
        all_paths = [dict(r) for r in base_result]

        if not all_paths:
            return []

        # CVE filter: narrow down to paths whose targets carry the CVE
        if cve_id:
            cve_result = session.run(
                """
                MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability {cve_id: $cve_id})
                RETURN collect(DISTINCT a.id) AS affected_ids
                """,
                cve_id=cve_id,
            )
            row = cve_result.single()
            affected_ids = set(row["affected_ids"]) if row else set()

            cve_paths = [
                p for p in all_paths
                if affected_ids.intersection(p["target_ids"])
            ]
            if cve_paths:
                all_paths = cve_paths
            else:
                logger.debug(
                    "No paths found targeting assets with %s; "
                    "falling back to all high-criticality paths.",
                    cve_id,
                )

        # Attach PRECEDES transition probabilities for each path.
        # Batch all transition pairs into a single Cypher call to avoid
        # N round-trips per path (the main source of timeout errors).
        all_pairs: list[dict[str, str]] = []
        for path in all_paths:
            steps: list[str] = path.get("steps") or []
            for i in range(len(steps) - 1):
                all_pairs.append({"from_id": steps[i], "to_id": steps[i + 1]})

        prob_lookup: dict[tuple[str, str], float] = {}
        if all_pairs:
            prob_result = session.run(
                """
                UNWIND $pairs AS pair
                OPTIONAL MATCH (a:TTP {mitre_id: pair.from_id})
                               -[r:PRECEDES]->
                               (b:TTP {mitre_id: pair.to_id})
                RETURN pair.from_id AS from_id,
                       pair.to_id   AS to_id,
                       r.transition_probability AS prob
                """,
                pairs=all_pairs,
            )
            for row in prob_result:
                p = row["prob"] if row["prob"] is not None else 0.5
                prob_lookup[(row["from_id"], row["to_id"])] = float(p)

        for path in all_paths:
            steps = path.get("steps") or []
            transitions: list[dict] = []
            for i in range(len(steps) - 1):
                prob = prob_lookup.get((steps[i], steps[i + 1]), 0.5)
                transitions.append({
                    "from_id": steps[i],
                    "to_id":   steps[i + 1],
                    "prob":    prob,
                })
            path["transitions"] = transitions

        return all_paths


def sync_get_detection_coverage(
    driver: Driver,
    mitre_id: str,
) -> float:
    """
    Return the detection coverage score [0, 1] for a TTP.

    Phase 3 stub: always returns 0.5.
    Phase 4 will query a DetectionRule node and return coverage based on
    deployed SIEM/EDR rules mapped to the TTP.
    """
    # Stub — Phase 4 implementation:
    # with driver.session() as session:
    #     result = session.run(
    #         "MATCH (t:TTP {mitre_id: $mid})<-[:COVERS]-(r:DetectionRule) "
    #         "WHERE r.deployed = true "
    #         "RETURN avg(r.coverage_score) AS cov",
    #         mid=mitre_id,
    #     )
    #     row = result.single()
    #     return float(row["cov"]) if row and row["cov"] else 0.0
    return 0.5
