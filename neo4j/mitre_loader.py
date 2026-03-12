#!/usr/bin/env python3
"""
AEGIS MITRE ATT&CK Loader

One-shot script that downloads the Enterprise ATT&CK STIX 2.1 bundle
from GitHub and loads it into Neo4j, extending the existing AEGIS schema.

What is loaded
--------------
  :TTP           – attack-pattern objects  (skip deprecated / revoked)
  :ThreatActor   – intrusion-set objects
  :Mitigation    – course-of-action objects
  [:USES]        – intrusion-set → attack-pattern
  [:MITIGATES]   – course-of-action → attack-pattern
  [:PRECEDES]    – tactic kill-chain ordering, boosted where co-used by actor

Usage
-----
    python mitre_loader.py

Environment variables
---------------------
    NEO4J_URL       bolt://neo4j:7687                          (default)
    NEO4J_USER      neo4j                                      (default)
    NEO4J_PASSWORD  <required>
    MITRE_STIX_URL  enterprise-attack.json GitHub URL          (default)
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections import defaultdict
from typing import Any

import httpx
import redis as redis_sync
import stix2
from datetime import datetime
from dotenv import load_dotenv
from neo4j import GraphDatabase, Driver

load_dotenv()

# ---------------------------------------------------------------------------
# Redis (synchronous — this is a one-shot script, not an async agent)
# ---------------------------------------------------------------------------

redis_client = redis_sync.Redis(
    host=os.getenv("REDIS_HOST", "redis"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    decode_responses=True,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

STIX_URL = os.getenv(
    "MITRE_STIX_URL",
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json",
)

NEO4J_URL      = os.getenv("NEO4J_URL",      "bolt://neo4j:7687")
NEO4J_USER     = os.getenv("NEO4J_USER",     "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")

if not NEO4J_PASSWORD:
    sys.exit("ERROR: NEO4J_PASSWORD environment variable is required.")

# ATT&CK tactic kill-chain order (STIX phase_name values, lowercase-hyphenated)
TACTIC_CHAIN: list[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

TACTIC_CHAIN_IDX: dict[str, int] = {t: i for i, t in enumerate(TACTIC_CHAIN)}

# Keywords used to infer nation_state=True from actor name/aliases/description
_NATION_STATE_KW = frozenset([
    "china", "chinese", "prc", "people's republic",
    "russia", "russian", "svr", "fsb", "gru", "cozy bear", "fancy bear",
    "north korea", "north korean", "dprk", "lazarus",
    "iran", "iranian", "irgc", "charming kitten",
    "vietnam", "vietnamese", "apt32",
    "india", "indian", "sidewinder",
    "state-sponsored", "nation-state", "government-backed",
])

# Rows per Neo4j UNWIND batch
_BATCH = 500


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _trunc(s: str | None, n: int) -> str:
    if not s:
        return ""
    return s[:n]


def _list_attr(obj: Any, key: str) -> list:
    """Safe list access that works on both stix2 objects and plain dicts."""
    try:
        val = obj.get(key, []) if hasattr(obj, "get") else getattr(obj, key, [])
    except Exception:
        val = []
    return val if isinstance(val, list) else []


def _mitre_id(obj: Any) -> str | None:
    """Return the T#### / M#### id from external_references, or None."""
    for ref in _list_attr(obj, "external_references"):
        src = ref.get("source_name") if isinstance(ref, dict) else getattr(ref, "source_name", "")
        if src == "mitre-attack":
            eid = ref.get("external_id") if isinstance(ref, dict) else getattr(ref, "external_id", None)
            return eid
    return None


def _bool_attr(obj: Any, key: str, default: bool = False) -> bool:
    try:
        val = obj.get(key) if hasattr(obj, "get") else getattr(obj, key, None)
    except Exception:
        val = None
    return bool(val) if val is not None else default


def _str_attr(obj: Any, key: str, default: str = "") -> str:
    try:
        val = obj.get(key) if hasattr(obj, "get") else getattr(obj, key, None)
    except Exception:
        val = None
    return str(val) if val is not None else default


def _is_nation_state(name: str, aliases: list[str], desc: str) -> bool:
    text = " ".join([name.lower()] + [a.lower() for a in aliases] + [desc.lower()[:400]])
    return any(kw in text for kw in _NATION_STATE_KW)


def classify_detection_coverage(text: str) -> str:
    """
    Classify MITRE detection text into stub coverage tiers.

    "none"    — field is empty, or text is under 60 chars,
                or text contains only generic phrases like
                "Monitor for" with no specific data sources mentioned.

    "partial" — text is 60+ chars AND mentions at least one of:
                ["process", "network", "command", "log", "event",
                 "registry", "file", "script", "audit", "sysmon",
                 "endpoint", "EDR", "SIEM", "signature"]

    Never returns "detected" — that tier is reserved for the
    Detection Agent after it generates and validates real Sigma rules.
    """
    if not text or len(text.strip()) < 60:
        return "none"
    keywords = [
        "process", "network", "command", "log", "event",
        "registry", "file", "script", "audit", "sysmon",
        "endpoint", "EDR", "SIEM", "signature",
    ]
    text_lower = text.lower()
    if any(kw in text_lower for kw in keywords):
        return "partial"
    return "none"


def extract_sigma_hint(text: str) -> str:
    """
    Pull the first complete sentence from the detection text
    to use as a human-readable sigma rule hint.
    Truncate to 120 chars max. Return empty string if no text.
    """
    if not text:
        return ""
    first_sentence = text.split(".")[0].strip()
    return first_sentence[:120] if first_sentence else ""


# ---------------------------------------------------------------------------
# Step 1: Download
# ---------------------------------------------------------------------------

def download_bundle(url: str) -> bytes:
    print(f"\n── Download ────────────────────────────────────────────────────────")
    print(f"  URL: {url}")
    t0 = time.monotonic()
    with httpx.Client(follow_redirects=True, timeout=120) as client:
        resp = client.get(url)
        resp.raise_for_status()
    elapsed = time.monotonic() - t0
    size_mb = len(resp.content) / (1024 * 1024)
    print(f"  ✓ {size_mb:.1f} MB in {elapsed:.1f}s")
    return resp.content


# ---------------------------------------------------------------------------
# Step 2: Parse STIX bundle
# ---------------------------------------------------------------------------

def parse_bundle(raw: bytes) -> tuple[
    dict[str, dict],   # techniques   stix_id → props
    dict[str, dict],   # actors       stix_id → props
    dict[str, dict],   # mitigations  stix_id → props
    list[dict],        # relationships
]:
    print(f"\n── Parse ───────────────────────────────────────────────────────────")
    t0 = time.monotonic()

    # Use stix2 to parse the bundle (allow_custom covers all x_mitre_* fields)
    bundle = stix2.parse(raw.decode("utf-8"), allow_custom=True)
    objects = list(bundle.objects)

    elapsed = time.monotonic() - t0
    print(f"  stix2.parse: {len(objects)} objects in {elapsed:.1f}s")

    techniques:   dict[str, dict] = {}
    actors:       dict[str, dict] = {}
    mitigations:  dict[str, dict] = {}
    relationships: list[dict]     = []

    skipped_deprecated = 0

    for obj in objects:
        otype = _str_attr(obj, "type")
        oid   = _str_attr(obj, "id")

        # Skip deprecated / revoked across all types
        if _bool_attr(obj, "x_mitre_deprecated") or _bool_attr(obj, "x_mitre_revoked"):
            skipped_deprecated += 1
            continue

        # ── attack-pattern → :TTP ─────────────────────────────────────────
        if otype == "attack-pattern":
            mid = _mitre_id(obj)
            if not mid:
                continue

            kc_phases = _list_attr(obj, "kill_chain_phases")
            tactics = [
                (kc.get("phase_name") if isinstance(kc, dict) else getattr(kc, "phase_name", ""))
                for kc in kc_phases
                if (kc.get("kill_chain_name") if isinstance(kc, dict) else getattr(kc, "kill_chain_name", "")) == "mitre-attack"
            ]

            raw_detection = _str_attr(obj, "x_mitre_detection")
            data_sources = _list_attr(obj, "x_mitre_data_sources")

            techniques[oid] = {
                "stix_id":        oid,
                "mitre_id":       mid,
                "name":           _str_attr(obj, "name"),
                "description":    _trunc(_str_attr(obj, "description"), 500),
                "tactic":         tactics[0] if tactics else "",
                "tactics":        tactics,
                "platform":       _list_attr(obj, "x_mitre_platforms"),
                "detection":      raw_detection,
                "is_subtechnique": _bool_attr(obj, "x_mitre_is_subtechnique"),
                "data_sources":   data_sources,
                "sigma_hint":     extract_sigma_hint(raw_detection),
            }

        # ── intrusion-set → :ThreatActor ──────────────────────────────────
        elif otype == "intrusion-set":
            name    = _str_attr(obj, "name")
            aliases = [a for a in _list_attr(obj, "aliases") if a != name]
            desc    = _str_attr(obj, "description")
            actors[oid] = {
                "stix_id":     oid,
                "name":        name,
                "aliases":     aliases,
                "description": _trunc(desc, 300),
                "nation_state": _is_nation_state(name, aliases, desc),
            }

        # ── course-of-action → :Mitigation ───────────────────────────────
        elif otype == "course-of-action":
            mid = _mitre_id(obj)
            if not mid or not mid.startswith("M"):
                continue
            mitigations[oid] = {
                "stix_id":     oid,
                "mitre_id":    mid,
                "name":        _str_attr(obj, "name"),
                "description": _trunc(_str_attr(obj, "description"), 300),
            }

        # ── relationship ──────────────────────────────────────────────────
        elif otype == "relationship":
            relationships.append({
                "rel_type":   _str_attr(obj, "relationship_type"),
                "source_ref": _str_attr(obj, "source_ref"),
                "target_ref": _str_attr(obj, "target_ref"),
            })

    print(f"  techniques={len(techniques)}  actors={len(actors)}  "
          f"mitigations={len(mitigations)}  relationships={len(relationships)}")
    print(f"  skipped (deprecated/revoked): {skipped_deprecated}")
    return techniques, actors, mitigations, relationships


# ---------------------------------------------------------------------------
# Neo4j batch helper
# ---------------------------------------------------------------------------

def _run_batched(session: Any, cypher: str, rows: list[dict]) -> int:
    total = 0
    for i in range(0, max(len(rows), 1), _BATCH):
        session.run(cypher, rows=rows[i : i + _BATCH])
        total += len(rows[i : i + _BATCH])
    return total


# ---------------------------------------------------------------------------
# Step 3a: Load :TTP nodes
# ---------------------------------------------------------------------------

def load_techniques(driver: Driver, techniques: dict) -> int:
    print(f"\n── Nodes ───────────────────────────────────────────────────────────")
    rows = list(techniques.values())
    cypher = """
        UNWIND $rows AS row
        MERGE (t:TTP {mitre_id: row.mitre_id})
        SET t.name            = row.name,
            t.description     = row.description,
            t.tactic          = row.tactic,
            t.tactics         = row.tactics,
            t.platform        = row.platform,
            t.detection       = row.detection,
            t.is_subtechnique  = row.is_subtechnique,
            t.data_sources    = row.data_sources,
            t.sigma_hint      = row.sigma_hint
    """
    with driver.session() as s:
        n = _run_batched(s, cypher, rows)
    print(f"  ✓ TTP               × {n}")
    return n


# ---------------------------------------------------------------------------
# Step 3b: Load :ThreatActor nodes
# ---------------------------------------------------------------------------

def load_actors(driver: Driver, actors: dict) -> int:
    rows = list(actors.values())
    cypher = """
        UNWIND $rows AS row
        MERGE (a:ThreatActor {name: row.name})
        SET a.aliases      = row.aliases,
            a.description  = row.description,
            a.nation_state = row.nation_state
    """
    with driver.session() as s:
        n = _run_batched(s, cypher, rows)
    print(f"  ✓ ThreatActor       × {n}")
    return n


# ---------------------------------------------------------------------------
# Step 3c: Load :Mitigation nodes (+ constraint)
# ---------------------------------------------------------------------------

def load_mitigations(driver: Driver, mitigations: dict) -> int:
    with driver.session() as s:
        s.run("""
            CREATE CONSTRAINT Mitigation_mitre_id_unique IF NOT EXISTS
            FOR (m:Mitigation) REQUIRE m.mitre_id IS UNIQUE
        """)

    rows = list(mitigations.values())
    cypher = """
        UNWIND $rows AS row
        MERGE (m:Mitigation {mitre_id: row.mitre_id})
        SET m.name        = row.name,
            m.description = row.description
    """
    with driver.session() as s:
        n = _run_batched(s, cypher, rows)
    print(f"  ✓ Mitigation        × {n}")
    return n


# ---------------------------------------------------------------------------
# Step 4a: Actor → TTP USES relationships
# ---------------------------------------------------------------------------

def load_actor_ttp_rels(
    driver: Driver,
    relationships: list[dict],
    techniques: dict,
    actors: dict,
) -> int:
    print(f"\n── Relationships ───────────────────────────────────────────────────")
    stix_to_mitre  = {v["stix_id"]: v["mitre_id"] for v in techniques.values()}
    stix_to_actor  = {v["stix_id"]: v["name"]     for v in actors.values()}

    rows = []
    for rel in relationships:
        if rel["rel_type"] != "uses":
            continue
        actor_name = stix_to_actor.get(rel["source_ref"])
        mitre_id   = stix_to_mitre.get(rel["target_ref"])
        if actor_name and mitre_id:
            rows.append({"actor_name": actor_name, "mitre_id": mitre_id})

    cypher = """
        UNWIND $rows AS row
        MATCH (a:ThreatActor {name:     row.actor_name})
        MATCH (t:TTP         {mitre_id: row.mitre_id})
        MERGE (a)-[:USES]->(t)
    """
    with driver.session() as s:
        n = _run_batched(s, cypher, rows)
    print(f"  ✓ USES (actor→TTP)  × {n}")
    return n


# ---------------------------------------------------------------------------
# Step 4b: TTP → TTP PRECEDES relationships
# ---------------------------------------------------------------------------

def _build_boosted_pairs(
    relationships: list[dict],
    techniques: dict,
    actors: dict,
) -> set[tuple[str, str]]:
    """
    Find (from_mitre_id, to_mitre_id) pairs that should receive
    transition_probability=0.7 because at least one threat actor uses
    both techniques in adjacent tactics.

    Only parent techniques (is_subtechnique=False) are considered to
    keep the PRECEDES edge count tractable.
    """
    stix_to_ttp    = {v["stix_id"]: v for v in techniques.values()}
    actor_stix_ids = {v["stix_id"] for v in actors.values()}

    # actor_stix_id → {tactic_idx: set(mitre_id)}
    actor_by_tactic: dict[str, dict[int, set[str]]] = defaultdict(lambda: defaultdict(set))

    for rel in relationships:
        if rel["rel_type"] != "uses":
            continue
        src = rel["source_ref"]
        tgt = rel["target_ref"]
        if src not in actor_stix_ids:
            continue
        ttp = stix_to_ttp.get(tgt)
        if not ttp or ttp.get("is_subtechnique"):
            continue
        tactic = ttp.get("tactic", "")
        idx    = TACTIC_CHAIN_IDX.get(tactic)
        if idx is not None:
            actor_by_tactic[src][idx].add(ttp["mitre_id"])

    boosted: set[tuple[str, str]] = set()

    for actor_id, tactic_map in actor_by_tactic.items():
        indices = sorted(tactic_map.keys())
        for i in range(len(indices) - 1):
            ci = indices[i]
            ni = indices[i + 1]
            if ni != ci + 1:
                continue   # tactics must be truly adjacent in the chain
            for a in tactic_map[ci]:
                for b in tactic_map[ni]:
                    boosted.add((a, b))

    return boosted


def load_precedes_rels(
    driver: Driver,
    techniques: dict,
    relationships: list[dict],
    actors: dict,
) -> int:
    # Group PARENT technique mitre_ids by tactic
    by_tactic: dict[str, list[str]] = defaultdict(list)
    for ttp in techniques.values():
        if ttp.get("is_subtechnique"):
            continue
        tactic = ttp.get("tactic", "")
        if tactic in TACTIC_CHAIN_IDX:
            by_tactic[tactic].append(ttp["mitre_id"])

    boosted = _build_boosted_pairs(relationships, techniques, actors)
    boosted_count = 0

    rows: list[dict] = []
    for i in range(len(TACTIC_CHAIN) - 1):
        src_tactic = TACTIC_CHAIN[i]
        dst_tactic = TACTIC_CHAIN[i + 1]
        for a in by_tactic.get(src_tactic, []):
            for b in by_tactic.get(dst_tactic, []):
                prob = 0.7 if (a, b) in boosted else 0.3
                if prob == 0.7:
                    boosted_count += 1
                rows.append({"from_id": a, "to_id": b, "prob": prob})

    # ON MATCH: only raise probability, never lower it (preserves hand-curated values)
    cypher = """
        UNWIND $rows AS row
        MATCH (a:TTP {mitre_id: row.from_id})
        MATCH (b:TTP {mitre_id: row.to_id})
        MERGE (a)-[r:PRECEDES]->(b)
        ON CREATE SET r.transition_probability = row.prob
        ON MATCH  SET r.transition_probability = CASE
            WHEN row.prob > r.transition_probability THEN row.prob
            ELSE r.transition_probability
        END
    """
    with driver.session() as s:
        n = _run_batched(s, cypher, rows)
    print(f"  ✓ PRECEDES          × {n}  ({boosted_count} boosted to 0.7)")
    return n


# ---------------------------------------------------------------------------
# Step 4c: Mitigation → TTP MITIGATES relationships
# ---------------------------------------------------------------------------

def load_mitigates_rels(
    driver: Driver,
    relationships: list[dict],
    techniques: dict,
    mitigations: dict,
) -> int:
    stix_to_ttp = {v["stix_id"]: v["mitre_id"] for v in techniques.values()}
    stix_to_mit = {v["stix_id"]: v["mitre_id"] for v in mitigations.values()}

    rows = []
    for rel in relationships:
        if rel["rel_type"] != "mitigates":
            continue
        mit_id = stix_to_mit.get(rel["source_ref"])
        ttp_id = stix_to_ttp.get(rel["target_ref"])
        if mit_id and ttp_id:
            rows.append({"mit_id": mit_id, "ttp_id": ttp_id})

    cypher = """
        UNWIND $rows AS row
        MATCH (m:Mitigation {mitre_id: row.mit_id})
        MATCH (t:TTP        {mitre_id: row.ttp_id})
        MERGE (m)-[:MITIGATES]->(t)
    """
    with driver.session() as s:
        n = _run_batched(s, cypher, rows)
    print(f"  ✓ MITIGATES         × {n}")
    return n


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(driver: Driver) -> None:
    print("\n── Graph Summary ───────────────────────────────────────────────────")
    labels = ["TTP", "ThreatActor", "Mitigation", "Asset", "Vulnerability", "AttackPath"]
    rels   = ["PRECEDES", "USES", "MITIGATES", "HAS_VULNERABILITY", "TARGETS", "USES_TTP"]
    with driver.session() as s:
        for label in labels:
            r = s.run(f"MATCH (n:{label}) RETURN count(n) AS c").single()
            print(f"  {label:<20} {r['c']:>6} nodes")
        print()
        for rel in rels:
            r = s.run(f"MATCH ()-[r:{rel}]->() RETURN count(r) AS c").single()
            print(f"  [:{rel:<22}]  {r['c']:>6} relationships")


# ---------------------------------------------------------------------------
# Step 5: Write Redis detection stubs
# ---------------------------------------------------------------------------

def write_redis_stubs(techniques: dict) -> None:
    """Pre-populate Redis hashes with stub coverage data from MITRE detection text."""
    print(f"\n── Redis Stubs ─────────────────────────────────────────────────────")

    coverage_map: dict[str, str] = {}
    sigma_map: dict[str, str] = {}
    data_sources_map: dict[str, str] = {}

    for ttp in techniques.values():
        mitre_id = ttp["mitre_id"]
        raw_detection = ttp.get("detection", "")
        data_sources = ttp.get("data_sources", [])

        coverage_map[mitre_id] = classify_detection_coverage(raw_detection)
        sigma_map[mitre_id] = extract_sigma_hint(raw_detection)
        data_sources_map[mitre_id] = json.dumps(data_sources)

    pipe = redis_client.pipeline()
    for mid, cov in coverage_map.items():
        pipe.hset("aegis:detection:coverage", mid, cov)
    for mid, hint in sigma_map.items():
        if hint:
            pipe.hset("aegis:detection:sigma", mid, hint)
    for mid, ds in data_sources_map.items():
        pipe.hset("aegis:detection:data_sources", mid, ds)
    pipe.set("aegis:detection:loaded_at", datetime.utcnow().isoformat())
    pipe.set("aegis:detection:technique_count", len(coverage_map))
    pipe.execute()

    print(f"  ✓ Wrote coverage stubs for {len(coverage_map)} techniques")
    print(f"  partial: {sum(1 for v in coverage_map.values() if v == 'partial')}")
    print(f"  none:    {sum(1 for v in coverage_map.values() if v == 'none')}")


# ---------------------------------------------------------------------------
# Verify (--verify flag)
# ---------------------------------------------------------------------------

def verify_redis() -> None:
    total = redis_client.hlen("aegis:detection:coverage")
    partial = sum(1 for v in redis_client.hvals("aegis:detection:coverage")
                  if v == "partial")
    detected = sum(1 for v in redis_client.hvals("aegis:detection:coverage")
                   if v == "detected")
    none_ = total - partial - detected
    loaded_at = redis_client.get("aegis:detection:loaded_at") or "unknown"

    print(f"\n=== aegis:detection:coverage ===")
    print(f"  Total techniques : {total}")
    print(f"  none             : {none_}")
    print(f"  partial          : {partial}")
    print(f"  detected         : {detected}")
    print(f"  Loaded at        : {loaded_at}")

    # Spot-check 5 high-value techniques
    spot = ["T1190", "T1059", "T1486", "T1027", "T1021"]
    print(f"\nSpot-check:")
    for tid in spot:
        cov = redis_client.hget("aegis:detection:coverage", tid) or "MISSING"
        hint = (redis_client.hget("aegis:detection:sigma", tid) or "")[:60]
        print(f"  {tid}  cov={cov:<8}  hint={hint!r}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print("AEGIS MITRE ATT&CK Loader")
    print(f"Neo4j: {NEO4J_URL}  user: {NEO4J_USER}")

    # ── Download ─────────────────────────────────────────────────────────
    raw = download_bundle(STIX_URL)

    # ── Parse ────────────────────────────────────────────────────────────
    techniques, actors, mitigations, relationships = parse_bundle(raw)

    # ── Connect ──────────────────────────────────────────────────────────
    print(f"\n── Neo4j ───────────────────────────────────────────────────────────")
    driver = GraphDatabase.driver(NEO4J_URL, auth=(NEO4J_USER, NEO4J_PASSWORD))
    driver.verify_connectivity()
    print("  Connected.")

    t0 = time.monotonic()

    # ── Nodes ────────────────────────────────────────────────────────────
    n_techniques  = load_techniques(driver, techniques)
    n_actors      = load_actors(driver, actors)
    n_mitigations = load_mitigations(driver, mitigations)

    # ── Relationships ─────────────────────────────────────────────────────
    n_uses      = load_actor_ttp_rels(driver, relationships, techniques, actors)
    n_precedes  = load_precedes_rels(driver, techniques, relationships, actors)
    n_mitigates = load_mitigates_rels(driver, relationships, techniques, mitigations)

    print_summary(driver)
    driver.close()

    # ── Redis stubs ───────────────────────────────────────────────────────
    write_redis_stubs(techniques)

    elapsed = time.monotonic() - t0
    print(f"\n✓ Load complete in {elapsed:.1f}s")
    print(f"  Techniques: {n_techniques}  |  Actors: {n_actors}  |  Mitigations: {n_mitigations}")
    print(f"  USES: {n_uses}  |  PRECEDES: {n_precedes}  |  MITIGATES: {n_mitigates}")


if __name__ == "__main__":
    if "--verify" in sys.argv:
        verify_redis()
    else:
        main()
