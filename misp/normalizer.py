"""
AEGIS MISP Ingestion – Normalizer

Pure functions for converting MISP events into AEGIS-compatible event dicts.
No side effects, no I/O — all state is passed in and returned.

Responsibilities:
  - Parse MISP galaxy tags (mitre-attack-pattern, threat-actor)
  - Extract CVE IDs from MISP attributes
  - Derive TLP classification from MISP tags
  - Map threat level → AEGIS priority
  - Assemble a complete AEGIS event dict ready for Redis XADD
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Galaxy tag parsers
# ---------------------------------------------------------------------------

_MITRE_TAG_RE = re.compile(
    r'mitre-attack-pattern="([^"]+)\s*-\s*(T\d+(?:\.\d+)?)"',
)
_THREAT_ACTOR_TAG_RE = re.compile(
    r'threat-actor="([^"]+)"',
)


def extract_mitre_techniques(tags: list[dict[str, Any]]) -> list[dict[str, str]]:
    """
    Extract MITRE ATT&CK technique IDs and names from MISP galaxy tags.

    Each tag dict has a ``"name"`` key like:
        ``mitre-attack-pattern="Spearphishing Attachment - T1566.001"``

    Returns a list of ``{"technique_id": "T1566.001", "name": "Spearphishing Attachment"}``.
    """
    techniques: list[dict[str, str]] = []
    seen: set[str] = set()
    for tag in tags:
        tag_name = tag.get("name", "")
        match = _MITRE_TAG_RE.search(tag_name)
        if match and match.group(2) not in seen:
            seen.add(match.group(2))
            techniques.append({
                "technique_id": match.group(2),
                "name": match.group(1).strip(),
            })
    return techniques


def extract_threat_actors(tags: list[dict[str, Any]]) -> list[str]:
    """
    Extract threat actor names from MISP galaxy tags.

    Tag format: ``threat-actor="APT29"``
    """
    actors: list[str] = []
    seen: set[str] = set()
    for tag in tags:
        tag_name = tag.get("name", "")
        match = _THREAT_ACTOR_TAG_RE.search(tag_name)
        if match and match.group(1) not in seen:
            seen.add(match.group(1))
            actors.append(match.group(1))
    return actors


# ---------------------------------------------------------------------------
# CVE extraction
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def extract_cves(attributes: list[dict[str, Any]]) -> list[str]:
    """
    Extract unique CVE IDs from MISP event attributes.

    Searches attribute ``value`` and ``comment`` fields for CVE patterns.
    """
    cves: set[str] = set()
    for attr in attributes:
        for field in ("value", "comment"):
            text = attr.get(field, "")
            if text:
                cves.update(m.upper() for m in _CVE_RE.findall(text))
    return sorted(cves)


# ---------------------------------------------------------------------------
# TLP classification
# ---------------------------------------------------------------------------

_TLP_ORDER = {"tlp:red": 4, "tlp:amber": 3, "tlp:green": 2, "tlp:white": 1}


def extract_tlp(tags: list[dict[str, Any]]) -> str:
    """
    Derive TLP classification from MISP tags.

    Returns the most restrictive TLP found, defaulting to ``"tlp:green"``.
    """
    best: str = "tlp:green"
    best_rank: int = _TLP_ORDER.get(best, 2)
    for tag in tags:
        tag_name = tag.get("name", "").lower().strip()
        rank = _TLP_ORDER.get(tag_name, 0)
        if rank > best_rank:
            best = tag_name
            best_rank = rank
    return best


# ---------------------------------------------------------------------------
# Priority mapping
# ---------------------------------------------------------------------------

_THREAT_LEVEL_TO_PRIORITY: dict[str, str] = {
    "1": "P0",   # High
    "2": "P1",   # Medium
    "3": "P2",   # Low
    "4": "P3",   # Undefined
}


def misp_threat_level_to_priority(threat_level_id: str) -> str:
    """
    Map MISP ``threat_level_id`` (1=High … 4=Undefined) to AEGIS priority.
    """
    return _THREAT_LEVEL_TO_PRIORITY.get(str(threat_level_id), "P2")


# ---------------------------------------------------------------------------
# Full event normalizer
# ---------------------------------------------------------------------------

def normalize_misp_event(misp_event: dict[str, Any]) -> dict[str, str]:
    """
    Convert a single MISP event into a flat ``dict[str, str]`` suitable for
    ``XADD`` to ``aegis:events:inbound``.

    The returned dict matches the AEGISEvent schema fields expected by the
    orchestrator.

    Parameters
    ----------
    misp_event : dict
        A single MISP event object (the ``"Event"`` wrapper is stripped by
        the caller if present).

    Returns
    -------
    dict[str, str]
        Flat key-value pairs ready for Redis XADD.
    """
    # Unwrap {"Event": {...}} envelope if present
    if "Event" in misp_event:
        misp_event = misp_event["Event"]

    tags = misp_event.get("Tag", [])
    attributes = misp_event.get("Attribute", [])
    galaxies = misp_event.get("Galaxy", [])

    # Flatten galaxy cluster tags into the top-level tags list
    all_tags = list(tags)
    for galaxy in galaxies:
        for cluster in galaxy.get("GalaxyCluster", []):
            cluster_tag = cluster.get("tag_name", "")
            if cluster_tag:
                all_tags.append({"name": cluster_tag})

    techniques = extract_mitre_techniques(all_tags)
    actors = extract_threat_actors(all_tags)
    cves = extract_cves(attributes)
    tlp = extract_tlp(all_tags)
    priority = misp_threat_level_to_priority(misp_event.get("threat_level_id", "3"))

    # Build raw_payload with MISP-specific context
    import json
    raw_payload: dict[str, Any] = {
        "misp_event_id": misp_event.get("id", ""),
        "misp_uuid": misp_event.get("uuid", ""),
        "info": misp_event.get("info", ""),
        "title": misp_event.get("info", ""),
        "cve_ids": cves,
        "cve_id": cves[0] if cves else None,
        "misp_techniques": [t["technique_id"] for t in techniques],
        "misp_technique_details": techniques,
        "threat_actors": actors,
        "tlp": tlp,
        "threat_level_id": misp_event.get("threat_level_id", ""),
        "analysis": misp_event.get("analysis", ""),
        "date": misp_event.get("date", ""),
        "published": misp_event.get("publish_timestamp", ""),
        "attribute_count": len(attributes),
    }

    event_id = str(uuid.uuid4())

    return {
        "event_id": event_id,
        "source_type": "misp",
        "priority": priority,
        "routing_target": "triage",
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "ttl": "86400",
        "raw_payload": json.dumps(raw_payload, separators=(",", ":")),
    }


def misp_event_dedup_key(misp_event: dict[str, Any]) -> str:
    """
    Return a stable deduplication key for a MISP event.

    Uses the MISP UUID, which is globally unique and stable across
    republications of the same event.
    """
    if "Event" in misp_event:
        misp_event = misp_event["Event"]
    return misp_event.get("uuid", "")
