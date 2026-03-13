"""
AEGIS Triage – External Enrichment APIs

Six zero-friction, keyless APIs queried at triage time:

  Tier 1
  ------
  EPSS (FIRST.org)     – Exploitation probability score [0,1]
  CISA KEV             – Known Exploited Vulnerabilities catalog
  CIRCL CVE            – CVE 5.1 records with SSVC decision tree scores

  Tier 2
  ------
  ThreatFox (abuse.ch) – IOC database: C2 IPs/domains, malware hashes,
                          actor attribution.  Direct threat_actor signal.
  MalwareBazaar        – Hash lookup: malware family, tags, actors.
                          Enriches EDR/SIEM events with file hashes.
  OSV (Google)         – Open Source Vulnerability database.  Affected
                          packages/versions for infrastructure_match.

All APIs are free, require no key, and are called concurrently.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger("aegis.triage.enrichment")

# ---------------------------------------------------------------------------
# Data container
# ---------------------------------------------------------------------------

@dataclass
class EnrichmentData:
    """Aggregated enrichment signals from external APIs."""

    # EPSS
    epss_score: float | None = None        # [0, 1] exploitation probability
    epss_percentile: float | None = None   # [0, 1]

    # CISA KEV
    in_kev: bool = False
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    kev_ransomware: str | None = None      # "Known", "Unknown"

    # CIRCL / SSVC
    ssvc_exploitation: str | None = None   # "active", "poc", "none"
    ssvc_automatable: str | None = None    # "yes", "no"
    ssvc_technical_impact: str | None = None  # "total", "partial"
    circl_cwe: list[str] = field(default_factory=list)

    # ThreatFox
    threatfox_malware: str | None = None        # e.g. "CobaltStrike"
    threatfox_actor: str | None = None           # e.g. "Lazarus Group"
    threatfox_confidence: int | None = None      # 0-100

    # MalwareBazaar
    malware_family: str | None = None            # e.g. "AgentTesla"
    malware_tags: list[str] = field(default_factory=list)

    # OSV
    osv_affected_packages: list[str] = field(default_factory=list)  # ["Maven:log4j-core", ...]
    osv_fix_available: bool = False


# ---------------------------------------------------------------------------
# KEV catalog cache (in-memory, refreshed every 24 h)
# ---------------------------------------------------------------------------

_kev_set: set[str] = set()
_kev_details: dict[str, dict[str, Any]] = {}
_kev_loaded_at: float = 0.0
_KEV_TTL_S = 86_400  # 24 h

_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


async def _refresh_kev_catalog(client: httpx.AsyncClient) -> None:
    """Download and cache the full KEV catalog if stale."""
    global _kev_set, _kev_details, _kev_loaded_at

    if time.monotonic() - _kev_loaded_at < _KEV_TTL_S and _kev_set:
        return  # cache is fresh

    try:
        resp = await client.get(_KEV_URL, timeout=15.0)
        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        new_set: set[str] = set()
        new_details: dict[str, dict[str, Any]] = {}
        for v in vulns:
            cve = v.get("cveID", "")
            if cve:
                new_set.add(cve)
                new_details[cve] = v

        _kev_set = new_set
        _kev_details = new_details
        _kev_loaded_at = time.monotonic()
        logger.info("KEV catalog refreshed: %d entries.", len(_kev_set))

    except Exception as exc:
        logger.warning("KEV catalog refresh failed: %s", exc)


# ---------------------------------------------------------------------------
# Tier 1 fetchers
# ---------------------------------------------------------------------------

async def _fetch_epss(
    client: httpx.AsyncClient,
    cve_id: str,
) -> tuple[float | None, float | None]:
    """Return (epss_score, percentile) or (None, None) on failure."""
    try:
        resp = await client.get(
            "https://api.first.org/data/v1/epss",
            params={"cve": cve_id},
            timeout=10.0,
        )
        resp.raise_for_status()
        records = resp.json().get("data", [])
        if records:
            rec = records[0]
            return float(rec["epss"]), float(rec["percentile"])
    except Exception as exc:
        logger.debug("EPSS lookup failed for %s: %s", cve_id, exc)
    return None, None


async def _fetch_kev(
    client: httpx.AsyncClient,
    cve_id: str,
) -> tuple[bool, dict[str, Any]]:
    """Return (in_kev, details_dict).  Refreshes catalog if stale."""
    await _refresh_kev_catalog(client)
    if cve_id in _kev_set:
        return True, _kev_details.get(cve_id, {})
    return False, {}


async def _fetch_circl(
    client: httpx.AsyncClient,
    cve_id: str,
) -> dict[str, Any]:
    """Return CIRCL CVE record or empty dict on failure."""
    try:
        resp = await client.get(
            f"https://cve.circl.lu/api/cve/{cve_id}",
            timeout=10.0,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.debug("CIRCL lookup failed for %s: %s", cve_id, exc)
    return {}


def _extract_ssvc(circl: dict[str, Any]) -> dict[str, str | None]:
    """Pull SSVC decision tree scores from a CIRCL record."""
    result: dict[str, str | None] = {
        "exploitation": None,
        "automatable": None,
        "technical_impact": None,
    }
    for path in (
        circl,
        circl.get("containers", {}).get("cna", {}),
    ):
        metrics = path.get("metrics", []) if isinstance(path, dict) else []
        if isinstance(metrics, list):
            for m in metrics:
                ssvc = m.get("other", {})
                if ssvc.get("type") == "ssvc":
                    content = ssvc.get("content", {})
                    result["exploitation"] = content.get("exploitation") or content.get("Exploitation")
                    result["automatable"] = content.get("automatable") or content.get("Automatable")
                    result["technical_impact"] = content.get("technicalImpact") or content.get("Technical Impact")
                    return result

    for key_map in [
        ("exploitation", ["exploitation", "Exploitation"]),
        ("automatable", ["automatable", "Automatable"]),
        ("technical_impact", ["technicalImpact", "Technical Impact", "technical_impact"]),
    ]:
        field_name, candidates = key_map
        for c in candidates:
            val = circl.get(c)
            if val is not None:
                result[field_name] = str(val).lower()
                break

    return result


# ---------------------------------------------------------------------------
# Tier 2 fetchers
# ---------------------------------------------------------------------------

async def _fetch_threatfox_ioc(
    client: httpx.AsyncClient,
    ioc_value: str,
    auth_key: str = "",
) -> dict[str, Any]:
    """
    Search ThreatFox for an IOC (IP, domain, hash, URL).

    Requires a free Auth-Key from https://auth.abuse.ch/
    Returns the best match record or empty dict.
    """
    if not auth_key:
        return {}
    try:
        resp = await client.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ioc_value},
            headers={"Auth-Key": auth_key},
            timeout=10.0,
        )
        if resp.status_code != 200:
            return {}
        data = resp.json()
        if data.get("query_status") == "ok" and data.get("data"):
            return data["data"][0]
    except Exception as exc:
        logger.debug("ThreatFox lookup failed for %s: %s", ioc_value, exc)
    return {}


async def _fetch_malwarebazaar_hash(
    client: httpx.AsyncClient,
    file_hash: str,
    auth_key: str = "",
) -> dict[str, Any]:
    """
    Look up a file hash (SHA256/MD5/SHA1) in MalwareBazaar.

    Requires a free Auth-Key from https://auth.abuse.ch/
    Returns the sample record or empty dict.
    """
    if not auth_key:
        return {}
    try:
        resp = await client.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": file_hash},
            headers={"Auth-Key": auth_key},
            timeout=10.0,
        )
        if resp.status_code != 200:
            return {}
        data = resp.json()
        if data.get("query_status") == "ok" and data.get("data"):
            return data["data"][0]
    except Exception as exc:
        logger.debug("MalwareBazaar lookup failed for %s: %s", file_hash, exc)
    return {}


async def _fetch_osv(
    client: httpx.AsyncClient,
    cve_id: str,
) -> dict[str, Any]:
    """
    Query OSV for a CVE.  Tries the direct vulnerability endpoint first
    (works when OSV has indexed the CVE), then falls back to batch query.
    Returns affected packages and fix info.
    """
    # Approach 1: direct lookup (works for CVEs OSV has indexed)
    try:
        resp = await client.get(
            f"https://api.osv.dev/v1/vulns/{cve_id}",
            timeout=10.0,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception as exc:
        logger.debug("OSV direct lookup failed for %s: %s", cve_id, exc)

    # Approach 2: batch query by alias
    try:
        resp = await client.post(
            "https://api.osv.dev/v1/querybatch",
            json={"queries": [{"package": {}, "version": "", "aliases": [cve_id]}]},
            timeout=10.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            if results and results[0].get("vulns"):
                return results[0]["vulns"][0]
    except Exception as exc:
        logger.debug("OSV batch lookup failed for %s: %s", cve_id, exc)

    return {}


# ---------------------------------------------------------------------------
# IOC / hash extraction from raw event payloads
# ---------------------------------------------------------------------------

def _extract_iocs(raw_payload: dict[str, Any]) -> list[str]:
    """
    Extract IOC values (IPs, domains, hashes) from an event payload.

    Checks common field names used by ThreatFox, EDR, and SIEM events.
    """
    iocs: list[str] = []
    for key in (
        "ioc", "ioc_value", "indicator", "ip", "domain",
        "c2_server", "c2_domain", "c2_ip",
        "src_ip", "dst_ip", "remote_ip",
        "url", "c2_url",
    ):
        val = raw_payload.get(key)
        if val and isinstance(val, str) and len(val) >= 4:
            iocs.append(val)

    # Check nested IOC lists
    for key in ("iocs", "indicators", "network_indicators"):
        val = raw_payload.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str) and len(item) >= 4:
                    iocs.append(item)
                elif isinstance(item, dict):
                    v = item.get("value") or item.get("indicator")
                    if v and isinstance(v, str):
                        iocs.append(v)

    return iocs[:5]  # cap to avoid API abuse


def _extract_hashes(raw_payload: dict[str, Any]) -> list[str]:
    """Extract file hashes (SHA256, MD5, SHA1) from an event payload."""
    hashes: list[str] = []
    for key in (
        "sha256", "sha256_hash", "md5", "md5_hash",
        "sha1", "sha1_hash", "file_hash", "hash",
    ):
        val = raw_payload.get(key)
        if val and isinstance(val, str) and len(val) >= 32:
            hashes.append(val)

    # Check nested hashes
    for key in ("hashes", "file_hashes"):
        val = raw_payload.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str) and len(item) >= 32:
                    hashes.append(item)

    return hashes[:3]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def enrich_cve(
    client: httpx.AsyncClient,
    cve_id: str | None,
) -> EnrichmentData:
    """
    Query Tier 1 APIs (EPSS, CISA KEV, CIRCL) concurrently for a CVE.

    Returns EnrichmentData with whatever signals succeeded.
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return EnrichmentData()

    (epss_score, epss_pct), (in_kev, kev_details), circl_data = (
        await asyncio.gather(
            _fetch_epss(client, cve_id),
            _fetch_kev(client, cve_id),
            _fetch_circl(client, cve_id),
        )
    )

    ssvc = _extract_ssvc(circl_data)

    cwe_list: list[str] = []
    for w in circl_data.get("weaknesses", []):
        for desc in w.get("description", []):
            cwe_id = desc.get("value")
            if cwe_id and cwe_id.startswith("CWE-"):
                cwe_list.append(cwe_id)

    data = EnrichmentData(
        epss_score=epss_score,
        epss_percentile=epss_pct,
        in_kev=in_kev,
        kev_date_added=kev_details.get("dateAdded"),
        kev_due_date=kev_details.get("dueDate"),
        kev_ransomware=kev_details.get("knownRansomwareCampaignUse"),
        ssvc_exploitation=ssvc["exploitation"],
        ssvc_automatable=ssvc["automatable"],
        ssvc_technical_impact=ssvc["technical_impact"],
        circl_cwe=cwe_list,
    )

    logger.info(
        "Enrichment for %s: EPSS=%.4f (p%d)  KEV=%s  SSVC=[exploit=%s auto=%s impact=%s]",
        cve_id,
        epss_score or 0.0,
        int((epss_pct or 0.0) * 100),
        "YES" if in_kev else "no",
        ssvc["exploitation"] or "?",
        ssvc["automatable"] or "?",
        ssvc["technical_impact"] or "?",
    )

    return data


async def enrich_osv(
    client: httpx.AsyncClient,
    cve_id: str | None,
) -> EnrichmentData:
    """Query OSV for package-level vulnerability data."""
    if not cve_id:
        return EnrichmentData()

    osv = await _fetch_osv(client, cve_id)
    if not osv:
        return EnrichmentData()

    packages: list[str] = []
    fix_available = False
    for affected in osv.get("affected", []):
        pkg = affected.get("package", {})
        ecosystem = pkg.get("ecosystem", "")
        name = pkg.get("name", "")
        if ecosystem and name:
            packages.append(f"{ecosystem}:{name}")
        # Check for fix versions
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fix_available = True

    if packages:
        logger.info(
            "OSV for %s: %d affected packages [%s], fix=%s",
            cve_id,
            len(packages),
            ", ".join(packages[:3]),
            "yes" if fix_available else "no",
        )

    return EnrichmentData(
        osv_affected_packages=packages,
        osv_fix_available=fix_available,
    )


async def enrich_ioc(
    client: httpx.AsyncClient,
    raw_payload: dict[str, Any],
    abusech_auth_key: str = "",
) -> EnrichmentData:
    """
    Query ThreatFox and MalwareBazaar for IOCs and hashes found in
    the event payload.  Returns actor/malware attribution signals.

    Requires a free Auth-Key from https://auth.abuse.ch/ — set via
    ABUSECH_AUTH_KEY env var.  Skips lookups if key is not set.
    """
    iocs = _extract_iocs(raw_payload)
    hashes = _extract_hashes(raw_payload)

    if not iocs and not hashes:
        return EnrichmentData()

    if not abusech_auth_key:
        return EnrichmentData()

    result = EnrichmentData()

    # ThreatFox: check first IOC that returns a hit
    for ioc_val in iocs:
        tf = await _fetch_threatfox_ioc(client, ioc_val, abusech_auth_key)
        if tf:
            result.threatfox_malware = tf.get("malware_printable") or tf.get("malware")
            result.threatfox_actor = tf.get("reporter")  # or threat_description
            result.threatfox_confidence = tf.get("confidence_level")

            # ThreatFox may have a more specific actor in tags
            tags = tf.get("tags") or []
            if isinstance(tags, list):
                for tag in tags:
                    if isinstance(tag, str) and any(
                        kw in tag.lower()
                        for kw in ("apt", "lazarus", "lockbit", "volt", "cozy", "fancy")
                    ):
                        result.threatfox_actor = tag
                        break

            logger.info(
                "ThreatFox hit for %s: malware=%s actor=%s confidence=%s",
                ioc_val,
                result.threatfox_malware or "?",
                result.threatfox_actor or "?",
                result.threatfox_confidence,
            )
            break  # one hit is enough

    # MalwareBazaar: check first hash that returns a hit
    for hash_val in hashes:
        mb = await _fetch_malwarebazaar_hash(client, hash_val, abusech_auth_key)
        if mb:
            result.malware_family = (
                mb.get("signature") or mb.get("malware_family")
            )
            raw_tags = mb.get("tags") or []
            if isinstance(raw_tags, list):
                result.malware_tags = [
                    t for t in raw_tags if isinstance(t, str)
                ][:10]

            logger.info(
                "MalwareBazaar hit for %s: family=%s tags=%s",
                hash_val,
                result.malware_family or "?",
                result.malware_tags[:3],
            )
            break

    return result


async def enrich_event(
    client: httpx.AsyncClient,
    cve_id: str | None,
    raw_payload: dict[str, Any],
    source_type: str = "",
    abusech_auth_key: str = "",
) -> EnrichmentData:
    """
    Full enrichment pipeline: runs Tier 1 (CVE-based) and Tier 2
    (IOC/hash/package-based) lookups concurrently.

    Merges all results into a single EnrichmentData.
    """
    # Tier 1: CVE-based (always run if CVE present)
    cve_task = enrich_cve(client, cve_id)

    # Tier 2a: OSV (CVE-based package lookup)
    osv_task = enrich_osv(client, cve_id)

    # Tier 2b: IOC/hash lookup (most useful for edr, siem, threatfox sources)
    ioc_task = enrich_ioc(client, raw_payload, abusech_auth_key)

    cve_data, osv_data, ioc_data = await asyncio.gather(
        cve_task, osv_task, ioc_task,
    )

    # Merge: CVE data is primary, layer on Tier 2 signals
    merged = EnrichmentData(
        # Tier 1
        epss_score=cve_data.epss_score,
        epss_percentile=cve_data.epss_percentile,
        in_kev=cve_data.in_kev,
        kev_date_added=cve_data.kev_date_added,
        kev_due_date=cve_data.kev_due_date,
        kev_ransomware=cve_data.kev_ransomware,
        ssvc_exploitation=cve_data.ssvc_exploitation,
        ssvc_automatable=cve_data.ssvc_automatable,
        ssvc_technical_impact=cve_data.ssvc_technical_impact,
        circl_cwe=cve_data.circl_cwe,
        # Tier 2 — ThreatFox
        threatfox_malware=ioc_data.threatfox_malware,
        threatfox_actor=ioc_data.threatfox_actor,
        threatfox_confidence=ioc_data.threatfox_confidence,
        # Tier 2 — MalwareBazaar
        malware_family=ioc_data.malware_family,
        malware_tags=ioc_data.malware_tags,
        # Tier 2 — OSV
        osv_affected_packages=osv_data.osv_affected_packages,
        osv_fix_available=osv_data.osv_fix_available,
    )

    return merged
