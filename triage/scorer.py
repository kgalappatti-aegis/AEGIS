"""
AEGIS Triage – Relevance Scorer

Sub-score definitions
---------------------
infrastructure_match  – How much the threat overlaps known infrastructure.
                        Base: 1.0 if CVSS baseScore >= 7.0, else 0.5.
                        Boosted by: SSVC technical_impact = "total" (→1.0),
                        SSVC automatable = "yes" (→0.85), OSV affected
                        packages found (→0.8, or 0.9 if fix available).

threat_actor_history  – Confidence that a tracked threat actor is involved.
                        Queries the Neo4j graph when a driver is available;
                        falls back to 0.5 (neutral) when Neo4j is not
                        configured.

                        Score bands:
                          0.9  actor known + uses Initial-Access / Execution TTPs
                          0.6  actor known but only other tactics
                          0.3  actor unknown to the graph

exploitability        – EPSS score (model-backed exploitation probability)
                        from FIRST.org, [0, 1].  Falls back to CVSS/10.0
                        when EPSS is unavailable.
                        Boosted to max(score, 0.85) if SSVC exploitation
                        is "active" or CVE is in CISA KEV.

temporal_urgency      – 1.0 if CVE is in CISA KEV (actively exploited) or
                        published <= 7 days ago.  0.3 otherwise.

relevance_score       – Weighted sum:
                          infrastructure_match * 0.40
                          + threat_actor_history * 0.25
                          + exploitability       * 0.20
                          + temporal_urgency     * 0.15
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from config import TEMPORAL_URGENCY_WINDOW_DAYS, WEIGHTS
from enrichment import EnrichmentData

logger = logging.getLogger("aegis.triage.scorer")

# Tactics considered "high-relevance" for the actor history score
_RELEVANT_TACTICS = frozenset([
    "initial-access",
    "execution",
    # also handle the title-case names written by neo4j_init seed data
    "Initial Access",
    "Execution",
])


# ---------------------------------------------------------------------------
# CVSS extraction
# ---------------------------------------------------------------------------

def extract_cvss_score(raw_payload: dict[str, Any]) -> float | None:
    """
    Pull the highest-quality CVSS base score out of raw_payload.metrics.
    Preference: CVSSv3.1 -> CVSSv3.0 -> CVSSv2, Primary source preferred.
    """
    metrics = raw_payload.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries: list[dict] = metrics.get(key, [])
        if not entries:
            continue
        source = next(
            (e for e in entries if e.get("type") == "Primary"),
            entries[0],
        )
        score = source.get("cvssData", {}).get("baseScore")
        if score is not None:
            return float(score)
    return None


# ---------------------------------------------------------------------------
# Date parsing
# ---------------------------------------------------------------------------

def _parse_published(raw_payload: dict[str, Any]) -> datetime | None:
    published_str = raw_payload.get("published")
    if not published_str:
        return None
    try:
        s = str(published_str)
        if "." in s:
            base, frac = s.rsplit(".", 1)
            s = f"{base}.{frac.ljust(6, '0')[:6]}"
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError) as exc:
        logger.debug("Could not parse published date %r: %s", published_str, exc)
        return None


# ---------------------------------------------------------------------------
# Sub-scorers
# ---------------------------------------------------------------------------

def score_infrastructure_match(
    cvss_score: float | None,
    enrichment: EnrichmentData,
) -> float:
    base = 1.0 if (cvss_score is not None and cvss_score >= 7.0) else 0.5

    # SSVC boosts: automatable or total-impact threats are infra-relevant
    if enrichment.ssvc_technical_impact and enrichment.ssvc_technical_impact.lower() == "total":
        base = max(base, 1.0)
    if enrichment.ssvc_automatable and enrichment.ssvc_automatable.lower() == "yes":
        base = max(base, 0.85)

    # OSV: affected packages in known ecosystems = direct infra overlap signal
    if enrichment.osv_affected_packages:
        base = max(base, 0.8)
        # Fix available but not applied is even more infra-relevant
        if enrichment.osv_fix_available:
            base = max(base, 0.9)

    return base


async def score_threat_actor_history(
    actor_name: str,
    cve_id: str,
    neo4j_session: Any,
) -> float:
    """
    Query the Neo4j threat-actor graph to score how likely a known actor
    is involved in activity related to *cve_id*.

    Returns
    -------
    0.9  – actor is in the graph AND has USES edges to Initial-Access or
            Execution TTPs (the first stages most likely tied to a CVE exploit)
    0.6  – actor is in the graph but only uses TTPs in other tactics
    0.3  – actor is unknown to the graph (or actor_name is empty)
    """
    if not actor_name:
        return 0.3

    # Does this actor exist?  Does it use relevant-tactic TTPs?
    result = await neo4j_session.run(
        """
        OPTIONAL MATCH (a:ThreatActor)
        WHERE a.name = $actor_name
           OR $actor_name IN a.aliases
        WITH a
        OPTIONAL MATCH (a)-[:USES]->(t:TTP)
        WHERE t.tactic IN $relevant_tactics
        RETURN
            a IS NOT NULL                        AS actor_known,
            count(t) > 0                         AS has_relevant_ttps
        """,
        actor_name=actor_name,
        relevant_tactics=list(_RELEVANT_TACTICS),
    )

    record = await result.single()
    if record is None or not record["actor_known"]:
        return 0.3
    if record["has_relevant_ttps"]:
        return 0.9
    return 0.6


def score_exploitability(
    cvss_score: float | None,
    enrichment: EnrichmentData,
) -> float:
    # Primary: EPSS (model-backed exploitation probability)
    if enrichment.epss_score is not None:
        score = enrichment.epss_score
    elif cvss_score is not None:
        # Fallback: CVSS / 10
        score = max(0.0, min(1.0, cvss_score / 10.0))
    else:
        score = 0.5

    # Hard boost: KEV or SSVC "active" exploitation means confirmed exploit
    if enrichment.in_kev:
        score = max(score, 0.85)
    if enrichment.ssvc_exploitation and enrichment.ssvc_exploitation.lower() == "active":
        score = max(score, 0.85)

    return score


def score_temporal_urgency(
    published_at: datetime | None,
    enrichment: EnrichmentData,
) -> float:
    # KEV hit = actively exploited in the wild → maximum urgency
    if enrichment.in_kev:
        return 1.0

    # SSVC "active" exploitation is equivalent
    if enrichment.ssvc_exploitation and enrichment.ssvc_exploitation.lower() == "active":
        return 1.0

    if published_at is None:
        return 0.3
    age_days = (datetime.now(timezone.utc) - published_at).days
    return 1.0 if age_days <= TEMPORAL_URGENCY_WINDOW_DAYS else 0.3


# ---------------------------------------------------------------------------
# Composite score
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TriageScores:
    infrastructure_match:  float
    threat_actor_history:  float
    exploitability:        float
    temporal_urgency:      float
    relevance_score:       float

    def __str__(self) -> str:
        return (
            f"relevance={self.relevance_score:.3f} "
            f"[infra={self.infrastructure_match:.2f} "
            f"actor={self.threat_actor_history:.2f} "
            f"exploit={self.exploitability:.2f} "
            f"urgency={self.temporal_urgency:.2f}]"
        )


async def compute_scores(
    raw_payload: dict[str, Any],
    *,
    neo4j_driver: Any = None,
    actor_name: str = "",
    enrichment: EnrichmentData | None = None,
) -> TriageScores:
    """
    Derive all four sub-scores from raw_payload and external enrichment,
    then combine into a weighted relevance_score.

    Parameters
    ----------
    raw_payload   : NVD CVE payload dict (or similar structured dict).
    neo4j_driver  : Optional async Neo4j driver.  When provided the
                    threat_actor_history score is computed via a live
                    graph query; otherwise falls back to 0.5.
    actor_name    : Threat-actor name to look up.  Typically empty for
                    raw NVD events; set when actor attribution is known.
    enrichment    : External enrichment data (EPSS, KEV, CIRCL).
                    When None, scoring falls back to CVSS-only stubs.
    """
    if enrichment is None:
        enrichment = EnrichmentData()

    cvss     = extract_cvss_score(raw_payload)
    pub_date = _parse_published(raw_payload)
    cve_id   = raw_payload.get("id") or raw_payload.get("cve_id") or ""

    infra   = score_infrastructure_match(cvss, enrichment)
    exploit = score_exploitability(cvss, enrichment)
    urgency = score_temporal_urgency(pub_date, enrichment)

    if neo4j_driver is not None:
        try:
            async with neo4j_driver.session() as session:
                actor = await score_threat_actor_history(actor_name, cve_id, session)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Neo4j actor query failed (%s) — using 0.5 fallback.", exc)
            actor = 0.5
    else:
        actor = 0.5   # Phase 2 neutral default when Neo4j not configured

    # ThreatFox / MalwareBazaar actor attribution boosts
    # If ThreatFox identified a known actor, that's a direct attribution signal
    if enrichment.threatfox_actor:
        actor = max(actor, 0.8)
    if enrichment.threatfox_malware:
        actor = max(actor, 0.7)
    # MalwareBazaar: known malware family = moderate actor signal
    if enrichment.malware_family:
        actor = max(actor, 0.65)

    relevance = (
        infra   * WEIGHTS["infrastructure_match"]
        + actor   * WEIGHTS["threat_actor_history"]
        + exploit * WEIGHTS["exploitability"]
        + urgency * WEIGHTS["temporal_urgency"]
    )
    relevance = round(max(0.0, min(1.0, relevance)), 6)

    if cvss is not None or enrichment.epss_score is not None:
        logger.debug(
            "Scores for %s (CVSS=%s EPSS=%s KEV=%s): %s",
            cve_id,
            f"{cvss:.1f}" if cvss else "?",
            f"{enrichment.epss_score:.4f}" if enrichment.epss_score is not None else "?",
            "YES" if enrichment.in_kev else "no",
            TriageScores(infra, actor, exploit, urgency, relevance),
        )

    return TriageScores(
        infrastructure_match=infra,
        threat_actor_history=actor,
        exploitability=exploit,
        temporal_urgency=urgency,
        relevance_score=relevance,
    )
