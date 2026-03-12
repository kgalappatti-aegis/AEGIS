"""
AEGIS Detection Agent – LangGraph Nodes

Node 1: load_finding      – decode stream fields, skip if severity==low (opt-in)
Node 2: generate_detections – Claude call → Sigma rules + coverage gaps
Node 3: forward_to_advisory – XADD to aegis:queue:advisory, XACK source
"""

from __future__ import annotations

import json
import logging
import pathlib
import re
import sys
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
from anthropic import AsyncAnthropic

# ---------------------------------------------------------------------------
# Ensure orchestrator/schema.py is importable (monorepo layout)
# ---------------------------------------------------------------------------
_DET  = pathlib.Path(__file__).parent
_ORCH = _DET.parent / "orchestrator"
for _p in (_ORCH, _DET):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from config import (   # noqa: E402
    ADVISORY_QUEUE,
    CONSUMER_GROUP,
    DETECTION_QUEUE,
    settings,
)
from state import DetectionState  # noqa: E402

logger = logging.getLogger("aegis.detection.nodes")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _float_or_none(value: str | None) -> float | None:
    if value in (None, "", "None"):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _extract_json(text: str) -> dict:
    """Strip markdown fences and parse the first JSON object found."""
    text = re.sub(r"```(?:json)?\s*", "", text).strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return {}
    try:
        return json.loads(match.group())
    except json.JSONDecodeError:
        return {}


# ---------------------------------------------------------------------------
# Node 1: load_finding
# ---------------------------------------------------------------------------

async def load_finding(state: DetectionState) -> dict[str, Any]:
    """
    Decode raw Redis fields into typed state.

    Skips the message if:
      - required fields are missing (not a simulation finding)
      - severity == "low" and DETECTION_SKIP_LOW is enabled
    """
    fields = state.get("raw_fields", {})

    if "event_id" not in fields:
        logger.debug("Message %s has no event_id — skipping.", state.get("msg_id"))
        return {"skip": True, "skip_reason": "not_a_finding"}

    severity = fields.get("severity", "medium")

    if settings.skip_low_severity and severity == "low":
        logger.info(
            "Skipping low-severity event %s (DETECTION_SKIP_LOW=true).",
            fields.get("event_id"),
        )
        return {"skip": True, "skip_reason": "low_severity"}

    # Parse raw_payload JSON
    try:
        raw_payload = json.loads(fields.get("raw_payload", "{}"))
    except json.JSONDecodeError:
        raw_payload = {}

    # Extract cve_id from raw_payload (NVD CVE path)
    cve_id = raw_payload.get("id") or raw_payload.get("cve_id")
    if not cve_id:
        # Try metrics nesting
        cve_id = fields.get("cve_id")

    # Parse JSON list fields
    def _json_list(key: str) -> list:
        try:
            return json.loads(fields.get(key, "[]"))
        except (json.JSONDecodeError, TypeError):
            return []

    cvss_raw = _float_or_none(fields.get("cvss"))

    return {
        "event_id":             fields.get("event_id",    ""),
        "source_type":          fields.get("source_type", ""),
        "priority":             fields.get("priority",    "P3"),
        "ingested_at":          fields.get("ingested_at", ""),
        "raw_payload":          raw_payload,
        # Triage pass-through
        "relevance_score":      _float_or_none(fields.get("relevance_score")),
        "infrastructure_match": _float_or_none(fields.get("infrastructure_match")),
        "exploitability":       _float_or_none(fields.get("exploitability")),
        "temporal_urgency":     _float_or_none(fields.get("temporal_urgency")),
        # Simulation finding
        "cve_id":                   cve_id,
        "cvss":                     cvss_raw,
        "p_breach":                 float(fields.get("p_breach", 0.0)),
        "delta_p_breach":           float(fields.get("delta_p_breach", 0.0)),
        "highest_risk_path":        _json_list("highest_risk_path"),
        "blind_spots":              _json_list("blind_spots"),
        "compound_risk_factors":    _json_list("compound_risk_factors"),
        "recommended_detections":   _json_list("recommended_detections"),
        "severity":                 severity,
        "summary":                  fields.get("summary", ""),
        "simulated_at":             fields.get("simulated_at", ""),
        "skip":                     False,
        "skip_reason":              "",
    }


# ---------------------------------------------------------------------------
# Node 2: generate_detections
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are an expert Detection Engineer and threat hunter specialising in Sigma rules and SIEM coverage.

Given a simulation finding for a CVE, you will:
1. Generate 1-3 actionable Sigma detection rules targeting the attack paths described.
2. Identify coverage gaps — techniques or blind spots the current rule set would miss.
3. Write a concise analyst summary (2-3 sentences).

Rules MUST follow Sigma v2 format (logsource + detection blocks).
Favour host-based and network-based log sources that are commonly available
(Windows Security, Sysmon, Zeek/Suricata, auth logs).

Respond ONLY with valid JSON in exactly this shape:
{
  "sigma_rules": ["<yaml string>", ...],
  "coverage_gaps": ["<description>", ...],
  "detection_summary": "<paragraph>"
}
"""

_TTP_SYSTEM_PROMPT = """\
You are a detection engineer generating production-ready Sigma rules. \
Use the MITRE ATT&CK detection guidance and data sources provided to \
ground your rule in observable log fields."""


async def _fetch_mitre_context(
    redis: aioredis.Redis,
    ttp_id: str,
) -> tuple[str, list[str]]:
    """Fetch MITRE detection hint and data sources from Redis."""
    hint = await redis.hget("aegis:detection:sigma", ttp_id) or ""
    if isinstance(hint, bytes):
        hint = hint.decode()
    ds_raw = await redis.hget("aegis:detection:data_sources", ttp_id) or "[]"
    if isinstance(ds_raw, bytes):
        ds_raw = ds_raw.decode()
    try:
        data_sources = json.loads(ds_raw)
    except (json.JSONDecodeError, TypeError):
        data_sources = []
    return hint, data_sources


async def _generate_ttp_detection(
    client: AsyncAnthropic,
    redis: aioredis.Redis,
    ttp_id: str,
    ttp_name: str,
    tactic: str,
    platform: str,
) -> dict[str, Any] | None:
    """Generate a Sigma rule for a single TTP using MITRE grounding context."""
    hint, data_sources = await _fetch_mitre_context(redis, ttp_id)

    ds_block = (
        "\n".join(f"  - {ds}" for ds in data_sources)
        if data_sources else "  (none documented)"
    )

    user_content = (
        f"Technique: {ttp_id} — {ttp_name}\n"
        f"Tactic: {tactic}\n"
        f"Platform: {platform}\n\n"
        f"MITRE detection guidance:\n"
        f"{hint if hint else '(none documented)'}\n\n"
        f"MITRE data sources:\n{ds_block}\n\n"
        f"Generate:\n"
        f"1. A Sigma rule (YAML) targeting the most specific data source above.\n"
        f"   Use Sigma's logsource.category matching the first data source listed.\n"
        f"2. A coverage_score (0.0–1.0) estimating detection confidence:\n"
        f"     0.0–0.3  = low (generic or noisy rule)\n"
        f"     0.3–0.7  = medium (specific but may miss variants)\n"
        f"     0.7–1.0  = high (tight match on documented behavior)\n"
        f"3. A coverage_gaps list (strings) describing what the rule misses.\n\n"
        f"Return ONLY valid JSON:\n"
        f'{{\n'
        f'  "sigma_rule": "...",\n'
        f'  "coverage_score": 0.0,\n'
        f'  "coverage_gaps": ["..."]\n'
        f'}}'
    )

    try:
        response = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2_048,
            system=_TTP_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )
        raw = response.content[0].text
        result = _extract_json(raw)
        if not result:
            return None

        # Update Redis with real detection data
        score = float(result.get("coverage_score", 0.0))
        coverage = "detected" if score >= 0.7 else "partial"
        await redis.hset("aegis:detection:coverage", ttp_id, coverage)
        sigma_rule = result.get("sigma_rule", "")
        if sigma_rule:
            await redis.hset(
                "aegis:detection:sigma", ttp_id, sigma_rule[:500]
            )
        await redis.hset(
            "aegis:detection:score", ttp_id, str(round(score, 3))
        )

        logger.info(
            "TTP %s detection: coverage=%s score=%.3f", ttp_id, coverage, score,
        )
        return result

    except Exception as exc:
        logger.warning("TTP detection generation failed for %s: %s", ttp_id, exc)
        return None


async def generate_detections(
    state: DetectionState,
    *,
    client: AsyncAnthropic,
    redis: aioredis.Redis,
) -> dict[str, Any]:
    """
    Call Claude to produce Sigma rules and identify coverage gaps.

    For each TTP in the highest_risk_path, also generates a grounded
    Sigma rule using MITRE data sources from Redis and updates coverage.
    """
    cve_id   = state.get("cve_id",   "UNKNOWN")
    severity = state.get("severity", "medium")

    user_content = json.dumps({
        "cve_id":                 cve_id,
        "cvss":                   state.get("cvss"),
        "severity":               severity,
        "p_breach":               state.get("p_breach"),
        "delta_p_breach":         state.get("delta_p_breach"),
        "summary":                state.get("summary"),
        "highest_risk_path":      state.get("highest_risk_path",      []),
        "blind_spots":            state.get("blind_spots",            []),
        "compound_risk_factors":  state.get("compound_risk_factors",  []),
        "recommended_detections": state.get("recommended_detections", []),
        "infrastructure_match":   state.get("infrastructure_match"),
        "exploitability":         state.get("exploitability"),
    }, indent=2)

    fallback: dict[str, Any] = {
        "sigma_rules":       [],
        "coverage_gaps":     ["Detection generation unavailable — manual review required."],
        "detection_summary": f"Simulation finding for {cve_id} requires manual detection authoring.",
    }

    try:
        response = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2_048,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )

        raw    = response.content[0].text
        parsed = _extract_json(raw)

        sigma_rules = parsed.get("sigma_rules", [])
        if not isinstance(sigma_rules, list):
            sigma_rules = []

        coverage_gaps = parsed.get("coverage_gaps", [])
        if not isinstance(coverage_gaps, list):
            coverage_gaps = []

        detection_summary = parsed.get("detection_summary", "")

        # Generate grounded TTP-level detections for techniques in the path
        risk_path = state.get("highest_risk_path", [])
        for ttp_id in risk_path:
            if not isinstance(ttp_id, str) or not ttp_id.startswith("T"):
                continue
            ttp_result = await _generate_ttp_detection(
                client=client,
                redis=redis,
                ttp_id=ttp_id,
                ttp_name=ttp_id,  # name may not be available in state
                tactic="",
                platform="",
            )
            if ttp_result and ttp_result.get("sigma_rule"):
                sigma_rules.append(ttp_result["sigma_rule"])
            if ttp_result and ttp_result.get("coverage_gaps"):
                coverage_gaps.extend(ttp_result["coverage_gaps"])

        logger.info(
            "Detection generation for %s: %d Sigma rules, %d coverage gaps.",
            cve_id, len(sigma_rules), len(coverage_gaps),
        )

        return {
            "sigma_rules":       sigma_rules,
            "coverage_gaps":     coverage_gaps,
            "detection_summary": detection_summary,
        }

    except Exception as exc:
        logger.warning(
            "Claude call failed for %s: %s — using fallback.", cve_id, exc
        )
        return fallback


# ---------------------------------------------------------------------------
# Node 3: forward_to_advisory
# ---------------------------------------------------------------------------

async def forward_to_advisory(
    state: DetectionState,
    *,
    redis: aioredis.Redis,
) -> dict[str, Any]:
    """
    Write the enriched finding + detection content to ``aegis:queue:advisory``,
    then XACK the source message from ``aegis:queue:detection``.

    On skip: only ACKs — nothing forwarded.
    """
    msg_id = state.get("msg_id", "")

    if state.get("skip"):
        logger.debug(
            "Skipping event %s: %s",
            state.get("event_id", "?"), state.get("skip_reason", ""),
        )
        if msg_id:
            await redis.xack(DETECTION_QUEUE, CONSUMER_GROUP, msg_id)
        return {"forwarded": False, "forward_error": None}

    payload: dict[str, str] = {
        # Core identity
        "event_id":    state.get("event_id",    ""),
        "source_type": state.get("source_type", ""),
        "priority":    state.get("priority",    "P3"),
        "routing_target": "advisory",
        "ingested_at": state.get("ingested_at", ""),
        # Triage scores (pass-through)
        "relevance_score":      str(state.get("relevance_score",    "") or ""),
        "infrastructure_match": str(state.get("infrastructure_match","") or ""),
        "exploitability":       str(state.get("exploitability",     "") or ""),
        "temporal_urgency":     str(state.get("temporal_urgency",   "") or ""),
        # Simulation finding (pass-through)
        "p_breach":               str(state.get("p_breach",               0.0)),
        "delta_p_breach":         str(state.get("delta_p_breach",         0.0)),
        "highest_risk_path":      json.dumps(state.get("highest_risk_path",      [])),
        "blind_spots":            json.dumps(state.get("blind_spots",            [])),
        "compound_risk_factors":  json.dumps(state.get("compound_risk_factors",  [])),
        "recommended_detections": json.dumps(state.get("recommended_detections", [])),
        "severity":               state.get("severity", "medium"),
        "summary":                state.get("summary",  ""),
        "simulated_at":           state.get("simulated_at", ""),
        # Detection output
        "sigma_rules":       json.dumps(state.get("sigma_rules",       [])),
        "coverage_gaps":     json.dumps(state.get("coverage_gaps",     [])),
        "detection_summary": state.get("detection_summary", ""),
        "detected_at":       datetime.now(timezone.utc).isoformat(),
    }

    try:
        stream_id = await redis.xadd(
            ADVISORY_QUEUE, payload, maxlen=20_000, approximate=True
        )
        logger.info(
            "Forwarded event %s → %s (stream_id=%s, severity=%s, rules=%d)",
            state.get("event_id"),
            ADVISORY_QUEUE,
            stream_id,
            state.get("severity"),
            len(state.get("sigma_rules", [])),
        )
        if msg_id:
            await redis.xack(DETECTION_QUEUE, CONSUMER_GROUP, msg_id)
        return {"forwarded": True, "forward_error": None}

    except Exception as exc:
        logger.error(
            "Forward failed for event %s: %s",
            state.get("event_id"), exc,
        )
        return {"forwarded": False, "forward_error": str(exc)}
