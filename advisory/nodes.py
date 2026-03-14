"""
AEGIS Advisory Agent – LangGraph Nodes

Node 1: load_event        – deserialize fully-enriched advisory fields
Node 2: generate_advisory – Claude API → executive advisory JSON
Node 3: persist           – asyncpg write to PostgreSQL advisories table
Node 4: broadcast         – PUBLISH to aegis:broadcast (WebSocket bridge)
Node 5: acknowledge       – XACK the source message
"""

from __future__ import annotations

import json
import logging
import pathlib
import re
import sys
from datetime import datetime, timezone
from typing import Any

import asyncpg
import redis.asyncio as aioredis
from anthropic import AsyncAnthropic

# ---------------------------------------------------------------------------
# Ensure advisory/ is importable (monorepo layout)
# ---------------------------------------------------------------------------
_ADV  = pathlib.Path(__file__).parent
_ORCH = _ADV.parent / "orchestrator"
for _p in (_ORCH, _ADV):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from config import (   # noqa: E402
    ADVISORY_QUEUE,
    ADVISORY_STREAM,
    BROADCAST_CHANNEL,
    CONSUMER_GROUP,
    settings,
)
from state import AdvisoryState  # noqa: E402

logger = logging.getLogger("aegis.advisory.nodes")

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


def _ts_or_none(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def _extract_json(text: str) -> dict:
    """Strip markdown fences and parse the first JSON object."""
    text = re.sub(r"```(?:json)?\s*", "", text).strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return {}
    try:
        return json.loads(match.group())
    except json.JSONDecodeError:
        return {}


def _json_list(fields: dict[str, str], key: str) -> list:
    try:
        return json.loads(fields.get(key, "[]"))
    except (json.JSONDecodeError, TypeError):
        return []


# ---------------------------------------------------------------------------
# Node 1: load_event
# ---------------------------------------------------------------------------

async def load_event(state: AdvisoryState) -> dict[str, Any]:
    """
    Deserialize the fully-enriched advisory queue message into typed state.

    Skips messages that are missing the event_id sentinel field
    (e.g. bootstrap messages).
    """
    fields = state.get("raw_fields", {})

    if "event_id" not in fields:
        logger.debug(
            "Message %s has no event_id — skipping.", state.get("msg_id")
        )
        return {"skip": True, "skip_reason": "not_an_advisory"}

    try:
        raw_payload = json.loads(fields.get("raw_payload", "{}"))
    except json.JSONDecodeError:
        raw_payload = {}

    # Derive cve_id from multiple possible locations across source types
    cve_id = (
        raw_payload.get("id")
        or raw_payload.get("cve_id")
        or fields.get("cve_id")
    )
    # Fallback: regex scan text fields for CVE patterns (MISP, EDR, SIEM)
    if not cve_id:
        _cve_re = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
        for text_field in ("info", "title", "description", "short_description",
                           "vulnerability_name", "rule_name"):
            text = raw_payload.get(text_field, "")
            if text:
                m = _cve_re.search(str(text))
                if m:
                    cve_id = m.group(0).upper()
                    break

    return {
        "event_id":             fields.get("event_id",    ""),
        "source_type":          fields.get("source_type", ""),
        "priority":             fields.get("priority",    "P3"),
        "ingested_at":          fields.get("ingested_at", ""),
        "raw_payload":          raw_payload,
        # Triage scores
        "relevance_score":      _float_or_none(fields.get("relevance_score")),
        "infrastructure_match": _float_or_none(fields.get("infrastructure_match")),
        "exploitability":       _float_or_none(fields.get("exploitability")),
        "temporal_urgency":     _float_or_none(fields.get("temporal_urgency")),
        # Simulation finding
        "cve_id":                   cve_id,
        "p_breach":                 float(fields.get("p_breach",       0.0)),
        "delta_p_breach":           float(fields.get("delta_p_breach", 0.0)),
        "highest_risk_path":        _json_list(fields, "highest_risk_path"),
        "blind_spots":              _json_list(fields, "blind_spots"),
        "compound_risk_factors":    _json_list(fields, "compound_risk_factors"),
        "recommended_detections":   _json_list(fields, "recommended_detections"),
        "severity":                 fields.get("severity") or None,
        "sim_summary":              fields.get("summary",     ""),
        "simulated_at":             fields.get("simulated_at",""),
        # Detection output
        "sigma_rules":              _json_list(fields, "sigma_rules"),
        "coverage_gaps":            _json_list(fields, "coverage_gaps"),
        "validation_tests":         _json_list(fields, "validation_tests"),
        "detection_summary":        fields.get("detection_summary", ""),
        "detected_at":              fields.get("detected_at", ""),
        "skip":        False,
        "skip_reason": "",
    }


# ---------------------------------------------------------------------------
# Node 2: generate_advisory
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a senior threat intelligence analyst writing executive-ready security advisories.
Be precise, concise, and actionable.
Respond only in JSON."""

_RESPONSE_SCHEMA = """
{
  "title": "<string, max 80 chars>",
  "executive_summary": "<2-3 sentence non-technical summary>",
  "technical_summary": "<3-5 sentence technical detail>",
  "affected_assets": ["<asset name>", ...],
  "immediate_actions": ["<action>", ...],
  "detection_actions": ["<action>", ...],
  "risk_score": <integer 0-100>,
  "confidence": "<high|medium|low>",
  "tlp": "<RED|AMBER|GREEN|CLEAR>",
  "mitre_techniques": ["T####", ...],
  "references": ["<string>", ...]
}
"""


async def generate_advisory(
    state: AdvisoryState,
    *,
    client: AsyncAnthropic,
) -> dict[str, Any]:
    """
    Call Claude to produce a structured advisory card from the full
    pipeline context (triage + simulation + detection).
    """
    cve_id   = state.get("cve_id") or "UNKNOWN"
    priority = state.get("priority", "P3")

    # Severity from simulation; if not set, derive from priority so P0
    # events don't default to "medium"
    severity = state.get("severity")
    if not severity:
        _PRIORITY_SEVERITY = {"P0": "critical", "P1": "high", "P2": "medium", "P3": "low"}
        severity = _PRIORITY_SEVERITY.get(priority, "medium")

    user_content = json.dumps({
        "pipeline_context": {
            "cve_id":        cve_id,
            "severity":      severity,
            "priority":      priority,
            "source_type":   state.get("source_type"),
            # Triage
            "relevance_score":      state.get("relevance_score"),
            "infrastructure_match": state.get("infrastructure_match"),
            "exploitability":       state.get("exploitability"),
            "temporal_urgency":     state.get("temporal_urgency"),
            # Simulation
            "p_breach":               state.get("p_breach"),
            "delta_p_breach":         state.get("delta_p_breach"),
            "highest_risk_path":      state.get("highest_risk_path",      []),
            "blind_spots":            state.get("blind_spots",            []),
            "compound_risk_factors":  state.get("compound_risk_factors",  []),
            "recommended_detections": state.get("recommended_detections", []),
            "sim_summary":            state.get("sim_summary",            ""),
            # Detection
            "detection_summary": state.get("detection_summary", ""),
            "coverage_gaps":     state.get("coverage_gaps",     []),
            "sigma_rule_count":  len(state.get("sigma_rules", [])),
            # Validation
            "validation_tests":  [
                {"technique_id": t.get("technique_id"), "name": t.get("name"), "executor": t.get("executor")}
                for t in state.get("validation_tests", [])
            ][:5],
        },
        "response_schema": _RESPONSE_SCHEMA,
    }, indent=2)

    # Build a meaningful label for non-CVE events
    raw_payload = state.get("raw_payload", {})
    event_label = cve_id
    if cve_id == "UNKNOWN":
        event_label = (
            raw_payload.get("title")
            or raw_payload.get("info")
            or raw_payload.get("rule_name")
            or raw_payload.get("vulnerability_name")
            or f"{state.get('source_type', 'unknown')} alert"
        )
        if len(event_label) > 60:
            event_label = event_label[:57] + "..."

    fallback: dict[str, Any] = {
        "title":             f"Security Advisory: {event_label}",
        "executive_summary": (
            f"A {severity}-severity event ({event_label}) has been identified "
            f"with a breach probability of {state.get('p_breach', 0):.0%}. "
            "Manual analyst review is required."
        ),
        "technical_summary": state.get("sim_summary", "Advisory generation unavailable."),
        "affected_assets":   state.get("blind_spots",  []),
        "immediate_actions": state.get("recommended_detections", [])[:3],
        "detection_actions": [],
        "risk_score":        min(100, int((state.get("p_breach", 0.0)) * 100)),
        "confidence":        "low",
        "tlp":               "AMBER",
        "mitre_techniques":  state.get("highest_risk_path", []),
        "ext_references":    [],
    }

    try:
        response = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1_500,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )

        raw    = response.content[0].text
        parsed = _extract_json(raw)

        # Sanitise each field, falling back to the fallback value
        title = (parsed.get("title") or fallback["title"])[:80]

        confidence = parsed.get("confidence", "medium")
        if confidence not in ("high", "medium", "low"):
            confidence = "medium"

        tlp = parsed.get("tlp", "AMBER")
        if tlp not in ("RED", "AMBER", "GREEN", "CLEAR"):
            tlp = "AMBER"

        risk_score = int(parsed.get("risk_score", fallback["risk_score"]))
        risk_score = max(0, min(100, risk_score))

        def _str_list(key: str) -> list[str]:
            val = parsed.get(key, [])
            return [str(v) for v in val] if isinstance(val, list) else []

        result: dict[str, Any] = {
            "title":             title,
            "executive_summary": parsed.get("executive_summary", fallback["executive_summary"]),
            "technical_summary": parsed.get("technical_summary", fallback["technical_summary"]),
            "affected_assets":   _str_list("affected_assets"),
            "immediate_actions": _str_list("immediate_actions")[:3],
            "detection_actions": _str_list("detection_actions")[:3],
            "risk_score":        risk_score,
            "confidence":        confidence,
            "tlp":               tlp,
            "mitre_techniques":  _str_list("mitre_techniques"),
            "ext_references":    _str_list("references"),
        }

        logger.info(
            "Advisory generated for %s: risk=%d  tlp=%s  confidence=%s",
            cve_id, risk_score, tlp, confidence,
        )
        return result

    except Exception as exc:
        logger.warning(
            "Claude call failed for %s: %s — using fallback.", cve_id, exc
        )
        return fallback


# ---------------------------------------------------------------------------
# Node 3: persist
# ---------------------------------------------------------------------------

async def persist(
    state: AdvisoryState,
    *,
    pool: asyncpg.Pool,
    redis: aioredis.Redis,
) -> dict[str, Any]:
    """
    Write the advisory to the PostgreSQL ``advisories`` table.

    Also fetches the simulation finding from Redis and persists it in
    the ``finding_json`` column so the kill chain survives the 24h TTL.

    Uses INSERT … ON CONFLICT (event_id) DO UPDATE so re-processed
    messages overwrite rather than duplicate.
    """
    if state.get("skip"):
        return {"advisory_id": None, "persist_error": None}

    # Fetch simulation finding from Redis before it expires
    event_id = state.get("event_id", "")
    finding_json: str | None = None
    if event_id:
        try:
            raw = await redis.get(f"aegis:sim:findings:{event_id}")
            if raw:
                finding_json = raw.decode() if isinstance(raw, bytes) else raw
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not fetch finding for %s: %s", event_id, exc)

    sql = """
        INSERT INTO advisories (
            event_id, cve_id, priority, severity, p_breach, risk_score,
            title, executive_summary, technical_summary,
            affected_assets, immediate_actions, detection_actions,
            sigma_rules, coverage_gaps,
            tlp, confidence, mitre_techniques,
            source_type, ext_references,
            finding_json,
            simulated_at, detected_at
        ) VALUES (
            $1,  $2,  $3,  $4,  $5,  $6,
            $7,  $8,  $9,
            $10, $11, $12,
            $13, $14,
            $15, $16, $17,
            $18, $19,
            $20,
            $21, $22
        )
        ON CONFLICT (event_id) DO UPDATE SET
            risk_score        = EXCLUDED.risk_score,
            title             = EXCLUDED.title,
            executive_summary = EXCLUDED.executive_summary,
            technical_summary = EXCLUDED.technical_summary,
            affected_assets   = EXCLUDED.affected_assets,
            immediate_actions = EXCLUDED.immediate_actions,
            detection_actions = EXCLUDED.detection_actions,
            sigma_rules       = EXCLUDED.sigma_rules,
            coverage_gaps     = EXCLUDED.coverage_gaps,
            tlp               = EXCLUDED.tlp,
            confidence        = EXCLUDED.confidence,
            mitre_techniques  = EXCLUDED.mitre_techniques,
            ext_references    = EXCLUDED.ext_references,
            finding_json      = EXCLUDED.finding_json,
            detected_at       = EXCLUDED.detected_at
        RETURNING id::text
    """

    # ALTER TABLE to add unique constraint on event_id if missing
    # (idempotent — handled by DDL in agent.py startup)

    def _jb(val: list) -> str:
        return json.dumps(val)

    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                sql,
                state.get("event_id",    ""),         # $1
                state.get("cve_id"),                  # $2
                state.get("priority",    "P3"),        # $3
                state.get("severity",    "medium"),    # $4
                state.get("p_breach",    0.0),         # $5
                state.get("risk_score",  0),           # $6
                state.get("title",       ""),          # $7
                state.get("executive_summary", ""),    # $8
                state.get("technical_summary", ""),    # $9
                _jb(state.get("affected_assets",  [])), # $10
                _jb(state.get("immediate_actions",[])), # $11
                _jb(state.get("detection_actions",[])), # $12
                _jb(state.get("sigma_rules",      [])), # $13
                _jb(state.get("coverage_gaps",    [])), # $14
                state.get("tlp",        "AMBER"),      # $15
                state.get("confidence", "medium"),     # $16
                _jb(state.get("mitre_techniques", [])), # $17
                state.get("source_type", ""),          # $18
                _jb(state.get("ext_references",    [])), # $19
                finding_json,                            # $20
                _ts_or_none(state.get("simulated_at")), # $21
                _ts_or_none(state.get("detected_at")),  # $22
            )

        advisory_id = row["id"] if row else None
        logger.info(
            "Persisted advisory %s for event %s  (cve=%s, risk=%d)",
            advisory_id, state.get("event_id"), state.get("cve_id"),
            state.get("risk_score", 0),
        )
        return {"advisory_id": advisory_id, "persist_error": None}

    except Exception as exc:
        logger.error(
            "DB persist failed for event %s: %s",
            state.get("event_id"), exc,
        )
        return {"advisory_id": None, "persist_error": str(exc)}


# ---------------------------------------------------------------------------
# Node 4: broadcast
# ---------------------------------------------------------------------------

async def broadcast(
    state: AdvisoryState,
    *,
    redis: aioredis.Redis,
) -> dict[str, Any]:
    """
    PUBLISH the advisory as JSON to ``aegis:broadcast`` so the WebSocket
    bridge can push it to all connected dashboard clients.
    """
    if state.get("skip"):
        return {"broadcast_ok": False}

    payload = json.dumps({
        "type":              "advisory",
        "event_id":          state.get("event_id",          ""),
        "advisory_id":       state.get("advisory_id"),
        "cve_id":            state.get("cve_id"),
        "priority":          state.get("priority",          "P3"),
        "severity":          state.get("severity",          "medium"),
        "p_breach":          state.get("p_breach",          0.0),
        "risk_score":        state.get("risk_score",        0),
        "title":             state.get("title",             ""),
        "executive_summary": state.get("executive_summary", ""),
        "tlp":               state.get("tlp",               "AMBER"),
        "confidence":        state.get("confidence",        "medium"),
        "mitre_techniques":  state.get("mitre_techniques",  []),
        "immediate_actions": state.get("immediate_actions", []),
        "detection_actions": state.get("detection_actions", []),
        "sigma_rules":       state.get("sigma_rules",       []),
        "coverage_gaps":     state.get("coverage_gaps",     []),
        "validation_tests":  state.get("validation_tests",  []),
        "affected_assets":   state.get("affected_assets",   []),
        "created_at":        datetime.now(timezone.utc).isoformat(),
    })

    try:
        # Pub/sub for live clients
        receivers = await redis.publish(BROADCAST_CHANNEL, payload)

        # Persistent stream for UI catchup on reconnect
        await redis.xadd(
            ADVISORY_STREAM,
            {"data": payload},
            maxlen=500,
            approximate=True,
        )

        # Publish stage update for live UI tracking
        event_id = state.get("event_id", "")
        if event_id:
            await redis.hset("aegis:event:stages", event_id, "advisory")
            await redis.publish(BROADCAST_CHANNEL, json.dumps({
                "type": "stage_update",
                "event_id": event_id,
                "stage": "advisory",
            }))

        logger.info(
            "Broadcast advisory for %s to %d receiver(s) + stream.",
            state.get("event_id"), receivers,
        )
        return {"broadcast_ok": True}
    except Exception as exc:
        logger.warning(
            "Broadcast failed for event %s: %s",
            state.get("event_id"), exc,
        )
        return {"broadcast_ok": False}


# ---------------------------------------------------------------------------
# Node 5: acknowledge
# ---------------------------------------------------------------------------

async def acknowledge(
    state: AdvisoryState,
    *,
    redis: aioredis.Redis,
) -> dict[str, Any]:
    """
    XACK the source message from ``aegis:queue:advisory``.

    Always runs — even on skip — to prevent re-delivery of
    unprocessable messages.
    """
    msg_id = state.get("msg_id", "")
    if msg_id:
        try:
            await redis.xack(ADVISORY_QUEUE, CONSUMER_GROUP, msg_id)
            logger.debug("ACKed message %s", msg_id)
        except Exception as exc:
            logger.warning("XACK failed for %s: %s", msg_id, exc)
    return {"acknowledged": True}
