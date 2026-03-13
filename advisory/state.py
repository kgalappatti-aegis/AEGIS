"""
AEGIS Advisory Agent – LangGraph State
"""

from __future__ import annotations

from typing import Any, Optional
from typing_extensions import TypedDict


class AdvisoryState(TypedDict, total=False):
    """
    Mutable state threaded through all five LangGraph nodes.

    Only ``msg_id`` and ``raw_fields`` are guaranteed at graph entry.
    """

    # ── Input ────────────────────────────────────────────────────────────────
    msg_id:     str             # Redis stream message ID for XACK
    raw_fields: dict[str, str]  # raw decoded Redis stream fields

    # ── After load_event ─────────────────────────────────────────────────────
    event_id:             str
    source_type:          str
    priority:             str
    ingested_at:          str
    raw_payload:          dict[str, Any]

    # Triage scores
    relevance_score:      Optional[float]
    infrastructure_match: Optional[float]
    exploitability:       Optional[float]
    temporal_urgency:     Optional[float]

    # Simulation finding
    cve_id:                   Optional[str]
    p_breach:                 float
    delta_p_breach:           float
    highest_risk_path:        list[str]
    blind_spots:              list[str]
    compound_risk_factors:    list[str]
    recommended_detections:   list[str]
    severity:                 str
    sim_summary:              str     # simulation interpret_results summary
    simulated_at:             str

    # Detection output
    sigma_rules:              list[str]
    coverage_gaps:            list[str]
    validation_tests:         list[dict[str, Any]]  # Atomic Red Team tests
    detection_summary:        str
    detected_at:              str

    skip:        bool
    skip_reason: str

    # ── After generate_advisory ───────────────────────────────────────────────
    title:              str
    executive_summary:  str
    technical_summary:  str
    affected_assets:    list[str]
    immediate_actions:  list[str]
    detection_actions:  list[str]
    risk_score:         int              # 0–100
    confidence:         str              # "high" | "medium" | "low"
    tlp:                str              # "RED" | "AMBER" | "GREEN" | "CLEAR"
    mitre_techniques:   list[str]
    ext_references:     list[str]

    # ── After persist ─────────────────────────────────────────────────────────
    advisory_id:   Optional[str]   # UUID from DB
    persist_error: Optional[str]

    # ── After broadcast ───────────────────────────────────────────────────────
    broadcast_ok: bool

    # ── After acknowledge ─────────────────────────────────────────────────────
    acknowledged: bool
