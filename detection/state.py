"""
AEGIS Detection Agent – LangGraph State
"""

from __future__ import annotations

from typing import Any, Optional
from typing_extensions import TypedDict


class DetectionState(TypedDict, total=False):
    """
    Mutable state threaded through all three LangGraph nodes.

    Only ``msg_id`` and ``raw_fields`` are guaranteed at graph entry.
    """

    # ── Input ────────────────────────────────────────────────────────────────
    msg_id:     str             # Redis stream message ID for XACK
    raw_fields: dict[str, str]  # raw decoded Redis stream fields

    # ── After load_finding ───────────────────────────────────────────────────
    event_id:             str
    source_type:          str
    priority:             str
    ingested_at:          str
    raw_payload:          dict[str, Any]

    # Triage pass-through
    relevance_score:      Optional[float]
    infrastructure_match: Optional[float]
    exploitability:       Optional[float]
    temporal_urgency:     Optional[float]

    # Simulation finding
    cve_id:                   Optional[str]
    cvss:                     Optional[float]
    p_breach:                 float
    delta_p_breach:           float
    highest_risk_path:        list[str]
    blind_spots:              list[str]
    compound_risk_factors:    list[str]
    recommended_detections:   list[str]
    severity:                 str
    summary:                  str
    simulated_at:             str

    skip:        bool
    skip_reason: str

    # ── After generate_detections ────────────────────────────────────────────
    sigma_rules:      list[str]            # YAML strings, one per rule
    coverage_gaps:    list[str]            # human-readable gap descriptions
    detection_summary: str                 # one-paragraph analyst summary
    validation_tests: list[dict[str, Any]] # Atomic Red Team tests for validation

    # ── After forward_to_advisory ────────────────────────────────────────────
    forwarded:     bool
    forward_error: Optional[str]
