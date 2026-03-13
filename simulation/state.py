"""
AEGIS Simulation Agent – LangGraph State + Finding Schema
"""

from __future__ import annotations

from typing import Any, Optional
from typing_extensions import TypedDict


class SimulationState(TypedDict, total=False):
    """
    Mutable state threaded through all five LangGraph nodes.

    Fields are populated progressively; only ``msg_id`` and ``raw_fields``
    are guaranteed to be present at the start of every graph run.
    """

    # ── Input (pre-populated by the consumer loop) ────────────────────────
    msg_id:     str               # Redis stream message ID for XACK
    raw_fields: dict[str, str]    # raw decoded Redis stream fields

    # ── After load_event ──────────────────────────────────────────────────
    event_id:             str
    source_type:          str
    priority:             str
    routing_target:       str
    ingested_at:          str
    ttl:                  int
    raw_payload:          dict[str, Any]
    relevance_score:      Optional[float]
    infrastructure_match: Optional[float]
    exploitability:       Optional[float]
    temporal_urgency:     Optional[float]
    cve_id:               Optional[str]
    cvss:                 Optional[float]

    skip:        bool
    skip_reason: str

    # ── After strategy_selector ───────────────────────────────────────────
    strategies:     list[str]
    rationale:      str
    max_iterations: int

    # ── After run_simulation ──────────────────────────────────────────────
    # Keys are strategy names; values are per-strategy result dicts.
    simulation_results: dict[str, dict[str, Any]]

    # ── After interpret_results ───────────────────────────────────────────
    p_breach:               float
    delta_p_breach:         float
    highest_risk_path:      list[str]
    blind_spots:            list[str]
    compound_risk_factors:  list[str]
    recommended_detections: list[str]
    severity:               str
    summary:                str

    # ── After load_event (entry TTP heuristic) ───────────────────────────
    entry_ttp:      str                    # selected initial-access TTP ID

    # ── After build_finding_paths ───────────────────────────────────────
    finding_paths:  list[dict[str, Any]]   # structured path data for frontend
    synthetic_path: bool                   # True if Neo4j returned no paths
    actor_name:     Optional[str]          # top threat actor from Neo4j
    rotation_map:   dict[str, list[str]]   # detected TTP → substitute TTP IDs

    # ── After forward_to_detection ────────────────────────────────────────
    forwarded:     bool
    forward_error: Optional[str]
