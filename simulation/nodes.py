"""
AEGIS Simulation Agent – LangGraph Nodes

Node execution order:
  load_event → strategy_selector → run_simulation
             → interpret_and_build (interpret_results ∥ build_finding_paths)
             → forward_to_detection

All async nodes; blocking operations (Celery .get(), Neo4j sync queries)
are run in a thread-pool executor so they never stall the event loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
from anthropic import AsyncAnthropic
from neo4j import AsyncDriver

from config import (
    ALL_STRATEGIES,
    BROADCAST_CHANNEL,
    CONSUMER_GROUP,
    DETECTION_QUEUE,
    SIMULATION_QUEUE,
    settings,
)
from layout import (
    build_edges,
    build_synthetic_path,
    compute_layout,
    compute_path_p_breach,
    compute_path_stats,
    detect_blind_spots,
    path_label,
)
from neo4j_queries import (
    async_get_asset_context,
    async_get_threat_actors_for_ttps,
    async_get_top_actor,
    async_get_ttp_substitutes,
    async_query_paths,
)
from simulation import compute_delta_p_breach, run_simulation_strategy
from state import SimulationState

logger = logging.getLogger("aegis.simulation.nodes")

# Priority ranking: lower index = worse (higher) priority
_PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


# ---------------------------------------------------------------------------
# JSON extraction helper (handles markdown code fences from Claude)
# ---------------------------------------------------------------------------

def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    # Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Strip markdown fences
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Greedy JSON object search
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    raise ValueError(f"Could not extract JSON from Claude response: {text[:300]}")


# ---------------------------------------------------------------------------
# Entry TTP heuristic
# ---------------------------------------------------------------------------

# Default initial-access TTPs used as graph entry points
ENTRY_TTPS = ["T1190", "T1133", "T1566", "T1195", "T1078"]


def pick_entry_ttp(cve_id: str | None, title: str) -> str:
    """
    Select the most appropriate initial-access TTP based on CVE/title
    heuristics.  This narrows down the Neo4j path search to paths starting
    from a contextually relevant entry technique.
    """
    t = (title or "").lower()
    if any(kw in t for kw in ("ssl", "vpn", "fortinet", "palo", "citrix", "ivanti")):
        return "T1133"   # External Remote Services
    if any(kw in t for kw in ("phish", "email", "macro", "attachment", "spearphish")):
        return "T1566"   # Phishing
    if any(kw in t for kw in ("supply", "package", "npm", "pypi", "dependency")):
        return "T1195"   # Supply Chain Compromise
    if any(kw in t for kw in ("credential", "password", "brute", "default")):
        return "T1078"   # Valid Accounts
    return "T1190"       # Exploit Public-Facing Application (most common)


# ---------------------------------------------------------------------------
# Node 1: load_event
# ---------------------------------------------------------------------------

def load_event(state: SimulationState) -> dict[str, Any]:
    """
    Deserialise and validate the Redis stream message.

    Sets ``skip=True`` when:
    - The message is a non-event (missing source_type)
    - relevance_score < SIM_THRESHOLD (event not interesting enough to simulate)
    """
    import pathlib, sys
    _orch = pathlib.Path(__file__).parent.parent / "orchestrator"
    if str(_orch) not in sys.path:
        sys.path.insert(0, str(_orch))
    from schema import AEGISEvent  # noqa: PLC0415

    fields = state.get("raw_fields", {})

    # Non-event guard
    if "source_type" not in fields:
        return {"skip": True, "skip_reason": "non-event message (no source_type)"}

    try:
        event = AEGISEvent.from_redis_stream(fields)
    except Exception as exc:
        logger.warning("Event parse failed: %s", exc)
        return {"skip": True, "skip_reason": f"parse error: {exc}"}

    relevance = event.relevance_score
    if relevance is not None and relevance < settings.sim_threshold:
        return {
            "skip": True,
            "skip_reason": f"relevance_score {relevance:.3f} < threshold {settings.sim_threshold}",
            # Still carry event_id for logging
            "event_id": event.event_id,
        }

    raw_payload = event.raw_payload or {}
    cve_id  = raw_payload.get("cve_id")
    metrics = raw_payload.get("metrics", {})

    # Extract best available CVSS score
    cvss: float | None = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        primary = next(
            (e for e in entries if e.get("type") == "Primary"),
            entries[0] if entries else None,
        )
        if primary:
            cvss = primary.get("cvssData", {}).get("baseScore")
            break

    # Select contextually appropriate entry TTP based on CVE/title
    title = raw_payload.get("name", "") or raw_payload.get("title", "") or raw_payload.get("info", "")
    entry_ttp = pick_entry_ttp(cve_id, title)

    # MISP-sourced events may carry pre-tagged ATT&CK techniques
    misp_techniques: list[str] = raw_payload.get("misp_techniques", [])
    if misp_techniques:
        # Use the first MISP technique as entry TTP if it's an initial-access TTP
        for mt in misp_techniques:
            if mt in ENTRY_TTPS:
                entry_ttp = mt
                break
        logger.info(
            "MISP techniques detected: %s (entry override: %s)",
            misp_techniques[:5], entry_ttp,
        )

    logger.info(
        "Loaded event %s (CVE=%s, CVSS=%s, relevance=%.3f, entry=%s)",
        event.event_id, cve_id, cvss, relevance or 0.0, entry_ttp,
    )

    return {
        "skip":               False,
        "event_id":           event.event_id,
        "source_type":        event.source_type,
        "priority":           event.priority,
        "routing_target":     event.routing_target,
        "ingested_at":        event.ingested_at.isoformat(),
        "ttl":                event.ttl,
        "raw_payload":        raw_payload,
        "relevance_score":    event.relevance_score,
        "infrastructure_match": event.infrastructure_match,
        "exploitability":     event.exploitability,
        "temporal_urgency":   event.temporal_urgency,
        "cve_id":             cve_id,
        "cvss":               cvss,
        "entry_ttp":          entry_ttp,
    }


# ---------------------------------------------------------------------------
# Node 2: strategy_selector
# ---------------------------------------------------------------------------

def strategy_selector(state: SimulationState) -> dict[str, Any]:
    """
    Deterministic strategy selection based on triage scores and CVSS.

    Rules:
      - CVSS ≥ 9.0 or exploitability ≥ 0.8  → vuln_amplified + shortest_path
      - infrastructure_match ≥ 0.8            → lateral_movement added
      - temporal_urgency ≥ 0.8                → evasion_first added
      - Always includes full_landscape as baseline
      - Iterations scale with severity: 10k (critical), 5k (high), 3k (default)
    """
    cvss      = state.get("cvss") or 0.0
    relevance = state.get("relevance_score") or 0.0
    infra     = state.get("infrastructure_match") or 0.0
    exploit   = state.get("exploitability") or 0.0
    urgency   = state.get("temporal_urgency") or 0.0

    strategies: list[str] = ["full_landscape"]
    reasons: list[str] = []

    if cvss >= 9.0 or exploit >= 0.8:
        strategies.extend(["vuln_amplified", "shortest_path"])
        reasons.append(f"high severity (CVSS={cvss}, exploit={exploit:.2f})")

    if infra >= 0.8:
        strategies.append("lateral_movement")
        reasons.append(f"infra match={infra:.2f}")

    if urgency >= 0.8:
        strategies.append("evasion_first")
        reasons.append(f"temporal urgency={urgency:.2f}")

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for s in strategies:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    strategies = unique

    # Iteration count scales with criticality
    if cvss >= 9.0 or relevance >= 0.8:
        max_iter = 10_000
    elif cvss >= 7.0 or relevance >= 0.6:
        max_iter = 5_000
    else:
        max_iter = 3_000

    rationale = "; ".join(reasons) if reasons else "baseline scan"
    logger.info(
        "Strategy selector: %s  (max_iter=%d)  rationale: %s",
        strategies, max_iter, rationale,
    )
    return {
        "strategies":     strategies,
        "rationale":      rationale,
        "max_iterations": max_iter,
    }


# ---------------------------------------------------------------------------
# Node 3: run_simulation
# ---------------------------------------------------------------------------

async def run_simulation(state: SimulationState) -> dict[str, Any]:
    """
    Dispatch one Celery task per selected strategy, then wait for all results.

    Tasks are dispatched individually (not as a Celery group) and each result
    is collected via ``AsyncResult.get()`` in a thread-pool executor to avoid
    ``GroupResult.join_native`` pub/sub issues in asyncio contexts.
    """
    strategies  = state.get("strategies",     ["full_landscape"])
    max_iter    = state.get("max_iterations", 5_000)
    cve_id      = state.get("cve_id")
    cvss        = state.get("cvss")

    # Dispatch all tasks up front
    pending: list[tuple[str, Any]] = []
    for s in strategies:
        ar = run_simulation_strategy.apply_async(
            kwargs=dict(
                strategy=s,
                cve_id=cve_id,
                cvss=cvss,
                n_iterations=max_iter,
            ),
        )
        logger.info("Dispatched strategy=%s  task_id=%s", s, ar.id)
        pending.append((s, ar))

    # Collect results individually — avoids GroupResult.join_native
    loop = asyncio.get_running_loop()
    simulation_results: dict[str, dict] = {}

    for strategy, ar in pending:
        try:
            result = await loop.run_in_executor(
                None,
                lambda _ar=ar: _ar.get(timeout=60, propagate=False),
            )
            if isinstance(result, Exception):
                logger.error("Strategy %s failed: %s", strategy, result)
                simulation_results[strategy] = {
                    "strategy":     strategy,
                    "error":        str(result),
                    "p_breach":     0.0,
                    "success_rate": 0.0,
                    "paths_found":  0,
                }
            else:
                simulation_results[strategy] = result
        except Exception as exc:
            logger.error("Strategy %s result retrieval failed: %s", strategy, exc)
            simulation_results[strategy] = {
                "strategy":     strategy,
                "error":        str(exc),
                "p_breach":     0.0,
                "success_rate": 0.0,
                "paths_found":  0,
            }

    return {"simulation_results": simulation_results}


# ---------------------------------------------------------------------------
# Node 4: interpret_results
# ---------------------------------------------------------------------------

async def interpret_results(
    state: SimulationState,
    *,
    client: AsyncAnthropic,
    driver: AsyncDriver,
) -> dict[str, Any]:
    """
    Claude API call: synthesise simulation results into a structured finding.

    Enriches the prompt with asset context and threat-actor attribution
    fetched from Neo4j.
    """
    sim_results = state.get("simulation_results", {})
    cve_id      = state.get("cve_id")

    # Collect all targeted asset IDs from simulation results
    targeted_assets: set[str] = set()
    all_ttp_steps:   set[str] = set()
    for result in sim_results.values():
        for path in result.get("top_paths", []):
            targeted_assets.update(path.get("target_ids", []))
            all_ttp_steps.update(path.get("steps", []))

    # Parallel Neo4j enrichment
    asset_rows, actor_rows = await asyncio.gather(
        async_get_asset_context(driver, list(targeted_assets)),
        async_get_threat_actors_for_ttps(driver, list(all_ttp_steps)),
    )

    user_content = json.dumps({
        "event": {
            "cve_id":               cve_id,
            "cvss":                 state.get("cvss"),
            "source_type":          state.get("source_type"),
            "relevance_score":      state.get("relevance_score"),
            "infrastructure_match": state.get("infrastructure_match"),
            "exploitability":       state.get("exploitability"),
        },
        "simulation_results": {
            s: {k: v for k, v in r.items() if k != "top_paths"}
            for s, r in sim_results.items()
        },
        "asset_context":        asset_rows,
        "threat_actor_profile": actor_rows,
        "strategy_rationale":   state.get("rationale", ""),
    }, indent=2)

    fallback = {
        "p_breach":               max(
            (r.get("p_breach", 0.0) for r in sim_results.values()), default=0.0
        ),
        "delta_p_breach":         0.0,
        "highest_risk_path":      [],
        "blind_spots":            [],
        "compound_risk_factors":  ["Simulation interpretation unavailable"],
        "recommended_detections": [],
        "severity":               "medium",
        "summary":                "Simulation completed but interpretation failed.",
    }

    try:
        response = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1_024,
            system=(
                "You are a security analyst interpreting Monte Carlo attack simulation results. "
                "Respond only in JSON."
            ),
            messages=[{"role": "user", "content": user_content}],
        )

        raw    = response.content[0].text
        parsed = _extract_json(raw)

        # Clamp numeric fields
        p_breach = max(0.0, min(1.0, float(parsed.get("p_breach", 0.0))))
        delta    = max(-1.0, min(1.0, float(parsed.get("delta_p_breach", 0.0))))
        severity = parsed.get("severity", "medium")
        if severity not in ("critical", "high", "medium", "low"):
            severity = "medium"

        logger.info(
            "Interpretation: p_breach=%.3f  delta=%.3f  severity=%s",
            p_breach, delta, severity,
        )

        return {
            "p_breach":               p_breach,
            "delta_p_breach":         delta,
            "highest_risk_path":      parsed.get("highest_risk_path",      []),
            "blind_spots":            parsed.get("blind_spots",            []),
            "compound_risk_factors":  parsed.get("compound_risk_factors",  []),
            "recommended_detections": parsed.get("recommended_detections", []),
            "severity":               severity,
            "summary":                parsed.get("summary", ""),
        }

    except Exception as exc:
        logger.warning("Interpret results Claude call failed: %s — using fallback.", exc)
        return fallback


# ---------------------------------------------------------------------------
# Node 5: build_finding_paths  (Neo4j graph traversal + layout)
# ---------------------------------------------------------------------------

async def build_finding_paths(
    state: SimulationState,
    *,
    driver: AsyncDriver,
    redis: aioredis.Redis,
) -> dict[str, Any]:
    """
    Query Neo4j for structured attack paths per strategy, look up detection
    coverage from Redis, compute SVG layout coordinates, and assemble
    the full finding payload for the frontend.
    """
    strategies = state.get("strategies", ["full_landscape"])
    cve_id = state.get("cve_id")
    entry_ttp = state.get("entry_ttp")
    priority = state.get("priority", "P3")
    sim_results = state.get("simulation_results", {})
    highest_risk_path = state.get("highest_risk_path", [])

    # ── Part 3: Fetch detection coverage + sigma hints from Redis ─────
    cov_raw = await redis.hgetall("aegis:detection:coverage") or {}
    sig_raw = await redis.hgetall("aegis:detection:sigma") or {}
    coverage_map: dict[str, str] = {
        (_bstr(k)): _bstr(v) for k, v in cov_raw.items()
    }
    sigma_map: dict[str, str] = {
        (_bstr(k)): _bstr(v) for k, v in sig_raw.items()
    }

    # ── MISP techniques: use as supplementary TTP seed ────────────────
    misp_techniques: list[str] = (state.get("raw_payload") or {}).get("misp_techniques", [])

    # ── Determine actor name from TTPs (extracted from sim results) ──
    # Pull TTP steps directly from simulation results so this node
    # does not depend on interpret_results (enables parallel execution).
    all_ttp_ids: list[str] = []
    for result in sim_results.values():
        for path in result.get("top_paths", []):
            all_ttp_ids.extend(
                s for s in path.get("steps", [])
                if isinstance(s, str) and s.startswith("T")
            )
    # Also include any highest_risk_path TTPs if already available
    all_ttp_ids.extend(
        t for t in highest_risk_path
        if isinstance(t, str) and t.startswith("T")
    )
    # Include MISP-tagged techniques in the TTP set for actor resolution
    all_ttp_ids.extend(t for t in misp_techniques if t not in all_ttp_ids)
    ttp_ids = list(dict.fromkeys(all_ttp_ids))  # dedupe, preserve order
    actor_name = await async_get_top_actor(driver, ttp_ids)
    # MISP events may carry explicit actor attribution
    if not actor_name:
        misp_actors = (state.get("raw_payload") or {}).get("threat_actors", [])
        if misp_actors:
            actor_name = misp_actors[0]

    # ── Part 2: Query Neo4j paths per strategy ────────────────────────
    finding_paths: list[dict[str, Any]] = []
    is_synthetic = False

    for strategy in strategies:
        raw_paths = await async_query_paths(driver, actor_name, strategy, entry_ttp=entry_ttp)

        if not raw_paths:
            continue

        for rank, path_data in enumerate(raw_paths):
            ttp_nodes = path_data["nodes"]
            prob_map = path_data["transitions"]

            # Assign probabilities to each TTP by its mitre_id
            for ttp in ttp_nodes:
                mid = ttp.get("mitre_id", "")
                if mid not in prob_map:
                    prob_map[mid] = 0.5

            # Part 4: Compute layout
            layout_nodes = compute_layout(
                ttp_nodes, coverage_map, sigma_map, prob_map,
            )

            # Part 6: Build edges
            edges = build_edges(ttp_nodes, prob_map)

            # Part 5: Detect blind spots
            blind_spots = detect_blind_spots(layout_nodes)
            detections_count, hop_count = compute_path_stats(layout_nodes)
            p_breach_path = compute_path_p_breach(edges)

            # Compute delta_p_breach for CVE-relevant paths
            # CVE steps are those in initial-access, execution, priv-esc tactics
            cve_tactics = {"initial-access", "execution", "privilege-escalation"}
            cve_step_probs = [
                float(prob_map.get(t.get("mitre_id", ""), 0.75))
                for t in ttp_nodes
                if t.get("tactic") in cve_tactics
            ] if cve_id else []
            dp = 0.0
            if cve_step_probs:
                try:
                    dp = compute_delta_p_breach(p_breach_path, cve_step_probs)
                except Exception:
                    dp = 0.0

            finding_paths.append({
                "label": path_label(strategy, rank),
                "strategy": strategy,
                "p_breach": p_breach_path,
                "delta_p_breach": dp,
                "nodes": layout_nodes,
                "edges": edges,
                "blindSpots": blind_spots,
                "hopCount": hop_count,
                "detectionsCount": detections_count,
            })

    # ── Part 8: Fallback if no paths found ────────────────────────────
    if not finding_paths:
        logger.warning(
            "No paths found in Neo4j for %s/%s, using heuristic fallback",
            cve_id, actor_name,
        )
        is_synthetic = True
        layout_nodes, edges, blind_spots = build_synthetic_path(
            coverage_map, sigma_map,
        )
        detections_count, hop_count = compute_path_stats(layout_nodes)
        p_breach_path = compute_path_p_breach(edges)

        finding_paths.append({
            "label": "Synthetic fallback",
            "p_breach": p_breach_path,
            "nodes": layout_nodes,
            "edges": edges,
            "blindSpots": blind_spots,
            "hopCount": hop_count,
            "detectionsCount": detections_count,
        })

    # ── TTP-Rotation: for detected techniques in the best path, query
    #    structurally equivalent alternatives with lower detection coverage.
    #    Run for P0/P1. Augments finding metadata, does not create new paths.
    rotation_map: dict[str, list[str]] = {}
    if priority in ("P0", "P1") and finding_paths and not is_synthetic:
        best_path_nodes = finding_paths[0].get("nodes", [])
        for node in best_path_nodes:
            if node.get("type") != "ttp":
                continue
            mid = node.get("id", "")
            cov = node.get("cov", "none")
            if cov in ("partial", "detected") and mid:
                subs = await async_get_ttp_substitutes(
                    driver, mid, node.get("tactic", ""),
                )
                if subs:
                    rotation_map[mid] = [s["mitre_id"] for s in subs]
        if rotation_map:
            logger.info(
                "TTP-Rotation: %d detected techniques have %d total substitutes",
                len(rotation_map),
                sum(len(v) for v in rotation_map.values()),
            )

    logger.info(
        "Built %d finding paths for event %s (synthetic=%s, entry=%s)",
        len(finding_paths), state.get("event_id", "?"), is_synthetic,
        entry_ttp or "default",
    )

    return {
        "finding_paths": finding_paths,
        "synthetic_path": is_synthetic,
        "actor_name": actor_name or "",
        "rotation_map": rotation_map,
    }


def _bstr(val: Any) -> str:
    """Decode bytes to str if needed."""
    return val.decode() if isinstance(val, bytes) else str(val) if val else ""


# ---------------------------------------------------------------------------
# Node 4+5 combined: interpret_and_build (parallel)
# ---------------------------------------------------------------------------

async def interpret_and_build(
    state: SimulationState,
    *,
    client: AsyncAnthropic,
    driver: AsyncDriver,
    redis: aioredis.Redis,
) -> dict[str, Any]:
    """
    Run interpret_results and build_finding_paths concurrently.

    These two nodes have no data dependency on each other (build_finding_paths
    extracts TTPs from simulation_results directly), so running them in
    parallel saves ~18s of serial LLM latency.
    """
    interpret_coro = interpret_results(state, client=client, driver=driver)
    build_coro = build_finding_paths(state, driver=driver, redis=redis)

    results = await asyncio.gather(
        interpret_coro, build_coro, return_exceptions=True,
    )

    merged: dict[str, Any] = {}
    for i, (label, res) in enumerate([
        ("interpret_results", results[0]),
        ("build_finding_paths", results[1]),
    ]):
        if isinstance(res, BaseException):
            logger.error("Parallel node %s failed: %s", label, res)
        else:
            merged.update(res)

    return merged


# ---------------------------------------------------------------------------
# Node 6: forward_to_detection
# ---------------------------------------------------------------------------

async def forward_to_detection(
    state: SimulationState,
    *,
    redis: aioredis.Redis,
) -> dict[str, Any]:
    """
    Write the enriched event + finding to ``aegis:queue:detection``,
    then XACK the source message.

    On skip: only ACKs the message — nothing is forwarded downstream.
    """
    msg_id = state.get("msg_id", "")

    if state.get("skip"):
        logger.debug(
            "Skipping event %s: %s",
            state.get("event_id", "?"), state.get("skip_reason", ""),
        )
        if msg_id:
            await redis.xack(SIMULATION_QUEUE, CONSUMER_GROUP, msg_id)
        return {"forwarded": False, "forward_error": None}

    payload: dict[str, str] = {
        # Core event identity
        "event_id":     state.get("event_id",     ""),
        "source_type":  state.get("source_type",  ""),
        "priority":     state.get("priority",     "P3"),
        "routing_target": "detection",
        "ingested_at":  state.get("ingested_at",  ""),
        "ttl":          str(state.get("ttl",      86_400)),
        "raw_payload":  json.dumps(state.get("raw_payload", {})),
        # Triage scores (pass-through)
        "relevance_score":      str(state.get("relevance_score",    "") or ""),
        "infrastructure_match": str(state.get("infrastructure_match","") or ""),
        "exploitability":       str(state.get("exploitability",     "") or ""),
        "temporal_urgency":     str(state.get("temporal_urgency",   "") or ""),
        # Simulation finding
        "p_breach":               str(state.get("p_breach",               0.0)),
        "delta_p_breach":         str(state.get("delta_p_breach",         0.0)),
        "highest_risk_path":      json.dumps(state.get("highest_risk_path",      [])),
        "blind_spots":            json.dumps(state.get("blind_spots",            [])),
        "compound_risk_factors":  json.dumps(state.get("compound_risk_factors",  [])),
        "recommended_detections": json.dumps(state.get("recommended_detections", [])),
        "severity":               state.get("severity", "medium"),
        "summary":                state.get("summary",  ""),
        "simulated_at":           datetime.now(timezone.utc).isoformat(),
    }

    try:
        stream_id = await redis.xadd(
            DETECTION_QUEUE, payload, maxlen=50_000, approximate=True
        )
        logger.info(
            "Forwarded event %s → %s (stream_id=%s, severity=%s, p_breach=%.3f)",
            state.get("event_id"),
            DETECTION_QUEUE,
            stream_id,
            state.get("severity"),
            state.get("p_breach", 0.0),
        )
        if msg_id:
            await redis.xack(SIMULATION_QUEUE, CONSUMER_GROUP, msg_id)

        # ── Write TTP aggregation hashes and per-finding key ──────────
        await _write_ttp_aggregation(redis, state)

        # Publish stage update for live UI tracking
        event_id = state.get("event_id", "")
        if event_id:
            await redis.hset("aegis:event:stages", event_id, "simulated")
            await redis.publish("aegis:broadcast", json.dumps({
                "type": "stage_update",
                "event_id": event_id,
                "stage": "simulated",
            }))

        return {"forwarded": True, "forward_error": None}

    except Exception as exc:
        logger.error(
            "Forward failed for event %s: %s",
            state.get("event_id"), exc,
        )
        return {"forwarded": False, "forward_error": str(exc)}


async def _write_ttp_aggregation(
    redis: aioredis.Redis,
    state: SimulationState,
) -> None:
    """
    After each simulation run, update Redis aggregation hashes so the
    bridge /api/attack-matrix and /api/simulation/{event_id} endpoints
    can serve data immediately.

    Writes:
      aegis:ttp:hits        HINCRBY for each TTP in highest_risk_path + finding_paths
      aegis:ttp:priority    HSET (set unconditionally on first write, upgrade only after)
      aegis:ttp:actors      HSET comma-joined actor set (from build_finding_paths actor_name)
      aegis:ttp:name        HSET technique name (from finding_path nodes)
      aegis:ttp:tactic      HSET technique tactic (from finding_path nodes)
      aegis:ttp:updated_at  ISO timestamp
      aegis:sim:findings:{event_id}  full finding JSON (24h TTL)

    Also publishes ttp_update messages to aegis:broadcast so the bridge
    can push real-time updates to WebSocket clients.
    """
    event_id = state.get("event_id", "")
    priority = state.get("priority", "P3")
    highest_risk_path = state.get("highest_risk_path", [])

    # Actor name resolved by build_finding_paths via Neo4j
    actor_name = state.get("actor_name", "")

    pipe = redis.pipeline()

    # 1. HINCRBY hit counts for each TTP in the highest_risk_path
    ttp_ids = [t for t in highest_risk_path if isinstance(t, str) and t.startswith("T")]
    for ttp_id in ttp_ids:
        pipe.hincrby("aegis:ttp:hits", ttp_id, 1)
    await pipe.execute()

    # 2. Priority + actors — read current values, then set in batch
    if ttp_ids:
        current_priorities = await asyncio.gather(
            *(redis.hget("aegis:ttp:priority", tid) for tid in ttp_ids)
        )
        pipe2 = redis.pipeline()
        new_rank = _PRIORITY_RANK.get(priority, 3)
        for tid, cur_p in zip(ttp_ids, current_priorities):
            cur_str = cur_p.decode() if isinstance(cur_p, bytes) else cur_p
            if cur_str is None:
                # First write — always set
                pipe2.hset("aegis:ttp:priority", tid, priority)
            else:
                cur_rank = _PRIORITY_RANK.get(cur_str, 3)
                if new_rank < cur_rank:
                    pipe2.hset("aegis:ttp:priority", tid, priority)

        # 3. Actor names — merge actor_name with existing comma-joined set
        if actor_name:
            current_actors = await asyncio.gather(
                *(redis.hget("aegis:ttp:actors", tid) for tid in ttp_ids)
            )
            for tid, cur_a in zip(ttp_ids, current_actors):
                cur_str = cur_a.decode() if isinstance(cur_a, bytes) else (cur_a or "")
                existing = {a.strip() for a in cur_str.split(",") if a.strip()} if cur_str else set()
                merged = existing | {actor_name}
                pipe2.hset("aegis:ttp:actors", tid, ",".join(sorted(merged)))

        # 4. Updated timestamp
        pipe2.set("aegis:ttp:updated_at", datetime.now(timezone.utc).isoformat())
        await pipe2.execute()

    # 5. Serialize full finding to aegis:sim:findings:{event_id} with 24h TTL
    #    Also collect technique metadata from finding_path nodes for the
    #    attack-matrix endpoint.
    if event_id:
        finding_paths = state.get("finding_paths", [])
        finding = {
            "event_id":              event_id,
            "cve":                   state.get("cve_id"),
            "actor":                 actor_name,
            "entry_ttp":             state.get("entry_ttp"),
            "severity":              state.get("severity", "medium"),
            "p_breach":              state.get("p_breach", 0.0),
            "delta_p_breach":        state.get("delta_p_breach", 0.0),
            "risk_score":            int(state.get("p_breach", 0.0) * 100),
            "highest_risk_path":     highest_risk_path,
            "blind_spots":           state.get("blind_spots", []),
            "compound_risk_factors": state.get("compound_risk_factors", []),
            "recommended_detections": state.get("recommended_detections", []),
            "summary":               state.get("summary", ""),
            "strategies":            state.get("strategies", []),
            "strategies_run":        state.get("strategies", []),
            "iterations":            state.get("max_iterations", 10_000),
            "paths":                 finding_paths,
            "rotation_map":          state.get("rotation_map", {}),
            "synthetic_path":        state.get("synthetic_path", False),
            "simulated_at":          datetime.now(timezone.utc).isoformat(),
        }
        await redis.set(
            f"aegis:sim:findings:{event_id}",
            json.dumps(finding),
            ex=86_400,  # 24h TTL
        )

        # Update TTP aggregates + metadata from structured path nodes
        meta_pipe = redis.pipeline()
        for fp in finding_paths:
            for node in fp.get("nodes", []):
                if node.get("type") != "ttp":
                    continue
                nid = node.get("id", "")
                if not nid:
                    continue
                meta_pipe.hincrby("aegis:ttp:hits", nid, 1)
                # Store technique name + tactic so the UI can render dynamically
                if node.get("name"):
                    meta_pipe.hset("aegis:ttp:name", nid, node["name"])
                if node.get("tactic"):
                    meta_pipe.hset("aegis:ttp:tactic", nid, node["tactic"])
        await meta_pipe.execute()

    # 6. Publish ttp_update to aegis:broadcast for real-time WebSocket push
    #    Format matches advisory convention: flat object with "type" at root.
    #    The bridge's subscribe loop pops "type" and wraps the rest into
    #    { type, payload, ts } envelope for the WebSocket client.
    for tid in ttp_ids:
        update_msg = json.dumps({
            "type": "ttp_update",
            "mitre_id": tid,
            "hits_delta": 1,
            "priority": priority,
            "actor": actor_name or None,
        })
        await redis.publish(BROADCAST_CHANNEL, update_msg)

    logger.debug(
        "TTP aggregation: %d TTPs updated for event %s (actor=%s)",
        len(ttp_ids), event_id, actor_name or "unknown",
    )
