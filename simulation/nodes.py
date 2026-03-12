"""
AEGIS Simulation Agent – LangGraph Nodes

Node execution order:
  load_event → strategy_selector → run_simulation
             → interpret_results → build_finding_paths
             → forward_to_detection

All async nodes; blocking operations (Celery .get(), Neo4j sync queries)
are run in a thread-pool executor so they never stall the event loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
from anthropic import AsyncAnthropic
from celery import group
from neo4j import AsyncDriver

from config import (
    ALL_STRATEGIES,
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
    async_query_paths,
)
from simulation import run_simulation_strategy
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

    logger.info(
        "Loaded event %s (CVE=%s, CVSS=%s, relevance=%.3f)",
        event.event_id, cve_id, cvss, relevance or 0.0,
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
    }


# ---------------------------------------------------------------------------
# Node 2: strategy_selector
# ---------------------------------------------------------------------------

async def strategy_selector(
    state: SimulationState,
    *,
    client: AsyncAnthropic,
) -> dict[str, Any]:
    """
    Claude API call: choose which simulation strategies to run.

    Falls back to ["full_landscape"] with max_iterations=5000 on any error
    so the pipeline never stalls due to an API failure.
    """
    cve_id    = state.get("cve_id")
    cvss      = state.get("cvss")
    relevance = state.get("relevance_score")
    infra     = state.get("infrastructure_match")
    exploit   = state.get("exploitability")

    user_content = json.dumps({
        "cve_id":      cve_id,
        "cvss":        cvss,
        "source_type": state.get("source_type"),
        "triage_scores": {
            "relevance_score":      relevance,
            "infrastructure_match": infra,
            "exploitability":       exploit,
            "temporal_urgency":     state.get("temporal_urgency"),
        },
        "available_strategies": sorted(ALL_STRATEGIES),
    }, indent=2)

    try:
        response = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=512,
            system=(
                "You are an adversarial simulation strategist. "
                "Select which simulation strategies to run based on the threat profile. "
                "Respond only in JSON."
            ),
            messages=[{"role": "user", "content": user_content}],
        )

        raw = response.content[0].text
        parsed = _extract_json(raw)

        # Validate and sanitise
        strategies = [
            s for s in parsed.get("strategies", [])
            if s in ALL_STRATEGIES
        ] or ["full_landscape"]

        max_iter = int(parsed.get("max_iterations", 10_000))
        max_iter = max(1_000, min(max_iter, 50_000))  # clamp to sane range

        logger.info(
            "Strategy selector: %s  (max_iter=%d)  rationale: %s",
            strategies, max_iter, parsed.get("rationale", "")[:80],
        )
        return {
            "strategies":     strategies,
            "rationale":      parsed.get("rationale", ""),
            "max_iterations": max_iter,
        }

    except Exception as exc:
        logger.warning("Strategy selector Claude call failed: %s — using fallback.", exc)
        return {
            "strategies":     ["full_landscape"],
            "rationale":      f"Fallback due to error: {exc}",
            "max_iterations": 5_000,
        }


# ---------------------------------------------------------------------------
# Node 3: run_simulation
# ---------------------------------------------------------------------------

async def run_simulation(state: SimulationState) -> dict[str, Any]:
    """
    Dispatch one Celery task per selected strategy, then wait for all results.

    The `.get()` call blocks a thread-pool thread, not the event loop.
    ``propagate=False`` means individual task failures are returned as
    exception objects rather than raised, so partial results are preserved.
    """
    strategies  = state.get("strategies",     ["full_landscape"])
    max_iter    = state.get("max_iterations", 5_000)
    cve_id      = state.get("cve_id")
    cvss        = state.get("cvss")

    job = group([
        run_simulation_strategy.s(
            strategy=s,
            cve_id=cve_id,
            cvss=cvss,
            n_iterations=max_iter,
        )
        for s in strategies
    ])

    async_result = job.apply_async()

    loop = asyncio.get_running_loop()
    results_list: list[Any] = await loop.run_in_executor(
        None,
        lambda: async_result.get(timeout=300, propagate=False),
    )

    simulation_results: dict[str, dict] = {}
    for strategy, result in zip(strategies, results_list):
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

    # ── Determine actor name from TTPs ────────────────────────────────
    ttp_ids = [t for t in highest_risk_path if isinstance(t, str) and t.startswith("T")]
    actor_name = await async_get_top_actor(driver, ttp_ids)

    # ── Part 2: Query Neo4j paths per strategy ────────────────────────
    finding_paths: list[dict[str, Any]] = []
    is_synthetic = False

    for strategy in strategies:
        raw_paths = await async_query_paths(driver, actor_name, strategy)

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

            finding_paths.append({
                "label": path_label(strategy, rank),
                "p_breach": p_breach_path,
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

    logger.info(
        "Built %d finding paths for event %s (synthetic=%s)",
        len(finding_paths), state.get("event_id", "?"), is_synthetic,
    )

    return {
        "finding_paths": finding_paths,
        "synthetic_path": is_synthetic,
    }


def _bstr(val: Any) -> str:
    """Decode bytes to str if needed."""
    return val.decode() if isinstance(val, bytes) else str(val) if val else ""


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
      aegis:ttp:hits        HINCRBY for each TTP in highest_risk_path
      aegis:ttp:priority    HSET only if new priority is worse than existing
      aegis:ttp:actors      HSET comma-joined actor set
      aegis:ttp:updated_at  ISO timestamp
      aegis:sim:findings:{event_id}  full finding JSON (24h TTL)
    """
    event_id = state.get("event_id", "")
    priority = state.get("priority", "P3")
    highest_risk_path = state.get("highest_risk_path", [])

    # Collect actor names from simulation results
    sim_results = state.get("simulation_results", {})
    actor_names: set[str] = set()
    for result in sim_results.values():
        for path in result.get("top_paths", []):
            for actor in path.get("actors", []):
                if isinstance(actor, str) and actor:
                    actor_names.add(actor)

    pipe = redis.pipeline()

    # 1. HINCRBY hit counts for each TTP in the path
    ttp_ids = [t for t in highest_risk_path if isinstance(t, str) and t.startswith("T")]
    for ttp_id in ttp_ids:
        pipe.hincrby("aegis:ttp:hits", ttp_id, 1)

    # 2. Priority — only set if new priority is worse (lower rank number)
    #    Use a pipeline GET + conditional SET pattern via Lua-free approach:
    #    fetch current values first, then set in batch.
    await pipe.execute()

    # Priority updates require reading current values
    if ttp_ids:
        current_priorities = await asyncio.gather(
            *(redis.hget("aegis:ttp:priority", tid) for tid in ttp_ids)
        )
        pipe2 = redis.pipeline()
        new_rank = _PRIORITY_RANK.get(priority, 3)
        for tid, cur_p in zip(ttp_ids, current_priorities):
            cur_str = cur_p.decode() if isinstance(cur_p, bytes) else cur_p
            cur_rank = _PRIORITY_RANK.get(cur_str, 3) if cur_str else 3
            if new_rank < cur_rank:
                pipe2.hset("aegis:ttp:priority", tid, priority)

        # 3. Actor names — merge with existing comma-joined set
        if actor_names:
            current_actors = await asyncio.gather(
                *(redis.hget("aegis:ttp:actors", tid) for tid in ttp_ids)
            )
            for tid, cur_a in zip(ttp_ids, current_actors):
                cur_str = cur_a.decode() if isinstance(cur_a, bytes) else (cur_a or "")
                existing = {a.strip() for a in cur_str.split(",") if a.strip()} if cur_str else set()
                merged = existing | actor_names
                pipe2.hset("aegis:ttp:actors", tid, ",".join(sorted(merged)))

        # 4. Updated timestamp
        pipe2.set("aegis:ttp:updated_at", datetime.now(timezone.utc).isoformat())
        await pipe2.execute()

    # 5. Serialize full finding to aegis:sim:findings:{event_id} with 24h TTL
    if event_id:
        finding_paths = state.get("finding_paths", [])
        finding = {
            "event_id":              event_id,
            "cve":                   state.get("cve_id"),
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
            "iterations":            state.get("max_iterations", 10_000),
            "paths":                 finding_paths,
            "synthetic_path":        state.get("synthetic_path", False),
            "simulated_at":          datetime.now(timezone.utc).isoformat(),
        }
        await redis.set(
            f"aegis:sim:findings:{event_id}",
            json.dumps(finding),
            ex=86_400,  # 24h TTL
        )

        # Also update TTP aggregates from structured path nodes
        for fp in finding_paths:
            for node in fp.get("nodes", []):
                if node.get("type") != "ttp":
                    continue
                nid = node.get("id", "")
                if not nid:
                    continue
                await redis.hincrby("aegis:ttp:hits", nid, 1)

    logger.debug(
        "TTP aggregation: %d TTPs updated for event %s",
        len(ttp_ids), event_id,
    )
