"""
AEGIS Simulation Agent – Celery App + Monte Carlo Tasks

Each task receives a strategy name and event context, queries Neo4j
for relevant attack paths, then runs N-iteration Monte Carlo simulation
using numpy for vectorised sampling.

Transition probabilities are treated as uncertain: each step's probability
is sampled from a Beta(α, β) distribution parameterised by the known
PRECEDES weight and a fixed effective-sample-size prior, producing a
distribution of outcomes rather than a deterministic result.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import numpy as np
from celery import Celery
from neo4j import GraphDatabase

from config import (
    ALL_STRATEGIES,
    BETA_ALPHA_PRIOR,
    BETA_BETA_PRIOR,
    BETA_EFFECTIVE_N,
    DETECTION_PENALTY,
    LATERAL_MOVEMENT_TTPS,
    MAX_PATHS_PER_TASK,
    settings,
)
from neo4j_queries import sync_get_attack_paths, sync_get_detection_coverage

logger = logging.getLogger("aegis.simulation.worker")

# ---------------------------------------------------------------------------
# Celery application
# ---------------------------------------------------------------------------

celery_app = Celery(
    "aegis_simulation",
    broker=settings.celery_broker_url,
    backend=settings.celery_backend_url,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_acks_late=True,           # re-queue on worker crash
    worker_prefetch_multiplier=1,  # one task at a time per worker slot
    result_expires=3600,
)


# ---------------------------------------------------------------------------
# Per-worker Neo4j driver (created once per Celery worker process)
# ---------------------------------------------------------------------------

_neo4j_driver: GraphDatabase | None = None


def _get_driver() -> GraphDatabase:
    global _neo4j_driver
    if _neo4j_driver is None:
        _neo4j_driver = GraphDatabase.driver(
            settings.neo4j_url,
            auth=(settings.neo4j_user, settings.neo4j_password),
            connection_timeout=10,
            max_connection_lifetime=300,
            connection_acquisition_timeout=30,
        )
    return _neo4j_driver


# ---------------------------------------------------------------------------
# Strategy path filtering / parameter modification
# ---------------------------------------------------------------------------

def _apply_strategy(
    paths: list[dict[str, Any]],
    strategy: str,
    cvss: float | None,
) -> list[dict[str, Any]]:
    """
    Filter and annotate paths according to the selected strategy.
    Returns a (possibly shorter) list of paths with optional modifier keys:
      ``probability_boost``         – multiplier applied to each transition prob
      ``detection_penalty_modifier`` – multiplier applied to the detection penalty
    """
    if not paths:
        return paths

    if strategy == "shortest_path":
        # Operate only on the shortest hop paths (bottom third by step count)
        paths = sorted(paths, key=lambda p: len(p.get("steps") or []))
        cutoff = max(1, len(paths) // 3)
        paths = paths[:cutoff]

    elif strategy == "evasion_first":
        # Attacker actively evades detection — halve the effective penalty
        paths = [dict(p, detection_penalty_modifier=0.5) for p in paths]

    elif strategy == "vuln_amplified":
        # Elevated exploitation capability because the CVE is present
        boost = min(1.8, 1.0 + (cvss or 5.0) / 10.0)
        paths = [dict(p, probability_boost=boost) for p in paths]

    elif strategy == "lateral_movement":
        # Only paths that traverse at least one lateral-movement TTP
        paths = [
            p for p in paths
            if any(
                step in LATERAL_MOVEMENT_TTPS
                for step in (p.get("steps") or [])
            )
        ]
        # Fall back to all paths if none qualify (keeps simulation meaningful)
        if not paths:
            logger.debug("No lateral-movement paths found; using all paths.")
            paths = paths or []

    # full_landscape: no filtering

    return paths[:MAX_PATHS_PER_TASK]


# ---------------------------------------------------------------------------
# Monte Carlo core (numpy-vectorised)
# ---------------------------------------------------------------------------

def _monte_carlo_path(
    path: dict[str, Any],
    n_iterations: int,
    driver,
) -> dict[str, Any]:
    """
    Run ``n_iterations`` Monte Carlo trials for a single attack path.

    Each trial independently samples transition probabilities from Beta
    distributions, then applies Bernoulli steps and detection blocking.

    Returns a dict of per-path statistics.
    """
    steps: list[str] = path.get("steps") or []
    transitions: list[dict] = path.get("transitions") or []
    prob_boost   = float(path.get("probability_boost",          1.0))
    det_modifier = float(path.get("detection_penalty_modifier", 1.0))

    if not transitions:
        return {
            "path_id":         path.get("path_id", "unknown"),
            "path_name":       path.get("path_name", ""),
            "steps":           steps,
            "success_rate":    0.0,
            "detection_prob":  0.5,
            "mean_path_length": 0.0,
            "target_ids":      path.get("target_ids", []),
            "n_iterations":    n_iterations,
        }

    base_probs = np.array([
        min(0.98, t["prob"] * prob_boost)
        for t in transitions
    ], dtype=float)

    n_steps = len(base_probs)

    # Beta distribution parameters: encode known probability as the mode of
    # Beta(α + p * n_eff,  β + (1-p) * n_eff)
    alphas = BETA_ALPHA_PRIOR + base_probs * BETA_EFFECTIVE_N
    betas  = BETA_BETA_PRIOR  + (1.0 - base_probs) * BETA_EFFECTIVE_N

    # Detection coverage per step
    det_coverage = np.array([
        sync_get_detection_coverage(driver, t["from_id"])
        for t in transitions
    ], dtype=float)
    effective_penalty = DETECTION_PENALTY * det_modifier

    # ── Vectorised sampling ───────────────────────────────────────────────
    # Shape: (n_iterations, n_steps)
    sampled_probs = np.random.beta(alphas, betas, size=(n_iterations, n_steps))

    # Bernoulli step success
    step_success = np.random.random((n_iterations, n_steps)) < sampled_probs

    # Detection: each step independently triggers with coverage * penalty
    step_detected = np.random.random((n_iterations, n_steps)) < (
        det_coverage * effective_penalty
    )

    # A step is blocked if it triggers detection; detection only matters
    # when the attacker actually attempts the step
    step_blocked = step_detected & step_success

    # Combined: step progresses if it succeeds AND is not blocked
    step_progressed = step_success & ~step_blocked

    # Path succeeds only if every step progresses
    path_success = np.all(step_progressed, axis=1)
    success_rate = float(path_success.mean())

    # Detection probability: P(at least one step detected | path attempted)
    any_detected = np.any(step_detected & step_success, axis=1)
    detection_prob = float(any_detected.mean())

    # Mean path depth before termination
    # For failed paths, find the index of the first non-progressed step
    first_block = np.argmax(~step_progressed, axis=1)
    mean_path_length = float(
        np.where(path_success, n_steps, first_block).mean()
    )

    return {
        "path_id":          path.get("path_id", "unknown"),
        "path_name":        path.get("path_name", ""),
        "steps":            steps,
        "success_rate":     success_rate,
        "detection_prob":   detection_prob,
        "mean_path_length": mean_path_length,
        "target_ids":       path.get("target_ids", []),
        "n_iterations":     n_iterations,
    }


# ---------------------------------------------------------------------------
# Result aggregation
# ---------------------------------------------------------------------------

def _aggregate_results(
    strategy: str,
    path_results: list[dict[str, Any]],
    n_iterations: int,
) -> dict[str, Any]:
    """Combine per-path Monte Carlo results into a single strategy summary."""
    if not path_results:
        return {
            "strategy":     strategy,
            "n_iterations": n_iterations,
            "paths_found":  0,
            "success_rate": 0.0,
            "detection_prob": 0.5,
            "mean_path_length": 0.0,
            "p_breach":     0.0,
            "top_paths":    [],
        }

    rates = [r["success_rate"]    for r in path_results]
    dets  = [r["detection_prob"]  for r in path_results]
    lens  = [r["mean_path_length"] for r in path_results]

    # Overall breach probability: P(at least one path succeeds)
    p_none_succeed = float(np.prod([1.0 - r for r in rates]))
    p_breach = 1.0 - p_none_succeed

    top_paths = sorted(path_results, key=lambda r: r["success_rate"], reverse=True)[:3]

    return {
        "strategy":         strategy,
        "n_iterations":     n_iterations,
        "paths_found":      len(path_results),
        "success_rate":     float(np.mean(rates)),
        "detection_prob":   float(np.mean(dets)),
        "mean_path_length": float(np.mean(lens)),
        "p_breach":         p_breach,
        "top_paths":        top_paths,
    }


# ---------------------------------------------------------------------------
# Celery task
# ---------------------------------------------------------------------------

@celery_app.task(
    bind=True,
    name="aegis.run_simulation_strategy",
    max_retries=2,
    soft_time_limit=270,
    time_limit=300,
)
def run_simulation_strategy(
    self,
    strategy: str,
    cve_id: str | None,
    cvss: float | None,
    n_iterations: int,
) -> dict[str, Any]:
    """
    CPU-bound Monte Carlo simulation for a single strategy.

    Executed by Celery workers in a separate process.  The task:
      1. Queries Neo4j for attack paths relevant to the event's CVE.
      2. Applies strategy-specific filters and modifiers.
      3. Runs Monte Carlo for each path.
      4. Returns an aggregated results dict.
    """
    t0 = time.monotonic()

    if strategy not in ALL_STRATEGIES:
        logger.warning("Unknown strategy '%s'; defaulting to full_landscape.", strategy)
        strategy = "full_landscape"

    try:
        driver = _get_driver()

        # 1. Fetch paths from Neo4j
        paths = sync_get_attack_paths(driver, cve_id=cve_id)
        logger.info(
            "[%s] %d attack paths found for CVE=%s",
            strategy, len(paths), cve_id,
        )

        # 2. Apply strategy filter / modifier
        paths = _apply_strategy(paths, strategy, cvss)
        logger.info("[%s] %d paths after strategy filter", strategy, len(paths))

        # 3. Monte Carlo per path
        path_results = [
            _monte_carlo_path(path, n_iterations, driver)
            for path in paths
        ]

        result = _aggregate_results(strategy, path_results, n_iterations)
        result["elapsed_s"] = round(time.monotonic() - t0, 2)

        logger.info(
            "[%s] p_breach=%.3f  success_rate=%.3f  elapsed=%.1fs",
            strategy,
            result["p_breach"],
            result["success_rate"],
            result["elapsed_s"],
        )
        return result

    except Exception as exc:
        logger.exception("[%s] Task failed: %s", strategy, exc)
        raise self.retry(exc=exc, countdown=15)
