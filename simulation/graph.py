"""
AEGIS Simulation Agent – LangGraph Graph

Topology:

    load_event
        │
        ├── skip=True  ──────────────────────────────► forward_to_detection
        │                                                      │
        └── skip=False                                         ▼
                │                                             END
                ▼
        strategy_selector
                │
                ▼
        run_simulation
                │
                ▼
        interpret_results
                │
                ▼
        build_finding_paths   ← Neo4j graph traversal + SVG layout
                │
                ▼
        forward_to_detection
                │
                ▼
               END
"""

from __future__ import annotations

import functools
from typing import Literal

import redis.asyncio as aioredis
from anthropic import AsyncAnthropic
from langgraph.graph import END, START, StateGraph
from neo4j import AsyncDriver

from nodes import (
    build_finding_paths,
    forward_to_detection,
    interpret_results,
    load_event,
    run_simulation,
    strategy_selector,
)
from state import SimulationState


# ---------------------------------------------------------------------------
# Edge conditions
# ---------------------------------------------------------------------------

def _after_load_event(
    state: SimulationState,
) -> Literal["strategy_selector", "forward_to_detection"]:
    return "forward_to_detection" if state.get("skip") else "strategy_selector"


# ---------------------------------------------------------------------------
# Graph factory
# ---------------------------------------------------------------------------

def build_graph(
    redis_client: aioredis.Redis,
    neo4j_driver: AsyncDriver,
    anthropic_client: AsyncAnthropic,
) -> StateGraph:
    """
    Construct and compile the simulation graph.

    Dependencies are injected via ``functools.partial`` at build time so
    every node signature is ``(state) -> dict``, matching LangGraph's
    expected interface.
    """
    _strategy_selector = functools.partial(
        strategy_selector, client=anthropic_client
    )
    _interpret_results = functools.partial(
        interpret_results, client=anthropic_client, driver=neo4j_driver
    )
    _build_paths = functools.partial(
        build_finding_paths, driver=neo4j_driver, redis=redis_client
    )
    _forward = functools.partial(
        forward_to_detection, redis=redis_client
    )

    graph = StateGraph(SimulationState)

    graph.add_node("load_event",           load_event)
    graph.add_node("strategy_selector",    _strategy_selector)
    graph.add_node("run_simulation",       run_simulation)
    graph.add_node("interpret_results",    _interpret_results)
    graph.add_node("build_finding_paths",  _build_paths)
    graph.add_node("forward_to_detection", _forward)

    graph.add_edge(START, "load_event")

    graph.add_conditional_edges(
        "load_event",
        _after_load_event,
        {
            "strategy_selector":    "strategy_selector",
            "forward_to_detection": "forward_to_detection",
        },
    )

    graph.add_edge("strategy_selector",    "run_simulation")
    graph.add_edge("run_simulation",       "interpret_results")
    graph.add_edge("interpret_results",    "build_finding_paths")
    graph.add_edge("build_finding_paths",  "forward_to_detection")
    graph.add_edge("forward_to_detection", END)

    return graph.compile()
