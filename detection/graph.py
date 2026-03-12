"""
AEGIS Detection Agent – LangGraph Graph

Topology:

    load_finding
        │
        ├── skip=True  ──────────────────────────────► forward_to_advisory
        │                                                      │
        └── skip=False                                         ▼
                │                                            END
                ▼
        generate_detections
                │
                ▼
        forward_to_advisory
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

from nodes import (
    forward_to_advisory,
    generate_detections,
    load_finding,
)
from state import DetectionState


# ---------------------------------------------------------------------------
# Edge conditions
# ---------------------------------------------------------------------------

def _after_load_finding(
    state: DetectionState,
) -> Literal["generate_detections", "forward_to_advisory"]:
    return "forward_to_advisory" if state.get("skip") else "generate_detections"


# ---------------------------------------------------------------------------
# Graph factory
# ---------------------------------------------------------------------------

def build_graph(
    redis_client: aioredis.Redis,
    anthropic_client: AsyncAnthropic,
) -> StateGraph:
    """
    Construct and compile the detection graph.

    Dependencies are injected via ``functools.partial`` so every node
    signature is ``(state) -> dict``, matching LangGraph's interface.
    """
    _generate = functools.partial(generate_detections, client=anthropic_client, redis=redis_client)
    _forward  = functools.partial(forward_to_advisory,  redis=redis_client)

    graph = StateGraph(DetectionState)

    graph.add_node("load_finding",         load_finding)
    graph.add_node("generate_detections",  _generate)
    graph.add_node("forward_to_advisory",  _forward)

    graph.add_edge(START, "load_finding")

    graph.add_conditional_edges(
        "load_finding",
        _after_load_finding,
        {
            "generate_detections": "generate_detections",
            "forward_to_advisory": "forward_to_advisory",
        },
    )

    graph.add_edge("generate_detections", "forward_to_advisory")
    graph.add_edge("forward_to_advisory", END)

    return graph.compile()
