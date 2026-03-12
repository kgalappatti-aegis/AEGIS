"""
AEGIS Advisory Agent – LangGraph Graph

Topology:

    load_event
        │
        ├── skip=True  ──────────────────────────────────────► acknowledge
        │                                                           │
        └── skip=False                                              ▼
                │                                                  END
                ▼
        generate_advisory
                │
                ▼
            persist
                │
                ▼
           broadcast
                │
                ▼
          acknowledge
                │
                ▼
               END
"""

from __future__ import annotations

import functools
from typing import Literal

import asyncpg
import redis.asyncio as aioredis
from anthropic import AsyncAnthropic
from langgraph.graph import END, START, StateGraph

from nodes import (
    acknowledge,
    broadcast,
    generate_advisory,
    load_event,
    persist,
)
from state import AdvisoryState


# ---------------------------------------------------------------------------
# Edge conditions
# ---------------------------------------------------------------------------

def _after_load_event(
    state: AdvisoryState,
) -> Literal["generate_advisory", "acknowledge"]:
    return "acknowledge" if state.get("skip") else "generate_advisory"


# ---------------------------------------------------------------------------
# Graph factory
# ---------------------------------------------------------------------------

def build_graph(
    redis_client: aioredis.Redis,
    anthropic_client: AsyncAnthropic,
    db_pool: asyncpg.Pool,
) -> StateGraph:
    """
    Construct and compile the advisory graph.

    All node dependencies are injected via ``functools.partial`` so every
    node signature is ``(state) -> dict``.
    """
    _generate  = functools.partial(generate_advisory, client=anthropic_client)
    _persist   = functools.partial(persist,           pool=db_pool)
    _broadcast = functools.partial(broadcast,         redis=redis_client)
    _ack       = functools.partial(acknowledge,       redis=redis_client)

    graph = StateGraph(AdvisoryState)

    graph.add_node("load_event",        load_event)
    graph.add_node("generate_advisory", _generate)
    graph.add_node("persist",           _persist)
    graph.add_node("broadcast",         _broadcast)
    graph.add_node("acknowledge",       _ack)

    graph.add_edge(START, "load_event")

    graph.add_conditional_edges(
        "load_event",
        _after_load_event,
        {
            "generate_advisory": "generate_advisory",
            "acknowledge":       "acknowledge",
        },
    )

    graph.add_edge("generate_advisory", "persist")
    graph.add_edge("persist",           "broadcast")
    graph.add_edge("broadcast",         "acknowledge")
    graph.add_edge("acknowledge",       END)

    return graph.compile()
