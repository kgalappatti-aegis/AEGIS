"""
AEGIS LangGraph StateGraph
Defines the orchestration pipeline and conditional routing edges.

Graph topology:
                        ┌──────────┐
              ┌─ error ─► send_dlq │
              │          └──────────┘
    validate ─┤
              │          ┌──────────┐     ┌──────────┐
              └─  ok  ──► classify ├──ok─► dispatch │
                          └────┬────┘     └──────────┘
                               │ error
                          ┌────▼────┐
                          │send_dlq │
                          └─────────┘
"""

from __future__ import annotations

import functools
import logging
from typing import Literal

import redis.asyncio as aioredis
from langgraph.graph import END, START, StateGraph

from nodes import classify, dispatch, send_to_dlq, validate
from schema import OrchestratorState

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Edge condition helpers
# ---------------------------------------------------------------------------

def _after_validate(
    state: OrchestratorState,
) -> Literal["classify", "send_dlq"]:
    return "send_dlq" if state.get("validation_error") else "classify"


def _after_classify(
    state: OrchestratorState,
) -> Literal["dispatch", "send_dlq"]:
    return "send_dlq" if not state.get("dispatch_key") else "dispatch"


# ---------------------------------------------------------------------------
# Graph factory
# ---------------------------------------------------------------------------

def build_graph(redis_client: aioredis.Redis) -> StateGraph:
    """
    Constructs and compiles the AEGIS orchestration graph.

    Async nodes (dispatch / send_to_dlq) are wrapped with functools.partial
    to inject the shared Redis client at build time, keeping node signatures
    compatible with LangGraph's synchronous-or-async invocation model.
    """

    # Bind Redis client into async nodes
    _dispatch = functools.partial(dispatch, redis=redis_client)
    _send_dlq = functools.partial(send_to_dlq, redis=redis_client)

    graph = StateGraph(OrchestratorState)

    # Register nodes
    graph.add_node("validate",  validate)
    graph.add_node("classify",  classify)
    graph.add_node("dispatch",  _dispatch)
    graph.add_node("send_dlq",  _send_dlq)

    # Entry edge
    graph.add_edge(START, "validate")

    # Conditional edge: validate → classify | send_dlq
    graph.add_conditional_edges(
        "validate",
        _after_validate,
        {"classify": "classify", "send_dlq": "send_dlq"},
    )

    # Conditional edge: classify → dispatch | send_dlq
    graph.add_conditional_edges(
        "classify",
        _after_classify,
        {"dispatch": "dispatch", "send_dlq": "send_dlq"},
    )

    # Terminal edges
    graph.add_edge("dispatch",  END)
    graph.add_edge("send_dlq", END)

    return graph.compile()
