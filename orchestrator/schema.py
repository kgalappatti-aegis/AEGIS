"""
AEGIS Event Schema
Pydantic models for validation + TypedDict for LangGraph state.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Optional
from typing_extensions import TypedDict

from pydantic import (
    AwareDatetime,
    BaseModel,
    Field,
    field_validator,
    model_validator,
)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SourceType(str, Enum):
    NVD       = "nvd"        # National Vulnerability Database
    STIX      = "stix"       # STIX/TAXII threat intel bundle
    CISA_KEV  = "cisa_kev"   # CISA Known Exploited Vulnerabilities
    THREATFOX = "threatfox"  # Abuse.ch ThreatFox IOC feed
    EDR       = "edr"        # Endpoint Detection & Response telemetry
    SIEM      = "siem"       # SIEM correlation rule hit
    MISP      = "misp"       # MISP threat intelligence platform


class Priority(str, Enum):
    P0 = "P0"  # Critical  – active exploitation / live endpoint hit
    P1 = "P1"  # High      – confirmed threat intel / SIEM alert
    P2 = "P2"  # Medium    – vulnerability disclosure
    P3 = "P3"  # Low       – contextual / background intel


class RoutingTarget(str, Enum):
    TRIAGE     = "triage"     # Immediate human/agent assessment
    SIMULATION = "simulation" # Adversary emulation / threat modeling
    DETECTION  = "detection"  # Detection rule pipeline
    ADVISORY   = "advisory"   # Vulnerability advisory / patch guidance


# ---------------------------------------------------------------------------
# Redis Streams field registry
# Fields whose values need JSON encoding when serialised to a flat string map.
# ---------------------------------------------------------------------------

_JSON_FIELDS = frozenset({"raw_payload"})

# Fields that hold ISO-8601 datetime strings in the stream.
_DATETIME_FIELDS = frozenset({"ingested_at", "triage_completed_at"})

# Fields that are floats.
_FLOAT_FIELDS = frozenset({
    "relevance_score",
    "infrastructure_match",
    "threat_actor_history",
    "exploitability",
    "temporal_urgency",
})

# Fields that are ints.
_INT_FIELDS = frozenset({"ttl"})


# ---------------------------------------------------------------------------
# Pydantic event model
# ---------------------------------------------------------------------------

class AEGISEvent(BaseModel):
    """
    Canonical event envelope for the AEGIS orchestration pipeline.

    Lifecycle
    ---------
    Ingestion writes the base fields.  The Triage Agent populates the
    ``triage_*`` fields and sets ``triage_completed_at``.

    Redis Streams
    -------------
    ``to_redis_stream()``  → flat ``dict[str, str]``  (None fields omitted)
    ``from_redis_stream()`` ← flat ``dict[str, str]`` (None fields absent)
    """

    # ------------------------------------------------------------------
    # Base fields – written by Ingestion
    # ------------------------------------------------------------------

    event_id: Annotated[
        str,
        Field(
            default_factory=lambda: str(uuid.uuid4()),
            description="UUIDv4 identifier, unique per event.",
            examples=["3fa85f64-5717-4562-b3fc-2c963f66afa6"],
        ),
    ]

    source_type: Annotated[
        SourceType,
        Field(description="Origin feed type. Drives priority and routing."),
    ]

    raw_payload: Annotated[
        dict[str, Any],
        Field(
            default_factory=dict,
            description="Feed-specific payload. Opaque to the orchestrator.",
        ),
    ]

    ingested_at: Annotated[
        AwareDatetime,
        Field(
            default_factory=lambda: datetime.now(timezone.utc),
            description="UTC timestamp of ingestion (ISO-8601 with timezone).",
            examples=["2026-03-11T00:00:00Z"],
        ),
    ]

    priority: Annotated[
        Optional[Priority],
        Field(
            default=None,
            description="Assigned by the classify node. Null on raw inbound events.",
        ),
    ]

    routing_target: Annotated[
        Optional[RoutingTarget],
        Field(
            default=None,
            description="Destination agent queue. Null on raw inbound events.",
        ),
    ]

    ttl: Annotated[
        int,
        Field(
            default=86_400,
            ge=0,
            le=604_800,  # hard cap: 7 days
            description="Event TTL in seconds. Range: 0–604 800 (7 days).",
        ),
    ]

    # ------------------------------------------------------------------
    # Triage enrichment – populated by the Triage Agent
    # ------------------------------------------------------------------

    relevance_score: Annotated[
        Optional[float],
        Field(
            default=None,
            ge=0.0,
            le=1.0,
            description=(
                "Composite triage score [0.0, 1.0] weighting all sub-scores. "
                "Null until triage completes."
            ),
        ),
    ]

    infrastructure_match: Annotated[
        Optional[float],
        Field(
            default=None,
            ge=0.0,
            le=1.0,
            description="Degree to which the threat overlaps known infrastructure [0.0, 1.0].",
        ),
    ]

    threat_actor_history: Annotated[
        Optional[float],
        Field(
            default=None,
            ge=0.0,
            le=1.0,
            description="Confidence that a known threat actor is responsible [0.0, 1.0].",
        ),
    ]

    exploitability: Annotated[
        Optional[float],
        Field(
            default=None,
            ge=0.0,
            le=1.0,
            description="Likelihood of active or near-term exploitation [0.0, 1.0].",
        ),
    ]

    temporal_urgency: Annotated[
        Optional[float],
        Field(
            default=None,
            ge=0.0,
            le=1.0,
            description="Time-sensitivity score based on recency and feed velocity [0.0, 1.0].",
        ),
    ]

    triage_completed_at: Annotated[
        Optional[AwareDatetime],
        Field(
            default=None,
            description="UTC timestamp when the Triage Agent finished scoring. Null until complete.",
        ),
    ]

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @field_validator("event_id", mode="before")
    @classmethod
    def normalise_event_id(cls, v: Any) -> str:
        """Accept UUID objects or strings; reject empty strings."""
        s = str(v).strip()
        if not s:
            raise ValueError("event_id must not be empty")
        return s

    @field_validator("ingested_at", "triage_completed_at", mode="before")
    @classmethod
    def coerce_datetime(cls, v: Any) -> datetime | None:
        """
        Coerce Unix epoch floats and naive datetime objects to UTC.
        Pydantic's AwareDatetime rejects naive datetimes, so UTC is
        attached here before the type check runs.
        """
        if v is None:
            return v
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(v, tz=timezone.utc)
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    @model_validator(mode="after")
    def priority_and_routing_consistent(self) -> AEGISEvent:
        """priority and routing_target must both be set or both be None."""
        has_priority = self.priority is not None
        has_routing  = self.routing_target is not None
        if has_priority ^ has_routing:
            raise ValueError(
                "priority and routing_target must both be set or both be None; "
                f"got priority={self.priority!r}, routing_target={self.routing_target!r}"
            )
        return self

    @model_validator(mode="after")
    def triage_fields_all_or_none(self) -> AEGISEvent:
        """
        All triage scoring fields and triage_completed_at must be set
        together.  Partial triage enrichment indicates a pipeline bug.
        """
        triage_fields = {
            "relevance_score":      self.relevance_score,
            "infrastructure_match": self.infrastructure_match,
            "threat_actor_history": self.threat_actor_history,
            "exploitability":       self.exploitability,
            "temporal_urgency":     self.temporal_urgency,
            "triage_completed_at":  self.triage_completed_at,
        }
        set_fields   = {k for k, v in triage_fields.items() if v is not None}
        unset_fields = {k for k, v in triage_fields.items() if v is None}

        if set_fields and unset_fields:
            raise ValueError(
                "Triage enrichment fields must all be set or all be None. "
                f"Set: {sorted(set_fields)}. "
                f"Missing: {sorted(unset_fields)}."
            )
        return self

    # ------------------------------------------------------------------
    # Redis Streams serialisation
    # ------------------------------------------------------------------

    def to_redis_stream(self) -> dict[str, str]:
        """
        Serialise to a flat ``dict[str, str]`` suitable for ``XADD``.

        Rules
        -----
        * ``None`` fields are omitted (absent keys signal "not yet set").
        * ``dict`` fields (``raw_payload``) are JSON-encoded.
        * ``datetime`` fields are converted to ISO-8601 UTC strings.
        * Everything else is converted with ``str()``.
        """
        result: dict[str, str] = {}
        for field_name, value in self.model_dump(mode="python").items():
            if value is None:
                continue
            if field_name in _JSON_FIELDS:
                result[field_name] = json.dumps(value, separators=(",", ":"))
            elif isinstance(value, datetime):
                result[field_name] = value.isoformat()
            else:
                result[field_name] = str(value)
        return result

    @classmethod
    def from_redis_stream(cls, data: dict[str, str]) -> AEGISEvent:
        """
        Reconstruct an ``AEGISEvent`` from a flat Redis Streams message.

        ``data`` is the raw ``{field: value}`` mapping returned by
        ``XREAD`` / ``XRANGE`` (all values are byte-strings or str).
        """
        coerced: dict[str, Any] = {}
        for key, raw in data.items():
            value: Any = raw
            if key in _JSON_FIELDS:
                value = json.loads(raw)
            elif key in _DATETIME_FIELDS:
                value = datetime.fromisoformat(raw)
            elif key in _FLOAT_FIELDS:
                value = float(raw)
            elif key in _INT_FIELDS:
                value = int(raw)
            coerced[key] = value
        return cls.model_validate(coerced)

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    model_config = {
        "use_enum_values": True,
        "json_schema_extra": {
            "examples": [
                {
                    "event_id":      "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                    "source_type":   "cisa_kev",
                    "raw_payload":   {"cve": "CVE-2024-1234", "product": "ExampleApp"},
                    "ingested_at":   "2026-03-11T00:00:00Z",
                    "priority":      "P1",
                    "routing_target": "triage",
                    "ttl":           86400,
                    "relevance_score":      0.87,
                    "infrastructure_match": 0.75,
                    "threat_actor_history": 0.60,
                    "exploitability":       0.95,
                    "temporal_urgency":     0.80,
                    "triage_completed_at":  "2026-03-11T00:01:00Z",
                }
            ]
        },
    }


# ---------------------------------------------------------------------------
# LangGraph state (TypedDict – mutated across nodes)
# ---------------------------------------------------------------------------

class OrchestratorState(TypedDict, total=False):
    # Core event fields
    event_id: str
    source_type: str
    raw_payload: dict[str, Any]
    ingested_at: str
    priority: str
    routing_target: str
    ttl: int

    # Triage enrichment fields
    relevance_score: float
    infrastructure_match: float
    threat_actor_history: float
    exploitability: float
    temporal_urgency: float
    triage_completed_at: str

    # Internal orchestration fields
    redis_stream_id: str       # XREAD message ID for ACK
    validation_error: Optional[str]
    dispatch_key: str          # Target Redis stream key
    dispatched: bool
    dispatch_error: Optional[str]
