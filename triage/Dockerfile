# Build context: repo root  (docker compose build context: .)
#
# Directory layout inside the image mirrors the repo so that the sys.path
# manipulation in agent.py resolves correctly:
#
#   /app/
#   ├── orchestrator/
#   │   └── schema.py        ← shared Pydantic models
#   └── triage/
#       ├── agent.py
#       ├── config.py
#       └── scorer.py
#
# pathlib.Path(__file__).parent.parent / "orchestrator"
#   = /app/triage/../orchestrator  = /app/orchestrator  ✓

# ── Build stage ────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# gcc required for hiredis C extension
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

COPY triage/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Runtime stage ──────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /install /usr/local

# Non-root user
RUN addgroup --system aegis \
    && adduser --system --ingroup aegis --no-create-home aegis

# Shared schema (must live at /app/orchestrator/schema.py)
COPY --chown=aegis:aegis orchestrator/schema.py orchestrator/schema.py

# Service source
COPY --chown=aegis:aegis triage/ triage/

USER aegis

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python", "triage/agent.py"]
