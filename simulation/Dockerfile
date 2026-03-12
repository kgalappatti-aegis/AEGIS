# Build context: repo root  (docker compose build context: .)
#
# Two services share this image, started with different entrypoints:
#   simulation-agent  → python simulation/agent.py
#   simulation-worker → celery -A simulation worker ...
#
# Directory layout inside the image:
#   /app/
#   ├── orchestrator/schema.py   ← shared Pydantic models
#   └── simulation/              ← service source

# ── Build stage ────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# gcc for hiredis; numpy ships pre-built wheels for Python 3.12 (no gcc needed)
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

COPY simulation/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Runtime stage ──────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /install /usr/local

RUN addgroup --system aegis \
    && adduser --system --ingroup aegis --no-create-home aegis

# Shared schema
COPY --chown=aegis:aegis orchestrator/schema.py orchestrator/schema.py

# Service source
COPY --chown=aegis:aegis simulation/ simulation/

USER aegis

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
