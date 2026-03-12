# Build context: repo root  (docker compose build context: .)
#
# Directory layout inside the image:
#   /app/
#   ├── orchestrator/schema.py   ← shared Pydantic models
#   └── detection/               ← service source

# ── Build stage ────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

COPY detection/requirements.txt .
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
COPY --chown=aegis:aegis detection/ detection/

USER aegis

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python", "detection/agent.py"]
