# Build context: repo root  (docker compose build context: .)
#
# Directory layout inside the image:
#   /app/
#   ├── orchestrator/schema.py   ← shared Pydantic models
#   └── advisory/                ← service source

# ── Build stage ────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY advisory/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Runtime stage ──────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# asyncpg needs libpq at runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

RUN addgroup --system aegis \
    && adduser --system --ingroup aegis --no-create-home aegis

# Shared schema
COPY --chown=aegis:aegis orchestrator/schema.py orchestrator/schema.py

# Service source
COPY --chown=aegis:aegis advisory/ advisory/

USER aegis

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python", "advisory/agent.py"]
