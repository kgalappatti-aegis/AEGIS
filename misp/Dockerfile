# Build context: ./misp (standalone — no shared schema needed)
#
# MISP agent publishes raw dicts to aegis:events:inbound via XADD,
# so it does not import orchestrator/schema.py.

# ── Build stage ────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Runtime stage ──────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /install /usr/local

# Non-root user
RUN addgroup --system aegis \
    && adduser --system --ingroup aegis --no-create-home aegis

COPY --chown=aegis:aegis . .

USER aegis

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python", "main.py"]
