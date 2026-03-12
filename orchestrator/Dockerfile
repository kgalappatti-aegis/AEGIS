# ── Build stage ────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# gcc is required to compile the hiredis C extension
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Runtime stage ──────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# Copy only the pre-built site-packages from the build stage
COPY --from=builder /install /usr/local

# Non-root user
RUN addgroup --system aegis \
    && adduser --system --ingroup aegis --no-create-home aegis

# Source files (build context: ./orchestrator)
COPY --chown=aegis:aegis . .

USER aegis

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python", "main.py"]
