# Build context: ./bridge
#
# Single-purpose WebSocket bridge:
#   Subscribes to aegis:broadcast Redis pub/sub channel
#   Fans out advisory JSON to all connected WebSocket clients

FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /install /usr/local

RUN addgroup --system aegis \
    && adduser --system --ingroup aegis --no-create-home aegis

COPY --chown=aegis:aegis main.py .

USER aegis

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8765"]
