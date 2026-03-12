# One-shot init container — runs neo4j_init.py and exits.
# Build context: ./neo4j

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY neo4j_init.py .
COPY mitre_loader.py .

RUN addgroup --system aegis \
    && adduser --system --ingroup aegis --no-create-home aegis
USER aegis

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python", "neo4j_init.py"]
