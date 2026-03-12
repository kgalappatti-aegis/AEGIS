# AEGIS

**Autonomous Event-driven Guardian for Infrastructure Security**

AEGIS is a multi-agent security operations platform that ingests vulnerability feeds, scores and triages events, simulates adversary attack paths via Monte Carlo methods, generates Sigma detection rules, and produces actionable security advisories — all in real time.

```
NVD API ──► Ingestion ──► Orchestrator ──► Triage ──► Simulation ──► Detection ──► Advisory
                                                          │                           │
                                                     Neo4j Graph                  PostgreSQL
                                                     (ATT&CK)                    + Pub/Sub
                                                                                      │
                                                                               Bridge (WS)
                                                                                      │
                                                                               React Dashboard
```

## Architecture

AEGIS runs as a set of containerized microservices communicating through Redis Streams. Each agent is a LangGraph state machine that consumes from an input stream, processes events through a directed graph of nodes, and publishes results to the next stream in the pipeline.

| Service | Role | Key Tech |
|---------|------|----------|
| **Ingestion** | Polls NVD API v2 for new CVEs, maps to `AEGISEvent` schema | httpx, async rate limiter |
| **Orchestrator** | Validates, classifies (priority + routing), dispatches to queues | LangGraph, Pydantic |
| **Triage** | Scores relevance (infrastructure match, actor history, exploitability, temporal urgency) | Neo4j, weighted composite |
| **Simulation** | Monte Carlo adversary emulation across ATT&CK kill chain | Celery, NumPy, Claude API |
| **Detection** | Generates Sigma v2 detection rules grounded in MITRE context | Claude API |
| **Advisory** | Enriches findings into executive advisories, persists to PostgreSQL | Claude API, asyncpg |
| **Bridge** | WebSocket gateway + REST API for the dashboard | FastAPI, aioredis |
| **React UI** | Real-time dashboard with event table, advisory cards, ATT&CK heatmap, kill chain SVG | React 18, Vite |

### Infrastructure

| Component | Image | Purpose |
|-----------|-------|---------|
| Redis 7 | `redis:7-alpine` | Streams, pub/sub, shared state hashes |
| Neo4j 5 | `neo4j:5.19-community` | MITRE ATT&CK knowledge graph |
| PostgreSQL 16 | `postgres:16-alpine` | Advisory persistence |

## Quick Start

### Prerequisites

- Docker & Docker Compose v2
- An [Anthropic API key](https://console.anthropic.com/)
- (Optional) An [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) for higher rate limits

### 1. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:

```env
ANTHROPIC_API_KEY=sk-ant-...
NEO4J_PASSWORD=your-neo4j-password
NVD_API_KEY=              # optional, increases NVD rate limit from 5 to 50 req/30s
```

### 2. Start Infrastructure

```bash
docker compose -f aegis.yml up -d redis neo4j postgres
```

Wait for health checks to pass:

```bash
docker compose -f aegis.yml ps
```

### 3. Initialize the Knowledge Graph

Load threat actors, TTPs, and relationships into Neo4j:

```bash
docker compose -f aegis.yml run --rm neo4j-init
```

(Optional) Load full MITRE ATT&CK STIX bundle and pre-populate Redis detection stubs:

```bash
docker compose -f aegis.yml run --rm mitre-loader
```

Verify Redis stubs were written:

```bash
docker compose -f aegis.yml run --rm mitre-loader python mitre_loader.py --verify
```

### 4. Start All Services

```bash
docker compose -f aegis.yml up -d
```

### 5. Open the Dashboard

| Interface | URL |
|-----------|-----|
| React Dashboard | http://localhost:3000 |
| Neo4j Browser | http://localhost:7474 |

## Services in Detail

### Ingestion Agent

Polls the NVD CVE API v2 on a configurable interval (default: 5 minutes). Each CVE is mapped to an `AEGISEvent` with CVSS-derived priority:

| CVSS Score | Priority |
|------------|----------|
| >= 9.0 | P0 (Critical) |
| >= 7.0 | P1 (High) |
| >= 4.0 | P2 (Medium) |
| < 4.0 | P3 (Low) |

The poller implements sliding-window rate limiting with exponential backoff and jitter, and persists a cursor in Redis to resume cleanly after restarts.

### Orchestrator

A LangGraph state machine that validates incoming events against the `AEGISEvent` Pydantic schema, assigns priority and routing target from static matrices, and dispatches to the appropriate downstream queue. Invalid events are routed to a dead-letter queue (`aegis:events:dlq`).

**Routing matrix:**

| Source Type | Routing Target |
|------------|----------------|
| `cisa_kev` | triage |
| `edr` | detection |
| `siem` | triage |
| `threatfox` | triage |
| `nvd` | advisory |
| `stix` | simulation |

### Triage Agent

Computes a composite relevance score from four sub-scores:

```
relevance = infrastructure_match * 0.40
           + threat_actor_history * 0.25
           + exploitability       * 0.20
           + temporal_urgency     * 0.15
```

- **Infrastructure match**: 1.0 if CVSS >= 7.0, else 0.5
- **Threat actor history**: Neo4j query checking if known actors use TTPs related to the CVE (0.3 / 0.6 / 0.9)
- **Exploitability**: CVSS baseScore / 10.0
- **Temporal urgency**: 1.0 if published within 7 days, else 0.3

Events scoring above `TRIAGE_THRESHOLD` (default: 0.4) are routed to simulation; others go directly to advisory.

### Simulation Agent

A two-process design:

- **simulation-agent**: LangGraph pipeline that selects attack strategies via Claude, dispatches Monte Carlo tasks to Celery, interprets results, queries Neo4j for structured attack paths, and computes SVG layout coordinates.
- **simulation-worker**: Celery worker pool executing NumPy-vectorized Monte Carlo sampling across ATT&CK kill chain paths.

**LangGraph topology:**

```
load_event → strategy_selector → run_simulation → interpret_results
           → build_finding_paths → forward_to_detection
```

**Attack strategies:**

| Strategy | Description |
|----------|-------------|
| `shortest_path` | Minimum-hop path through the ATT&CK graph |
| `evasion_first` | Prioritizes defense-evasion techniques |
| `vuln_amplified` | Weights paths through known vulnerabilities |
| `lateral_movement` | Emphasizes lateral movement TTPs |
| `full_landscape` | Broad coverage of all reachable paths |

The `build_finding_paths` node queries Neo4j with strategy-specific Cypher, computes detection coverage from Redis hashes, assigns SVG coordinates via the layout engine, and writes structured findings to `aegis:sim:findings:{event_id}` (24h TTL).

### Detection Agent

Generates Sigma v2 detection rules for each TTP in the highest-risk attack path. Uses Claude with a grounding prompt that includes the TTP's MITRE description and known data sources from Redis. Rules scoring >= 0.7 confidence automatically upgrade the TTP's Redis coverage status to `"detected"`.

### Advisory Agent

Produces executive-grade security advisories via Claude, including:
- Executive and technical summaries
- Immediate and detection actions
- TLP classification and confidence scoring
- MITRE technique mapping

Advisories are persisted to PostgreSQL (upserted by `event_id`) and broadcast via Redis pub/sub to all connected WebSocket clients.

### Bridge

FastAPI service providing:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/ws` | WebSocket | Live event + advisory stream |
| `/api/attack-matrix` | GET | ATT&CK heatmap data (hit counts, priority, actors) |
| `/api/simulation/{event_id}` | GET | Simulation finding with attack paths |
| `/healthz` | GET | Liveness probe |

The bridge runs two background loops:
1. **Detection tail**: XREAD on `aegis:queue:detection`, emits `type: "event"` messages
2. **Pub/sub subscriber**: Listens on `aegis:broadcast`, emits `type: "advisory"` messages

### React Dashboard

Three-tab SPA built with React 18 + Vite:

- **EVENTS**: Real-time event table with priority filtering. Click a row to see triage scores and (for simulated events) an interactive SVG kill chain diagram.
- **ADVISORIES**: Advisory cards with expandable Sigma rules, coverage gaps, and kill chain visualizations.
- **ATT&CK**: 14-column MITRE ATT&CK heatmap grid colored by simulation hit count, with actor filtering, list/heatmap views, and click-to-detail panel.

## Redis Key Reference

| Key | Type | Purpose |
|-----|------|---------|
| `aegis:events:inbound` | Stream | Ingestion output |
| `aegis:events:dlq` | Stream | Dead-letter queue |
| `aegis:queue:triage` | Stream | Triage input |
| `aegis:queue:simulation` | Stream | Simulation input |
| `aegis:queue:detection` | Stream | Detection input |
| `aegis:queue:advisory` | Stream | Advisory input |
| `aegis:broadcast` | Pub/Sub | Advisory broadcast channel |
| `aegis:cursor:nvd` | String | NVD poller cursor |
| `aegis:detection:coverage` | Hash | TTP detection coverage (none/partial/detected) |
| `aegis:detection:sigma` | Hash | TTP sigma rule hints |
| `aegis:detection:data_sources` | Hash | TTP data sources |
| `aegis:ttp:hits` | Hash | TTP simulation hit counts |
| `aegis:ttp:priority` | Hash | TTP max priority seen |
| `aegis:ttp:actors` | Hash | TTP actor attributions |
| `aegis:sim:findings:{event_id}` | String (JSON) | Simulation finding (24h TTL) |

## Neo4j Graph Schema

**Node labels:**
- `TTP` — MITRE ATT&CK techniques (id, name, tactic, platform, detection, sigma_hint)
- `ThreatActor` — Known threat actors (name, aliases, description)
- `Mitigation` — MITRE mitigations (id, name, description)

**Relationships:**
- `(:TTP)-[:PRECEDES]->(:TTP)` — Kill chain sequencing
- `(:ThreatActor)-[:USES]->(:TTP)` — Actor technique attribution
- `(:Mitigation)-[:MITIGATES]->(:TTP)` — Mitigation mapping

**Seeded threat actors:** Volt Typhoon, APT29, Lazarus Group, LockBit, BlackCat

## Configuration

All services are configured via environment variables (with Pydantic Settings). Key variables:

| Variable | Default | Used By |
|----------|---------|---------|
| `REDIS_URL` | `redis://localhost:6379` | All services |
| `ANTHROPIC_API_KEY` | (required) | Simulation, Detection, Advisory |
| `NEO4J_URL` | `bolt://neo4j:7687` | Triage, Simulation |
| `NEO4J_USER` | `neo4j` | Triage, Simulation |
| `NEO4J_PASSWORD` | (required) | Triage, Simulation, Neo4j init |
| `DATABASE_URL` | `postgresql://aegis:aegis@localhost:5432/aegis` | Advisory |
| `NVD_API_KEY` | (optional) | Ingestion |
| `POLL_INTERVAL_SECONDS` | `300` | Ingestion |
| `TRIAGE_THRESHOLD` | `0.4` | Triage |
| `SIM_THRESHOLD` | `0.55` | Simulation |
| `BATCH_SIZE` | `5`–`10` | All agents |
| `LOG_LEVEL` | `INFO` | All services |

## Project Structure

```
AEGIS/
├── aegis.yml                # Docker Compose (full stack)
├── orchestrator.yml         # Docker Compose (minimal / dev)
├── .env                     # Environment variables (not committed)
├── .dockerignore
├── .gitignore
│
├── ingestion/               # NVD CVE poller
│   ├── agent.py
│   ├── config.py
│   ├── nvd_client.py
│   ├── requirements.txt
│   └── Dockerfile
│
├── orchestrator/            # Event validation + routing
│   ├── main.py
│   ├── config.py
│   ├── graph.py
│   ├── nodes.py
│   ├── schema.py            # AEGISEvent Pydantic model
│   ├── requirements.txt
│   └── Dockerfile
│
├── triage/                  # Relevance scoring
│   ├── agent.py
│   ├── config.py
│   ├── scorer.py
│   ├── requirements.txt
│   └── Dockerfile
│
├── simulation/              # Monte Carlo attack simulation
│   ├── agent.py
│   ├── config.py
│   ├── graph.py
│   ├── nodes.py
│   ├── state.py
│   ├── simulation.py        # Celery tasks
│   ├── neo4j_queries.py     # Cypher queries
│   ├── layout.py            # SVG coordinate engine
│   ├── requirements.txt
│   └── Dockerfile
│
├── detection/               # Sigma rule generation
│   ├── agent.py
│   ├── config.py
│   ├── graph.py
│   ├── nodes.py
│   ├── state.py
│   ├── requirements.txt
│   └── Dockerfile
│
├── advisory/                # Advisory generation + persistence
│   ├── agent.py
│   ├── config.py
│   ├── graph.py
│   ├── nodes.py
│   ├── state.py
│   ├── requirements.txt
│   └── Dockerfile
│
├── neo4j/                   # Graph initialization
│   ├── neo4j_init.py        # Seed actors, TTPs, relationships
│   ├── mitre_loader.py      # Full STIX bundle loader + Redis stubs
│   ├── requirements.txt
│   └── Dockerfile
│
├── bridge/                  # WebSocket + REST API gateway
│   ├── main.py
│   ├── requirements.txt
│   └── Dockerfile
│
├── aegis-ui/                # React dashboard
│   ├── src/
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   ├── index.css
│   │   └── components/
│   │       ├── AttackMatrix.jsx
│   │       └── KillChainFlow.jsx
│   ├── index.html
│   ├── vite.config.js
│   ├── nginx.conf
│   ├── package.json
│   └── Dockerfile
│
└── frontend/                # Legacy SSE dashboard
    ├── main.py
    ├── static/
    │   ├── index.html
    │   ├── style.css
    │   └── app.js
    ├── requirements.txt
    └── Dockerfile
```

## Scaling

The simulation worker pool can be horizontally scaled:

```bash
docker compose -f aegis.yml up -d --scale simulation-worker=4
```

All agents use Redis consumer groups (`XREADGROUP` + `XAUTOCLAIM`), so multiple instances of any agent can run concurrently for load distribution and fault tolerance.

## License

Proprietary. All rights reserved.
