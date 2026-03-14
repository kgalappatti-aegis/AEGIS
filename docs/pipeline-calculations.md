# AEGIS Pipeline Calculations Reference

This document describes the scoring, prioritisation, and risk computation models used across the AEGIS pipeline.

---

## 1. Priority Assignment

Priority is assigned in two stages: initial classification by the orchestrator, and optional adjustment by the triage agent.

### 1.1 Orchestrator — Initial Priority Matrix

The orchestrator assigns priority based on the event's source type:

| Source Type | Priority | Rationale |
|---|---|---|
| `cisa_kev` | **P0** (Critical) | CISA Known Exploited Vulnerabilities — active exploitation confirmed |
| `edr` | **P0** (Critical) | Endpoint Detection & Response — live endpoint alert |
| `siem` | **P1** (High) | SIEM correlation rule hit |
| `threatfox` | **P1** (High) | Active IOC / malware intel feed |
| `misp` | **P1** (High) | MISP threat intel (inherits MISP threat_level) |
| `nvd` | **P2** (Medium) | NVD vulnerability disclosure |
| `stix` | **P3** (Low) | Structured threat intel bundle (STIX/TAXII) |

For NVD events specifically, the ingestion agent also derives priority from CVSS:

| CVSS Score | Priority |
|---|---|
| >= 9.0 | P0 (Critical) |
| >= 7.0 | P1 (High) |
| >= 4.0 | P2 (Medium) |
| < 4.0 | P3 (Low) |

The orchestrator's source-type matrix takes precedence at routing time.

### 1.2 Orchestrator — Routing Matrix

Each source type is routed to a specific initial queue:

| Source Type | Initial Route | Full Path to Advisory |
|---|---|---|
| `cisa_kev` | triage | triage -> simulation -> detection -> advisory |
| `edr` | detection | detection -> advisory |
| `siem` | triage | triage -> simulation -> detection -> advisory |
| `threatfox` | triage | triage -> simulation -> detection -> advisory |
| `misp` | triage | triage -> simulation -> detection -> advisory |
| `nvd` | advisory | advisory (direct) |
| `stix` | simulation | simulation -> detection -> advisory |

### 1.3 Triage — Priority Adjustment

The triage agent may modify the priority based on two rules:

**Low relevance downgrade:** If `relevance_score < TRIAGE_THRESHOLD` (default 0.4), the event is downgraded to **P3** regardless of its original priority and routed directly to advisory, bypassing simulation.

**KEV priority bump:** If the CVE appears in the CISA Known Exploited Vulnerabilities catalog, the priority is bumped up one tier:

| Before | After KEV Bump |
|---|---|
| P3 | P2 |
| P2 | P1 |
| P1 | P0 |
| P0 | P0 (no change) |

After triage, the priority is passed through unchanged by simulation, detection, and advisory.

---

## 2. Triage Relevance Score

The triage agent computes a composite relevance score from four weighted sub-scores:

```
relevance = infrastructure_match * 0.40
           + threat_actor_history * 0.25
           + exploitability       * 0.20
           + temporal_urgency     * 0.15
```

### Sub-score Definitions

| Sub-score | Range | Computation |
|---|---|---|
| **Infrastructure match** | 0.0 – 1.0 | 1.0 if CVSS >= 7.0, else 0.5 |
| **Threat actor history** | 0.0 – 0.9 | Neo4j query: checks if known actors use TTPs related to the CVE. Returns 0.3 (no match), 0.6 (1 actor), or 0.9 (2+ actors) |
| **Exploitability** | 0.0 – 1.0 | `CVSS baseScore / 10.0` |
| **Temporal urgency** | 0.0 – 1.0 | 1.0 if CVE published within 7 days, else 0.3 |

### Routing Decision

| Condition | Destination | Priority |
|---|---|---|
| `relevance_score >= TRIAGE_THRESHOLD` | `aegis:queue:simulation` | Unchanged (or KEV-bumped) |
| `relevance_score < TRIAGE_THRESHOLD` | `aegis:queue:advisory` | Downgraded to P3 |

Default `TRIAGE_THRESHOLD`: **0.4** (configurable via environment variable).

---

## 3. Monte Carlo Simulation

The simulation agent estimates breach probability through Monte Carlo sampling over attack paths derived from the Neo4j ATT&CK knowledge graph.

### 3.1 Strategy Selection

Strategies are selected deterministically based on triage enrichment scores:

| Strategy | Trigger Condition | Description |
|---|---|---|
| `full_landscape` | Always included | Broad coverage of all reachable paths |
| `shortest_path` | CVSS >= 9.0 or exploitability >= 0.8 | Minimum-hop BFS path through the graph |
| `vuln_amplified` | CVSS >= 9.0 or exploitability >= 0.8 | High-probability paths through known vulnerabilities |
| `lateral_movement` | infrastructure_match >= 0.8 | Emphasises lateral movement TTPs |
| `evasion_first` | temporal_urgency >= 0.8 | Prioritises defense-evasion techniques |

### 3.2 Iteration Count

The number of Monte Carlo iterations scales with event criticality:

| Condition | Iterations |
|---|---|
| CVSS >= 9.0 or relevance >= 0.8 | 10,000 |
| CVSS >= 7.0 or relevance >= 0.6 | 5,000 |
| Otherwise | 3,000 |

### 3.3 Per-Path Monte Carlo (`_monte_carlo_path`)

For each attack path (a sequence of technique steps with transition probabilities from Neo4j):

**Step 1 — Sample transition probabilities from Beta distributions:**

Each step's known transition probability `p` is treated as the mode of a Beta distribution:

```
alpha = BETA_ALPHA_PRIOR + p * BETA_EFFECTIVE_N
beta  = BETA_BETA_PRIOR  + (1 - p) * BETA_EFFECTIVE_N
```

| Constant | Value |
|---|---|
| `BETA_ALPHA_PRIOR` | 2.0 |
| `BETA_BETA_PRIOR` | 2.0 |
| `BETA_EFFECTIVE_N` | 8.0 |

This encodes uncertainty around the known probability — with 8 effective observations, high-confidence probabilities stay tight while uncertain ones spread wide.

**Step 2 — Bernoulli step success:**

For each iteration, each step succeeds if `random() < sampled_probability`.

**Step 3 — Detection blocking:**

Each step has a detection coverage score (queried from Neo4j). If a step succeeds but is detected, it is blocked:

```
step_detected  = random() < (detection_coverage * DETECTION_PENALTY)
step_blocked   = step_detected AND step_success
step_progressed = step_success AND NOT step_blocked
```

`DETECTION_PENALTY` = **0.15** (probability of blocking per detected TTP step).

**Step 4 — Path outcome:**

A path succeeds only if **every step** progresses (succeeds and is not blocked).

```
success_rate = count(all steps progressed) / n_iterations
```

### 3.4 Aggregation — p_breach

Multiple attack paths may be discovered per strategy. The overall breach probability is the probability that **at least one** path succeeds (union of independent events):

```
p_breach = 1 - product(1 - success_rate_i)  for each path i
```

After simulation across all strategies, Claude interprets the results and returns a final `p_breach` (clamped to 0.0–1.0). The fallback (if Claude fails) is `max(p_breach)` across all strategies.

### 3.5 Delta p_breach — Marginal CVE Risk

`delta_p_breach` quantifies the marginal risk increase introduced by a specific CVE. It compares two counterfactual scenarios using the same Beta-sampling Monte Carlo method:

| Scenario | Transition Probability | Interpretation |
|---|---|---|
| **Pre-CVE baseline** | 0.50 (all CVE-relevant steps) | Hard to exploit without the vulnerability |
| **Post-CVE** | 0.95 (all CVE-relevant steps) | Trivial to exploit with the vulnerability |

CVE-relevant steps are those in the `initial-access`, `execution`, or `privilege-escalation` tactics.

```
delta_p_breach = p_breach_post_cve - p_breach_pre_cve
```

The delta can be **negative** if improved detection coverage offsets the increased exploitability.

---

## 4. Detection Agent

The detection agent generates Sigma v2 detection rules for each TTP in the highest-risk attack path. TTPs are sourced from three locations (in order):

1. `highest_risk_path` — technique IDs from the simulation finding
2. Sigma rule MITRE tags — extracted via regex from generated rules (`attack.tXXXX`)
3. `recommended_detections` — technique IDs mentioned in the simulation's detection recommendations

### Skip Logic

If `DETECTION_SKIP_LOW=true` (default: `false`), events with `severity=low` are dropped and not forwarded to the advisory queue.

---

## 5. Advisory Risk Score

The advisory agent computes a `risk_score` (integer 0–100) via two paths:

### 5.1 Claude-Generated (Primary)

The advisory prompt asks Claude to return a `risk_score` as part of a structured JSON response. Claude has access to the full event context: severity, p_breach, delta_p_breach, CVSS data, exploit availability, triage scores, detection gaps, highest risk path, blind spots, and Sigma rules. The returned value is clamped to 0–100.

### 5.2 Fallback

If Claude's response cannot be parsed, the fallback computation is:

```
risk_score = min(100, int(p_breach * 100))
```

This directly converts the simulation's breach probability to a 0–100 scale.

| p_breach | Fallback risk_score |
|---|---|
| 0.15 | 15 |
| 0.43 | 43 |
| 0.87 | 87 |
| 1.00 | 100 |

---

## 6. Pipeline Stage Tracking

Each event progresses through stages, tracked in `aegis:event:stages` (Redis hash) and broadcast via `aegis:broadcast` pub/sub:

| Stage | Set By | Meaning |
|---|---|---|
| `ingested` | (implicit) | Event arrived in inbound stream |
| `routed` | Orchestrator | Dispatched to downstream queue |
| `triaged` | Triage Agent | Relevance scoring complete, forwarded to simulation or advisory |
| `simulated` | Simulation Agent | Monte Carlo simulation complete, forwarded to detection |
| `detected` | Detection Agent | Sigma rules generated, forwarded to advisory |
| `advisory` | Advisory Agent | Advisory published and persisted |

### Timestamp Fields

Each agent sets a timestamp when it completes processing:

| Field | Set By | Format |
|---|---|---|
| `ingested_at` | Orchestrator | ISO-8601 UTC |
| `triage_completed_at` | Triage Agent | ISO-8601 UTC |
| `simulated_at` | Simulation Agent | ISO-8601 UTC |
| `detected_at` | Detection Agent | ISO-8601 UTC |
| `created_at` | Advisory Agent | ISO-8601 UTC |

Not all events pass through every stage. NVD events (`nvd -> advisory`) skip triage, simulation, and detection. EDR events (`edr -> detection`) skip triage and simulation.

---

## 7. Anthropic API Cost Estimation

Each event that traverses the full pipeline (triage → simulation → detection → advisory) makes multiple Claude API calls. This section estimates per-event and daily costs.

### 7.1 Model Usage by Agent

| Agent | Call | Model | Calls per Event |
|---|---|---|---|
| **Triage** | Relevance scoring | Neo4j queries only (no LLM) | 0 |
| **Simulation** | Result interpretation | `claude-sonnet-4-6` | 1 |
| **Detection** | Primary rule generation | `claude-sonnet-4-6` | 1 |
| **Detection** | Per-TTP rule generation | `claude-haiku-4-5` | 3–8 (varies by path length) |
| **Advisory** | Risk assessment & write-up | `claude-sonnet-4-6` | 1 |

### 7.2 Token Estimates per Call

| Call | Input Tokens | Output Tokens |
|---|---|---|
| Simulation interpretation | ~2,000 | ~500 |
| Detection (primary) | ~2,500 | ~1,500 |
| Detection (per-TTP) | ~1,500 | ~1,000 |
| Advisory generation | ~3,000 | ~2,000 |

### 7.3 Model Pricing (as of 2025)

| Model | Input (per 1M tokens) | Output (per 1M tokens) |
|---|---|---|
| `claude-sonnet-4-6` | $3.00 | $15.00 |
| `claude-haiku-4-5` | $0.80 | $4.00 |

### 7.4 Per-Event Cost Breakdown (Full Pipeline)

Assuming 5 TTPs per event (typical for a high-severity path):

| Call | Model | Input Cost | Output Cost | Subtotal |
|---|---|---|---|---|
| Simulation interpretation (×1) | Sonnet | $0.006 | $0.0075 | $0.0135 |
| Detection primary (×1) | Sonnet | $0.0075 | $0.0225 | $0.030 |
| Detection per-TTP (×5) | Haiku | $0.006 | $0.020 | $0.026 |
| Advisory generation (×1) | Sonnet | $0.009 | $0.030 | $0.039 |
| **Total per event** | | | | **~$0.027–$0.040** |

### 7.5 Cost by Agent Share

| Agent | Share of Cost |
|---|---|
| Detection (primary + per-TTP) | ~52% |
| Advisory | ~36% |
| Simulation | ~12% |

### 7.6 Daily Cost Projections

| Scenario | Events/Day | Est. Daily Cost |
|---|---|---|
| Light (dev/test) | 20 | ~$0.54–$0.80 |
| Moderate | 100 | ~$2.70–$4.00 |
| Heavy | 500 | ~$13.50–$20.00 |
| Stress test (harness) | 1,000 | ~$27–$40 |

### 7.7 Cost Optimization Notes

- Switching per-TTP detection from Sonnet to Haiku reduced per-event cost by ~30% (from ~$0.046–$0.077 to ~$0.027–$0.040).
- NVD events (`nvd → advisory`) skip triage, simulation, and detection — they incur only the advisory call (~$0.039).
- EDR events (`edr → detection`) skip triage and simulation — they incur detection + advisory (~$0.027).
- The `DETECTION_SKIP_LOW` flag (default `false`) can further reduce costs by skipping detection for low-severity events.

---

## 8. Worked Example

**Event:** CVE-2025-22457 (Ivanti Connect Secure RCE), source: `cisa_kev`, CVSS 9.8

| Stage | Computation | Result |
|---|---|---|
| **Orchestrator** | Source=`cisa_kev` -> Priority=P0, Route=triage | P0, triage queue |
| **Triage** | infra=1.0 (CVSS 9.8 >= 7.0), actors=0.9 (APT29+Volt Typhoon use related TTPs), exploit=0.98 (9.8/10), temporal=1.0 (recent) | relevance = 1.0*0.4 + 0.9*0.25 + 0.98*0.2 + 1.0*0.15 = **0.971** |
| | 0.971 >= 0.4 threshold -> simulation | Priority stays P0 (KEV bump: already P0) |
| **Simulation** | 5 strategies selected (CVSS >= 9.0), 10,000 iterations each | p_breach=0.431, delta=+0.18 |
| | Per-path: 15 paths found, best path success_rate=0.34 | severity=high |
| **Detection** | 6 Sigma rules generated across T1190, T1059, T1071 | 4 ART validation tests found |
| **Advisory** | Claude risk assessment with full context | risk_score=85, confidence=high, TLP=AMBER |
