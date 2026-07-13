# GUARDIAN Architecture

SOC/SIEM system for LTI. Runs as a self-contained digital twin: a synthetic LTI API generates realistic +
attack-laced traffic inside the same Docker network, so `docker compose up` demos the full
pipeline with no external infrastructure.

## Pipeline

```
mock-lti (FastAPI)                    synthetic traffic + attack injection
     │  async, non-blocking, out-of-band POST /ingest
     ▼
capture-agent (FastAPI + aiokafka)    ingestion boundary (eBPF stand-in, see Deviations)
     │  produce
     ▼
Redpanda                              topic guardian.telemetry.raw
     │  consume (group guardian-vector)
     ▼
Vector                                parse + normalize + enrich (VRL)
     │  bulk index                        │  produce (fan-out)
     ▼                                    ▼
OpenSearch                            guardian.telemetry.normalized
     │                                    │  consume (group guardian-argus)
     ▼                                    ▼
OpenSearch Dashboards             argus (FastAPI + aiokafka)   1-min buckets, baselines, anomaly scores
                                          │ produce                    │ produce (anomalies only)
                                          ▼                            ▼
                                  guardian.scores              guardian.alerts
                                          │ Vector → OpenSearch        │ ├─ Vector → OpenSearch (guardian-alerts-*)
                                          ▼                            │ └─ alerting (5-min dedup → Slack/Discord)
                                  guardian-scores-*                    ▼
```

Vector is the single OpenSearch write path: ARGUS never talks to OpenSearch directly —
it is pure Kafka-in/Kafka-out, and Vector carries score/alert documents into their
indices. OpenSearch Alerting monitors (e.g. `guardian-error-rate-spike`) post into the
alerting service's `/notify` endpoint via a notification channel, so SIEM-native alerts
share the same dedup window as ARGUS alerts.

Extra-credit layers still to come (later weeks): SENTINEL / CASSANDRA scorer
microservices (they will consume `guardian.telemetry.normalized` exactly like ARGUS),
Guardian Pulse HUD. See each service's README.

## Port / hostname allocations (contract)

| Service | Container host | Container port | Host port |
|---|---|---|---|
| mock-lti | `mock-lti` | 8000 | 8000 |
| capture-agent | `capture-agent` | 8001 | 8001 |
| Redpanda Kafka API (internal) | `redpanda` | 9092 | — |
| Redpanda Kafka API (host/external) | — | 19092 | 19092 |
| Redpanda Admin API | `redpanda` | 9644 | 9644 |
| Redpanda Console | `redpanda-console` | 8080 | 8080 |
| OpenSearch | `opensearch` | 9200 (https) | 9200 |
| OpenSearch Dashboards | `opensearch-dashboards` | 5601 | 5601 |
| ARGUS | `argus` | 8002 | 8002 |
| alerting | `alerting` | 8003 | 8003 |
| SENTINEL | `sentinel` | 8004 | 8004 |
| CASSANDRA | `cassandra` | 8005 | 8005 |
| fusion | `fusion` | 8006 | 8006 |

Queue topics (all 3 partitions, replication 1, ~6h retention — OpenSearch is the
durable store). Network: single bridge `guardian-net`.

| Topic | Producer | Consumers (group) |
|---|---|---|
| `guardian.telemetry.raw` | capture-agent | Vector (`guardian-vector`) |
| `guardian.telemetry.normalized` | Vector | ARGUS (`guardian-argus`), SENTINEL (`guardian-sentinel`), CASSANDRA (`guardian-cassandra`) |
| `guardian.scores` | ARGUS, SENTINEL, CASSANDRA, fusion | Vector (`guardian-vector-scores`) → `guardian-scores-*`, fusion (`guardian-fusion`) |
| `guardian.alerts` | ARGUS, SENTINEL, CASSANDRA, fusion | alerting (`guardian-alerting`), Vector (`guardian-vector-alerts`) → `guardian-alerts-*` |

All Week-3 scorers (SENTINEL, CASSANDRA) consume `guardian.telemetry.normalized` under
their own consumer groups — the same normalized shape ARGUS reads. fusion is the
exception: it consumes `guardian.scores` (group `guardian-fusion`), ignoring documents
with `score.model == "guardian"` so its own output doesn't feed back into itself.

Topic bootstrap: capture-agent creates `guardian.telemetry.raw`; ARGUS creates
`guardian.telemetry.normalized`, `guardian.scores` and `guardian.alerts`; the alerting
service also ensures `guardian.alerts` (idempotent creates, first one up wins). Week-3
services attach as additional producers/consumers on the existing topics — no new topics.

## Event schema

The telemetry envelope every service speaks. Code copies:
`services/mock-lti/app/schemas.py` (source of truth) and `services/capture/app/schemas.py`.

**Invariant: the envelope is always schema-valid JSON — even for attack traffic.**
Malformation is expressed in field *values* (negative amount, junk currency, missing
payer) plus `raw_payload_valid: false`, never by breaking the JSON. This keeps the
pipeline flowing while still surfacing bad data in the dashboard.

| Field | Type | Notes |
|---|---|---|
| `event_id` | str | uuid4 |
| `timestamp` | ISO8601 datetime | UTC |
| `source` | str | `"mock-lti"` |
| `event_type` | str | `transaction` \| `burst_spike` \| `malformed_payload` |
| `payer_id`, `payee_id` | str \| null | synthetic entity ids |
| `channel` | str \| null | `ecommerce` \| `wallet` \| `bank` |
| `amount` | float \| null | may be intentionally negative in attack traffic |
| `currency` | str \| null | ISO 4217 when well-formed |
| `status` | str | `approved` \| `declined` \| `error` \| `malformed` |
| `latency_ms` | float \| null | simulated routing latency |
| `is_attack` | bool | ground-truth label for later ML work |
| `attack_pattern` | str \| null | `burst` \| `malformed` \| `slow_exfil` \| `log_attack` |
| `client_ip` | str \| null | synthetic, always a valid IP |
| `raw_payload_valid` | bool | `false` marks intentionally malformed payloads |
| `log_message` | str \| null | rendered API-gateway log line (see [Attack modes](#attack-modes)); Vector maps it to `log.message` |

Example:

```json
{
  "event_id": "8f0c9b1e-3a7d-4f7b-9a0e-2f4d6c8b1a5e",
  "timestamp": "2026-07-12T03:15:42.123456Z",
  "source": "mock-lti",
  "event_type": "transaction",
  "payer_id": "merchant-0042",
  "payee_id": "bank-007",
  "channel": "ecommerce",
  "amount": 125000.0,
  "currency": "IDR",
  "status": "approved",
  "latency_ms": 12.7,
  "is_attack": false,
  "attack_pattern": null,
  "client_ip": "10.20.30.42",
  "raw_payload_valid": true,
  "log_message": "10.20.30.42 - merchant-0042 [12/Jul/2026:03:15:42 +0000] \"POST /api/v1/transactions/route HTTP/1.1\" 200 512 12.7ms \"routed ecommerce payment merchant-0042->bank-007\""
}
```

### Attack modes

The generator (`services/mock-lti/app/generator.py`) injects attacks per `ATTACK_MODE`
(runtime-switchable via `POST /admin/generator/config`). The envelope stays schema-valid
in every mode; ground truth is carried on `is_attack` / `attack_pattern`.

| Mode | Behaviour | Tunables | Exercises |
|---|---|---|---|
| `burst` | 10–20× rate spike 5–10s every 60–120s from ~4 attacker IPs (`event_type=burst_spike`) | — | ARGUS rate detector (per-IP cohort) |
| `malformed` | ~8% of events carry bad *values* (negative amount / junk currency / missing payer) with `raw_payload_valid=false` | — | ARGUS payload/error metrics |
| `slow_exfil` | one designated payer receives a steady trickle of *extra* transactions with modestly elevated amounts, layered on top of baseline; `attack_pattern=slow_exfil` | `EXFIL_PAYER_ID` (default `wallet-user-0001`), `EXFIL_EVENTS_PER_MINUTE` (default 2), `EXFIL_AMOUNT_MULTIPLIER` (default 1.8) | **CASSANDRA** — invisible to ARGUS per-minute 3σ / min-alert-volume floor, obvious in cumulative per-payer volume/amount over many minutes |
| `log_attack` | malicious log *content* at normal traffic rates from a modest external attacker-IP pool: SQL injection, path traversal, credential-stuffing auth failures, scanner probes. Events stay schema-valid with a normal status distribution; `attack_pattern=log_attack` | `LOG_ATTACK_PROBABILITY` (default 0.08) | **SENTINEL** — must not move ARGUS rate detectors or the error-rate monitor; detectable only from the log line |
| `mixed` | all four behaviours together (default) | — | full detection stack |

**`slow_exfil` safety margin.** The default `wallet-user-0001` is a payer in ordinary
traffic, so it has ARGUS baseline history (~1.7 events/min). At ~2 extra events/min its
per-minute count stays far under ARGUS's `min_alert_events` (10) volume floor, so no alert
ever fires. The covert channel is the elevated *amount*, which is **not** an ARGUS scoring
feature (ARGUS's z-detectors are rate/payload/error only) — so the money moved is
invisible per-minute, while the persistent per-payer volume+amount drift accumulates for
CASSANDRA's CUSUM. (ARGUS may still emit a few non-alerting `is_anomalous` score docs on
the payer while its low baseline slowly re-absorbs the higher steady rate — that is under
the alert floor by design.)

**`log_attack` safety margin.** Attack events are spread over ~20 external-looking IPs at
the default probability (≈2–3 events/min per IP), staying under ARGUS's per-IP cohort
alert floor; the transaction `status` keeps the baseline decline rate, so the derived
`error` field — and the `guardian-error-rate-spike` monitor — do not move. The attack
lives entirely in `log_message` (HTTP status in the log line is a separate dimension from
the payment `status`).

**Log-line format.** One line, ~90–160 chars, combined access/app style:
`<ip> - <payer> [<ts>] "<METHOD> <path> HTTP/1.1" <code> <bytes> <lat>ms "<msg>"`. Benign
traffic rotates a small set of endpoint families (route / balance / status / settlement /
declined) so a template miner (Drain3) converges on a stable template set; attack traffic
keeps the same envelope but carries the signature in the path or message.

## Normalized fields

Vector's `normalize` transform (infra/vector/vector.yaml) maps the envelope into the
OpenSearch document below; mappings are pinned by
`infra/opensearch/index-template.json`.

| OpenSearch field | From envelope | Type |
|---|---|---|
| `@timestamp` | `timestamp` | date |
| `event.id` / `event.type` | `event_id` / `event_type` | keyword |
| `source.service` | `source` | keyword |
| `network.client_ip` | `client_ip` | ip |
| `transaction.payer_id` `.payee_id` `.channel` `.currency` `.status` | same names | keyword |
| `transaction.amount` | `amount` | double |
| `transaction.latency_ms` | `latency_ms` | float |
| `security.is_attack` | `is_attack` | boolean |
| `security.attack_pattern` | `attack_pattern` | keyword |
| `security.is_malformed` | `!raw_payload_valid` | boolean |
| `error` | derived: status ∈ {declined, error, malformed} | boolean |
| `log.message` | `log_message` | text (+ `.keyword` subfield) |
| `ingest.pipeline_stage` / `ingest.processed_at` | added by Vector | keyword / date |

`log.message` is attached only when the envelope carries `log_message` (the field is
optional, so old queued events simply omit it); SENTINEL mines templates from it.

The error-rate visualization aggregates on `error`; traffic-volume splits on
`event.type` / `security.is_attack`.

## Detection layer

ARGUS consumes `guardian.telemetry.normalized` and aggregates events into **1-minute
tumbling buckets** per entity. Entity model:

| `entity_type` | `entity_id` | Baseline |
|---|---|---|
| `global` | `global` | EW mean/var of its own bucket history |
| `payer` | `transaction.payer_id` | EW mean/var of its own bucket history |
| `client_ip` | `network.client_ip` | **cohort** stats (all per-IP bucket counts) — random synthetic IPs rarely repeat, so per-IP history is useless but a flood IP towers over the cohort |

Per-bucket features: `event_count`, `mean_payload_bytes` (raw Kafka message size),
`mean_amount` (abs), `error_ratio`, `malformed_count`. Detectors: per-entity/cohort
z-score (threshold 3σ), plus an Isolation Forest and k-NN distance fit on a rolling
window of recent bucket vectors. `anomaly_score` ∈ [0, 1] (z of 3σ ≈ 0.5, ≥6σ = 1.0).

**Warmup:** an entity emits no alerts until `WARMUP_BUCKETS` (default 15) buckets of
history exist; scores are still emitted with `warming_up: true`. The production design
is a 7-day rolling window — the demo compresses this via env so a fresh stack is live
in ~15 minutes, or immediately after `training/seed_baseline.py` replays backdated
benign traffic through capture-agent.

### Score document (topic `guardian.scores` → index `guardian-scores-*`)

Every finalized bucket for `global`, plus per-entity buckets that are anomalous or have
≥3 events (volume floor). Shape (flattened): `@timestamp` (bucket end), `score.model`
(`"argus"`), `score.entity_type/entity_id`, `score.anomaly_score`, `score.is_anomalous`,
`score.warming_up`, `score.reasons[]` (e.g. `"rate_z=5.2>3.0"`), `score.features.*`,
`score.baseline.*` (`rate_mean/rate_std/payload_mean/payload_std/buckets_observed`),
`score.window.start/end/duration_seconds`. Mappings pinned by
`infra/opensearch/scores-template.json`.

### Alert message (topic `guardian.alerts` → alerting service + `guardian-alerts-*`)

Emitted only for anomalous, post-warmup buckets:

```json
{
  "@timestamp": "2026-07-12T08:41:00Z",
  "alert": {
    "id": "0d9c…",
    "type": "rate_spike",
    "severity": "high",
    "entity_type": "client_ip",
    "entity_id": "10.2.14.9",
    "score": 0.93,
    "source": "argus",
    "summary": "Request rate for client_ip 10.2.14.9 is 14.1x its cohort baseline (312 events/min, cohort mean 2.1).",
    "window": { "start": "2026-07-12T08:40:00Z", "end": "2026-07-12T08:41:00Z" },
    "details": { "rate_z": 9.4 }
  }
}
```

`alert.type` ∈ `rate_spike | payload_anomaly | error_ratio_spike | multivariate_outlier |
error_rate_spike` (the last emitted by the OpenSearch monitor, `source:
"opensearch-monitor"`). `severity` ∈ `low | medium | high`. Mappings pinned by
`infra/opensearch/alerts-template.json`. The alerting service dedups on
`(entity_type, entity_id, type)` within `DEDUP_SECONDS` (default 300) and posts to
Slack (`SLACK_WEBHOOK_URL`) and/or Discord (`DISCORD_WEBHOOK_URL`); with neither set it
runs in log-only mode.

## Detection layer — Week 3 scorers

Three services join the detection layer in Week 3. Two are additional scorers that read
the same `guardian.telemetry.normalized` stream as ARGUS and publish to `guardian.scores`
/ `guardian.alerts`; the third (fusion) aggregates all scorers into a single threat
picture. All score/alert documents keep the existing flattened shape (`score.model`,
`score.entity_type/entity_id`, … / `alert.type`, `alert.source`, …), so Vector carries
them into `guardian-scores-*` / `guardian-alerts-*` with no new templates.

The `features` objects below are **indicative and owned by the producing service** — the
exact set is finalised on each service's branch; only the envelope (`score.model`,
entity, `anomaly_score`/`is_anomalous`, `window`) is a hard cross-service contract.

### SENTINEL — log-line classification (`score.model: "sentinel"`)

Mines templates from `log.message` (Drain3) and scores per-`client_ip` (and, where
useful, per-payer) windows for malicious log content — SQL injection, path traversal,
credential stuffing, scanner probes. Entity is `client_ip` or a payer window.

```json
{
  "@timestamp": "2026-07-12T08:41:00Z",
  "score": {
    "model": "sentinel",
    "entity_type": "client_ip",
    "entity_id": "45.148.10.19",
    "anomaly_score": 0.88,
    "is_anomalous": true,
    "reasons": ["template=sqli_probe count=7", "auth_fail_ratio=0.6"],
    "features": { "template_counts": { "sqli_probe": 7, "scanner_probe": 3 }, "window_events": 24, "distinct_templates": 5 },
    "window": { "start": "2026-07-12T08:40:00Z", "end": "2026-07-12T08:41:00Z", "duration_seconds": 60 }
  }
}
```

Anomalous windows raise `alert.type: "log_classification"` (`alert.source: "sentinel"`).

### CASSANDRA — cumulative per-payer drift (`score.model: "cassandra"`)

Consumes normalized events, aggregates per-payer buckets, and runs a CUSUM (and/or
comparable cumulative test) over the aggregated series to catch slow, persistent drift —
the `slow_exfil` case that stays under ARGUS's per-minute detectors. Entity is `payer`.

```json
{
  "@timestamp": "2026-07-12T08:41:00Z",
  "score": {
    "model": "cassandra",
    "entity_type": "payer",
    "entity_id": "wallet-user-0001",
    "anomaly_score": 0.79,
    "is_anomalous": true,
    "reasons": ["cusum_volume=42.0>threshold", "cumulative_amount_drift=+38%"],
    "features": { "cusum_volume": 42.0, "buckets_elevated": 26, "cumulative_amount": 91500000.0, "mean_amount_ratio": 1.6 },
    "window": { "start": "2026-07-12T08:15:00Z", "end": "2026-07-12T08:41:00Z", "duration_seconds": 1560 }
  }
}
```

Sustained drift raises `alert.type: "slow_exfiltration"` (`alert.source: "cassandra"`).

### fusion — unified Guardian threat state (`score.model: "guardian"`)

fusion consumes `guardian.scores` (group `guardian-fusion`), **filtering out
`score.model == "guardian"`** to avoid a self-feedback loop. It maintains a decayed
per-entity threat state plus a global threat state, combining the scorers' outputs as a
weighted sum with a **corroboration boost** when multiple models independently flag the
same entity (e.g. ARGUS rate + SENTINEL log content on one IP). It emits `score.model:
"guardian"` documents to `guardian.scores` roughly every 30s and on any significant
change:

```json
{
  "@timestamp": "2026-07-12T08:41:12Z",
  "score": {
    "model": "guardian",
    "entity_type": "global",
    "entity_id": "global",
    "anomaly_score": 0.72,
    "threat_level": "elevated",
    "is_anomalous": true,
    "reasons": ["argus:rate_spike", "sentinel:sqli", "corroborated:2 models"],
    "features": { "contributors": { "argus": 0.61, "sentinel": 0.88 }, "corroboration": 2, "top_entities": ["45.148.10.19"] },
    "window": { "start": "2026-07-12T08:40:42Z", "end": "2026-07-12T08:41:12Z", "duration_seconds": 30 }
  }
}
```

Global threat level moves through `normal → elevated → critical` (with hysteresis on the
decayed global score). On a level transition fusion raises `alert.type:
"threat_level_change"` (`alert.source: "guardian"`), and exposes the current picture at
`GET /threat` for the future Guardian Pulse HUD.

### New alert types (Week 3)

`alert.type` gains three values on top of the ARGUS/monitor set above:

| `alert.type` | `alert.source` | Raised when |
|---|---|---|
| `log_classification` | `sentinel` | a client_ip/payer window carries malicious log content |
| `slow_exfiltration` | `cassandra` | a payer shows sustained cumulative volume/amount drift |
| `threat_level_change` | `guardian` | the global threat level transitions (normal↔elevated↔critical) |

The alerting service's `(entity_type, entity_id, type)` dedup applies unchanged.

## Index lifecycle

Daily indices `guardian-traffic-%Y.%m.%d` (time-based rollover via naming); ISM policy
`guardian-traffic-ilm` deletes indices older than 7 days. 1 shard / 0 replicas —
single-node cluster, replicas would only turn cluster health yellow. Demo-scale on
purpose; production-scale retention math is out of scope for the MVP.
`guardian-scores-*` / `guardian-alerts-*` follow the same daily-naming scheme but skip
ISM — their volume is a tiny fraction of traffic's and alert history is exactly what a
compliance reviewer wants kept.

## Deliberate deviations from the brief's suggested stack

1. **Kafka → Redpanda.** Same Kafka wire protocol (all clients/configs are portable),
   single binary, no ZooKeeper, far lower RAM footprint — the stack must fit a dev laptop
   where OpenSearch is already the RAM hog. Swappable back to Kafka with no app-code changes.
2. **eBPF mirroring → capture-agent service (MVP).** Kernel-level eBPF (Cilium Tetragon)
   needs a native Linux kernel; inside Docker Desktop's WSL2/Hyper-V VM, promiscuous-mode
   capture of other containers' traffic is unreliable, and debugging it would consume the
   Week 1 budget with no guarantee of success. The capture-agent sits at the same
   architectural seam (out-of-band, between telemetry source and queue) and satisfies the
   actual requirement — async/non-blocking ingestion that adds no latency to the request
   path. Real eBPF mirroring is planned for the DigitalOcean Linux VPS deployment.

## Branch ownership (Week 1 parallel work)

| Branch | Exclusively owns |
|---|---|
| `feat/mock-lti` | `services/mock-lti/**` |
| `feat/capture-agent` | `services/capture/**` |
| `feat/infra-pipeline` | `infra/**` |
| `feat/docs` | `docs/**` |
| `feat/dashboards` (after integration) | `infra/dashboards/saved_objects.ndjson` |

The compose file declares every service up front, and this document pins the
cross-service contracts (schema, ports, topic, normalized fields), so the branches
never need to touch each other's files.

## Branch ownership (Week 2)

`feat/w2-contracts-infra` lands first (this document's detection-layer contracts,
compose entries, Vector fan-out, index templates, init.sh); the rest build on it:

| Branch | Exclusively owns |
|---|---|
| `feat/argus` | `services/argus/**`, `training/**` |
| `feat/alerting` | `services/alerting/**` |
| `feat/dashboards-w2` | `infra/dashboards/detection_objects.ndjson` |
| `feat/docs-w2` | `docs/*_manual.md` |

## Branch ownership (Week 3)

`feat/w3-contracts-generator` lands first (this document's Week-3 contracts, the
`log_message` envelope field in both schema copies + Vector + index template, the
`slow_exfil` / `log_attack` generator modes, and `training/seed_baseline.py`); the rest
build on it. The compose file already declares the new services, so no branch edits it.

| Branch | Exclusively owns |
|---|---|
| `feat/w3-contracts-generator` | envelope schemas (both copies), `services/mock-lti/app/generator.py`, `infra/vector/vector.yaml`, `infra/opensearch/index-template.json`, `docs/architecture.md` contracts, `training/seed_baseline.py` |
| `feat/sentinel` | `services/sentinel/**`, `training/train_sentinel.py`, its compose block |
| `feat/cassandra` | `services/cassandra/**`, `training/seed_history.py`, its compose block |
| `feat/fusion` | `services/fusion/**`, its compose block |
| `feat/dashboards-w3` | `infra/dashboards/*_w3.ndjson` (new bundles) |
| `feat/docs-w3` | manuals + `README.md` |
| `fix/w3-integration` | reserved (integration fixes) |
