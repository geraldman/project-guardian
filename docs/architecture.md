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

Queue topics (all 3 partitions, replication 1, ~6h retention — OpenSearch is the
durable store). Network: single bridge `guardian-net`.

| Topic | Producer | Consumers (group) |
|---|---|---|
| `guardian.telemetry.raw` | capture-agent | Vector (`guardian-vector`) |
| `guardian.telemetry.normalized` | Vector | ARGUS (`guardian-argus`), later SENTINEL/CASSANDRA |
| `guardian.scores` | ARGUS | Vector (`guardian-vector-scores`) → `guardian-scores-*` |
| `guardian.alerts` | ARGUS | alerting (`guardian-alerting`), Vector (`guardian-vector-alerts`) → `guardian-alerts-*` |

Topic bootstrap: capture-agent creates `guardian.telemetry.raw`; ARGUS creates
`guardian.telemetry.normalized`, `guardian.scores` and `guardian.alerts`; the alerting
service also ensures `guardian.alerts` (idempotent creates, first one up wins).

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
| `attack_pattern` | str \| null | `burst` \| `malformed` |
| `client_ip` | str \| null | synthetic, always a valid IP |
| `raw_payload_valid` | bool | `false` marks intentionally malformed payloads |

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
  "raw_payload_valid": true
}
```

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
| `ingest.pipeline_stage` / `ingest.processed_at` | added by Vector | keyword / date |

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
   architectural seam (out-of-band, between telemetry source and queue) and satisfies
   §5.1.2's actual requirement — async/non-blocking ingestion that adds no latency to the
   request path. Real eBPF mirroring is planned for the DigitalOcean Linux VPS deployment.

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
