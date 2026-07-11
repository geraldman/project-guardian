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
     │  bulk index
     ▼
OpenSearch                            guardian-traffic-YYYY.MM.DD daily indices, ISM retention
     │
     ▼
OpenSearch Dashboards                 "Guardian Traffic Overview" single pane of glass
```

Extra-credit layers (later weeks): ARGUS / SENTINEL / CASSANDRA scorer microservices,
alerting (5-min dedup → Slack/Discord), Guardian Pulse HUD. See each service's README.

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

Queue: topic `guardian.telemetry.raw`, 3 partitions, ~6h retention (OpenSearch is the
durable store). Network: single bridge `guardian-net`.

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

## Index lifecycle

Daily indices `guardian-traffic-%Y.%m.%d` (time-based rollover via naming); ISM policy
`guardian-traffic-ilm` deletes indices older than 7 days. 1 shard / 0 replicas —
single-node cluster, replicas would only turn cluster health yellow. Demo-scale on
purpose; production-scale retention math is out of scope for the MVP.

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
