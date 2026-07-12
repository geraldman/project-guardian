# ARGUS — transaction-rate / payload-size anomaly scorer

FastAPI + aiokafka microservice. Consumes `guardian.telemetry.normalized`, folds events
into 1-minute tumbling buckets per entity, scores each bucket against baselines, and
emits score documents to `guardian.scores` (every bucket) and alerts to
`guardian.alerts` (anomalous, post-warmup buckets only). Pure Kafka-in/Kafka-out —
Vector carries both topics into OpenSearch (`guardian-scores-*` / `guardian-alerts-*`).

Contracts (entity model, document schemas, thresholds): `docs/architecture.md#detection-layer`.

## Detectors

| Signal | Technique | Fires as |
|---|---|---|
| per-entity request rate | EW mean/var z-score, 3σ | `rate_spike` |
| per-IP request rate | z-score vs the **cohort** of all per-IP counts | `rate_spike` |
| mean payload size | EW z-score | `payload_anomaly` |
| error ratio | EW z-score | `error_ratio_spike` |
| bucket shape (payers only) | Isolation Forest + k-NN distance ratio on recent per-payer bucket vectors | `multivariate_outlier` |

Score-then-update: each bucket is judged against the baseline as it stood before it.
The Isolation Forest / k-NN pair refits every ~15 buckets on a rolling reservoir in a
worker thread; it is not persisted across restarts (re-arms in minutes — cheaper than
versioning pickles). EW baselines *are* persisted to `/data/argus_state.json`
(atomic snapshot every 60s and on shutdown) so restarts don't reset learning.

## Warmup / cold start

No alerts for an entity until it has `WARMUP_BUCKETS` (default 15) buckets of history;
scores are still emitted with `warming_up: true`. Fresh stack options: wait ~15 min of
live traffic, or fast-forward via `python training/seed_baseline.py` (replays backdated
benign traffic through the real pipeline). Production design is a 7-day window — the
demo compresses it via env (`ARGUS_WARMUP_BUCKETS`, `ARGUS_Z_THRESHOLD` in compose).

## Endpoints (:8002)

| Endpoint | Purpose |
|---|---|
| `GET /health` | consumer status, warmup progress, model fitted |
| `GET /stats` | counters (events, buckets, scores, alerts), reservoir/model state, config |
| `GET /baseline/global` | the global traffic baseline |
| `GET /baseline/payer/{id}` | one payer's baseline (404 until first seen) |
| `GET /baseline/client_ip` | the IP cohort baseline |

## Local dev

Host Python 3.14 cannot build aiokafka wheels — develop in the container:
`docker compose up -d --build argus && docker compose logs -f argus`.
