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

## Offline validation (measured, shipped defaults)

`tests/offline_check.py` drives the unmodified detection path (no stack, no
retuning) through generator-shaped attacks and benign traffic, so ARGUS's
detectors have measured behaviour instead of assumed behaviour. It needs
`numpy` + `scikit-learn` (the multivariate scorer is real sklearn), so it runs
in the 3.13 validation venv, not host 3.14:

    .venv-val/Scripts/python.exe services/argus/tests/offline_check.py

Detection (each an unmistakable single-minute event — a burst/flood is
instantaneous, so the metric is hit-rate across seeds, not delay):

- **rate_spike**: a ~3× burst lifts the global rate → global `rate_spike`,
  detected across all seeds.
- **client_ip flood**: a flood on one origin towers over the IP cohort →
  `rate_spike` on that IP (`cohort_rate_z` in details), all seeds.
- **error_ratio spike**: a malformed storm that holds the rate flat lifts the
  global error ratio → global `error_ratio_spike`.
- **multivariate**: after warmup the Isolation Forest ranks a gross joint
  outlier strictly more anomalous than an ordinary bucket (`decision_function`
  more negative).

Findings the harness surfaces (real, worth improving — not failures):

- **Per-payer rate alarms are largely gated out.** The generator spreads
  transactions uniformly over ~700 payers, so individual payer rates sit under
  `min_alert_events`; ARGUS's rate/error alarms are carried by the **global**
  aggregate and the **client_ip cohort**. Detection targets those surfaces.
- **Cold-start false-alarm transient.** `warmup_buckets`(15) lifts the alarm
  guard long before the EW variance (`ew_halflife_buckets`=120) converges, so an
  **unseeded** cold start reads normal fluctuation as z>3 for the first ~hour
  (measured: alerts by run-third ≈ `[4, 5, 1]` — it decays to quiet). Seeding
  via `seed_baseline.py` skips this window; steady-state global false alarms are
  ~3/day at `z_threshold=3` (scenario 7). To improve: raise `warmup_buckets`
  toward the halflife, or gate alarms on variance convergence.
- **k-NN saturation on homogeneous traffic.** The k-NN self-distance p99
  collapses toward its floor when recent buckets are near-identical, so
  `knn_ratio` explodes and the k-NN half of the multivariate score saturates;
  the Isolation Forest half stays calibrated and the `min_alert_events` gate
  masks it for the low-count payers that dominate, but a genuinely high-volume
  payer would be mis-flagged.

After any detector/threshold change, rerun the harness — it re-measures both
detection and the false-alarm cost.

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
