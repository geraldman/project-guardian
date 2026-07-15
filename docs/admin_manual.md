# GUARDIAN Admin Manual

Operator and maintainer runbook: the service inventory, configuration reference, detector
tuning, day-to-day operations, reset/recovery, retraining, troubleshooting, and the
end-to-end verification checklist. For a first-time walkthrough see the
[User Manual](user_manual.md).

Conventions used below:

- Run `docker compose ...` commands from the repository root (the root compose file
  includes the canonical stack definition in `infra/docker-compose.yml`).
- `curl` examples use POSIX shell syntax and the default admin password
  `Guardian!Lti2026` — substitute your own if you overrode
  `OPENSEARCH_ADMIN_PASSWORD`. In Windows PowerShell use `curl.exe`.

## 1. The stack

The pipeline, port allocations, event schema, normalized field mapping, and the rationale
for the two deliberate stack choices (Redpanda instead of Kafka; an HTTP capture-agent as
the MVP stand-in for eBPF traffic mirroring) are pinned in
[architecture.md](architecture.md) — that document is the contract; this manual does not
restate it. The one-line version:

```
mock-lti → capture-agent → Redpanda (guardian.telemetry.raw) → Vector → OpenSearch → Dashboards
                                                                  │
                       guardian.telemetry.normalized ←────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
            ARGUS                 SENTINEL              CASSANDRA
              └──────────────────────┼──────────────────────┘
                                     ▼
                            guardian.scores  ──► fusion ──┐
                                     │                    │
                                     ▼                    ▼
                          Vector → guardian-scores-*  guardian.alerts
                                                          ├→ Vector → guardian-alerts-*
                                                          └→ alerting → Slack/Discord/log
```

### 1.1 The fourteen services

| # | Service | Port | Built? | What it does | If it dies |
|---|---|---|---|---|---|
| 1 | `redpanda` | 19092 (host), 9644 (admin) | image | Kafka-API queue; all four topics live here | Everything downstream stalls. Producers/consumers reconnect on their own. |
| 2 | `redpanda-console` | 8080 | image | Web UI for topics, messages, consumer-group lag | Cosmetic — inspection only. |
| 3 | `opensearch` | 9200 | image | Durable store + SIEM engine (ISM, Alerting plugins) | Vector's writes fail; the queue buffers (~6 h retention), so a quick recovery loses nothing. |
| 4 | `opensearch-dashboards` | 5601 | image | The analyst UI | Cosmetic — data keeps flowing. |
| 5 | `opensearch-init` | — | image | One-shot bootstrap: index templates, ISM policy, notification channel, monitor, dashboard bundles | Nothing to fix at runtime — `Exited (0)` is its healthy state. |
| 6 | `vector` | — | image | Parse + normalize + enrich (VRL); the **single OpenSearch write path**; fans normalized events back onto the queue | Indices stop growing and the detectors stop receiving events. First suspect when documents stop. |
| 7 | `mock-lti` | 8000 | build | Digital twin: synthetic LTI API + traffic/attack generator | No new traffic. The stack is idle but healthy. |
| 8 | `capture-agent` | 8001 | build | Ingestion boundary → Redpanda producer (eBPF stand-in) | Telemetry is dropped at the door; mock-lti's `telemetry.failed` counter climbs. |
| 9 | `argus` | 8002 | build | Rate / payload / error-ratio scorer (EW z-scores + Isolation Forest / k-NN) | Loses no baselines (volume-backed) but scores nothing while down. |
| 10 | `sentinel` | 8004 | build | Log-content classifier (Drain3 + XGBoost) | Stateless apart from mined templates; resumes from committed offsets. |
| 11 | `cassandra` | 8005 | build | Per-payer CUSUM slow-exfiltration detector | Baselines are volume-backed; resumes warm. |
| 12 | `fusion` | 8006 | build | Folds all scores into one decayed threat state; serves `/threat` | State is in-memory by design; re-forms from the live stream in ~2 min. |
| 13 | `alerting` | 8003 | build | 5-minute dedup + Slack/Discord delivery (plus an HTTP inlet for OpenSearch monitors) | Alerts accumulate on the queue and are delivered on restart. |
| 14 | `guardian-pulse` | 3000 | build | Guardian Pulse HUD — Next.js single pane over fusion + the scorers (threat lamp, heartbeats, narrative, freeze-to-PDF) | Cosmetic — detection, storage and alerting are untouched. Stateless; restart freely. |

Component-level detail lives with each component: `services/*/README.md`,
`infra/vector/vector.yaml`, `infra/opensearch/*.json` (index templates, ISM policy,
notification channel, monitor), `infra/opensearch-init/init.sh`,
`infra/dashboards/README.md`, `training/`.

### 1.2 Named volumes

| Volume | Holds | Lost on `down -v` |
|---|---|---|
| `opensearch-data` | all indices + the security config (including the admin password set at first start) | All indexed traffic, scores, alerts; all Dashboards state not committed to `infra/dashboards/*.ndjson` |
| `redpanda-data` | queued messages + consumer-group offsets | The ~6 h transit buffer |
| `argus-data` | ARGUS's learned baselines (`/data/argus_state.json`) | **Warm-up restarts** — 15 buckets per entity |
| `cassandra-data` | CASSANDRA's per-payer baselines and open CUSUM excursions (`/data/cassandra_state.json`) | **Warm-up restarts** — 30 observed minutes per payer |

⚠ The last two are the ones that bite. See [section 5](#5-reset-and-recovery).

## 2. Configuration

All tunables are environment variables. Put overrides in a `.env` file at the repository
root (or export them) before `docker compose up`. `.env` is gitignored.

### Overridable via `.env` (wired into the compose file)

| Variable | Default | Consumed by | Effect |
|---|---|---|---|
| `OPENSEARCH_ADMIN_PASSWORD` | `Guardian!Lti2026` | opensearch, dashboards, vector, opensearch-init | The single admin credential for the storage layer. **Applied only on first start** — see below. |
| `EVENTS_PER_SECOND` | `10` | mock-lti | Baseline synthetic-traffic rate. Also adjustable at runtime ([4.1](#41-runtime-generator-control)). |
| `ATTACK_MODE` | `mixed` | mock-lti | `off` \| `burst` \| `malformed` \| `mixed` \| `slow_exfil` \| `log_attack`. Also adjustable at runtime. |
| `SLACK_WEBHOOK_URL` | *(empty)* | alerting | Slack incoming-webhook URL. Empty = log-only mode (alerts go to `docker compose logs alerting`). Never commit a real URL. |
| `DISCORD_WEBHOOK_URL` | *(empty)* | alerting | Discord webhook URL; may be set together with Slack. |
| `ALERT_DEDUP_SECONDS` | `300` | alerting | Dedup window per `(entity_type, entity_id, alert type)`. |
| `ARGUS_WARMUP_BUCKETS` | `15` | argus | Buckets of history an entity needs before it may alert (demo-compressed; production design is a multi-day window). |
| `ARGUS_Z_THRESHOLD` | `3.0` | argus | Z-score threshold (σ) for the rate / payload / error-ratio detectors. |

### Fixed in the compose file

Wired to service hostnames on the internal `guardian-net` network; changing them means
editing `infra/docker-compose.yml`:

| Variable | Value | Consumed by |
|---|---|---|
| `CAPTURE_INGEST_URL` | `http://capture-agent:8001/ingest` | mock-lti |
| `REDPANDA_BROKERS` | `redpanda:9092` | capture-agent, argus, sentinel, cassandra, fusion, alerting |
| `TELEMETRY_TOPIC` | `guardian.telemetry.raw` | capture-agent |
| `INPUT_TOPIC` | `guardian.telemetry.normalized` | argus, sentinel, cassandra |
| `INPUT_TOPIC` | `guardian.scores` | **fusion** (it consumes scores, not telemetry) |
| `SCORES_TOPIC` / `ALERTS_TOPIC` | `guardian.scores` / `guardian.alerts` | argus, sentinel, cassandra, fusion (alerting consumes `ALERTS_TOPIC`) |
| `STATE_PATH` | `/data/argus_state.json` | argus |
| `STATE_PATH` | `/data/cassandra_state.json` | cassandra |
| `FUSION_URL` / `ARGUS_URL` / `SENTINEL_URL` / `CASSANDRA_URL` | `http://fusion:8006` etc. | guardian-pulse (server-side proxy targets; never exposed to the browser) |

### Service-level settings not surfaced in compose

Every service reads its settings from env (pydantic-settings: the env var name is the
field name in upper case), but the compose file only wires the ones above. Anything else
keeps its code default — including **all of SENTINEL's, CASSANDRA's and fusion's detection
knobs**. To change one, add it to that service's block in `infra/docker-compose.yml` and
`docker compose up -d <service>`. See [section 3](#3-tuning-the-detectors).

Also unsurfaced: mock-lti's `EMIT_TIMEOUT_SECONDS` (default `2.0`) bounding each
fire-and-forget telemetry POST, and its `slow_exfil` / `log_attack` tunables —
`EXFIL_PAYER_ID` (`wallet-user-0001`), `EXFIL_EVENTS_PER_MINUTE` (`2.0`),
`EXFIL_AMOUNT_MULTIPLIER` (`1.8`), `LOG_ATTACK_PROBABILITY` (`0.08`) — all in
`services/mock-lti/app/config.py`.

### The password caveat

OpenSearch consumes `OPENSEARCH_ADMIN_PASSWORD` as its *initial* admin password: it is
written into the security index **only when the `opensearch-data` volume is first
created**. Changing `.env` later does not change the actual password — Dashboards,
Vector, and the init job will then be using a wrong credential. To change the password,
either do it before first start, or wipe and re-init: `docker compose down -v` then
`docker compose up -d` (destroys all indexed data *and the learned baselines* — see
[section 5](#5-reset-and-recovery)).

## 3. Tuning the detectors

Each detector's README owns its knobs and explains the trade-off behind each default. Do
not tune blind — every one of these defaults was chosen against a measured false-alarm
rate or a documented failure mode.

| Detector | Knobs | Where |
|---|---|---|
| **ARGUS** | `ARGUS_WARMUP_BUCKETS`, `ARGUS_Z_THRESHOLD` (both `.env`-overridable) | [services/argus/README.md](../services/argus/README.md) |
| **SENTINEL** | `ANOMALY_THRESHOLD` (0.70), `SUSPICIOUS_THRESHOLD` (0.40), `AUTH_FAIL_STORM` (3), `MIN_WINDOW_EVENTS` (3), `MAX_ALERTS_PER_WINDOW` (5), `WINDOW_SECONDS` (60) | [services/sentinel/README.md](../services/sentinel/README.md) |
| **CASSANDRA** | `WARMUP_BUCKETS` (30), `CUSUM_K` (0.75), `CUSUM_H` (6.0), `CUSUM_H_SINGLE` (10.0), `MIN_DRIFT_BUCKETS` (6), `EWMA_ALARM_FLOOR` (0.9), `AMOUNT_EVENT_CAP` (1M IDR) | [services/cassandra/README.md](../services/cassandra/README.md) |
| **fusion** | `WEIGHT_ARGUS`/`WEIGHT_SENTINEL`/`WEIGHT_CASSANDRA` (0.55/0.60/0.50), `HALF_LIFE_SECONDS` (120), `CORROBORATION_BOOST` (0.25), `MIN_CONTRIB_EVENTS` (10), `ELEVATED_UP`/`CRITICAL_UP` (0.40/0.75) | [services/fusion/README.md](../services/fusion/README.md) |

Three things worth knowing before you touch anything:

- **CASSANDRA's defaults are a measured trade-off, not a guess.** At the shipped values the
  offline validation measures ~2 false-alarm episodes per ~3,100 benign payer-hours, and
  25/25 slow_exfil seeds detected with a median delay of 9 minutes. `CUSUM_K` is the shift
  size you are willing to be slow about; `CUSUM_H` trades detection delay against
  false-alarm rate. **After any change, re-measure both sides:**

  ```sh
  python services/cassandra/tests/offline_check.py    # host Python, no stack needed
  ```

- **fusion's `MIN_CONTRIB_EVENTS` is a noise floor, not a nicety.** ARGUS emits a steady
  trickle of `is_anomalous` score docs for tiny 1–6-event payer buckets; only real attack
  windows carry `event_count >= 10`. Lowering this floor will light the threat level up on
  benign traffic. (SENTINEL/CASSANDRA docs carry no `event_count` and are exempt — a single
  malicious log line is meaningful at any volume.)

- **Raising a threshold to silence alerts usually means the warm-up was skipped.** Check
  [section 6](#6-warm-up-and-seeding) before retuning.

Sanity-check a detector's *effective* config at runtime — `GET /stats` on each service
echoes what it is actually running with, which is the fastest way to confirm an env
override landed:

```sh
curl -s http://localhost:8005/stats   # CASSANDRA: config.cusum_k, cusum_h, warmup_buckets, ...
curl -s http://localhost:8004/stats   # SENTINEL: config.anomaly_threshold, auth_fail_storm, ...
curl -s http://localhost:8006/threat  # fusion: config.weights, thresholds, half_life_seconds
```

## 4. Operations

### 4.1 Runtime generator control

Traffic rate and attack mode change while the stack runs, via the mock-lti admin API:

```sh
# Current configuration and status counters
curl -s http://localhost:8000/admin/generator/status

# Change rate and/or attack mode (takes effect without a restart)
curl -s -X POST http://localhost:8000/admin/generator/config \
  -H 'Content-Type: application/json' \
  -d '{"events_per_second": 50, "attack_mode": "burst"}'
```

Valid modes: `off` | `burst` | `malformed` | `mixed` | `slow_exfil` | `log_attack`;
anything else is a 422. Runtime changes do not persist across a container restart — the
service falls back to `EVENTS_PER_SECOND` / `ATTACK_MODE`.

Verified live: the config endpoint echoes the effective configuration; the status response
carries `config`, `counters.events_emitted.{total,transaction,burst_spike,malformed_payload}`,
`counters.attacks_injected.{burst,malformed,slow_exfil,log_attack}`,
`counters.telemetry.{sent,failed}`, and `uptime_seconds`.

### 4.2 Inspecting the queue

**Redpanda Console** (http://localhost:8080) is the quickest view:

1. **Topics** — four: `guardian.telemetry.raw` (envelopes from capture-agent),
   `guardian.telemetry.normalized` (Vector's normalized fan-out), `guardian.scores` (one
   document per finalized bucket from *any* scorer, plus fusion's own `guardian` docs) and
   `guardian.alerts` (anomalies only). The Messages tab live-tails each.
2. **Consumer Groups** — `guardian-vector` (raw → OpenSearch), `guardian-argus`,
   `guardian-sentinel`, `guardian-cassandra` (normalized → scoring), `guardian-fusion`
   (scores → threat state), `guardian-vector-scores` / `guardian-vector-alerts`
   (scores/alerts → OpenSearch), `guardian-alerting` (alerts → webhooks). Lag near zero
   means the consumer is keeping up; steadily growing lag means events arrive faster than
   they are processed.

Command-line equivalents via `rpk` inside the Redpanda container:

```sh
docker compose exec redpanda rpk topic list
docker compose exec redpanda rpk topic consume guardian.telemetry.raw -n 5
docker compose exec redpanda rpk topic describe guardian.telemetry.raw

# Detection layer: are scores/alerts flowing, and is each scorer keeping up?
docker compose exec redpanda rpk topic consume guardian.scores -n 2
docker compose exec redpanda rpk group describe guardian-argus
docker compose exec redpanda rpk group describe guardian-sentinel
docker compose exec redpanda rpk group describe guardian-cassandra
docker compose exec redpanda rpk group describe guardian-fusion
```

For host-side Kafka tooling (kcat, a local `rpk`, custom clients), the external listener is
`localhost:19092`; the Redpanda Admin API is on `localhost:9644`.

The topic is a transit buffer, not the store: ~6 h retention, 3 partitions. OpenSearch
holds the durable data.

### 4.3 Index lifecycle

- **Daily indices.** Vector writes to `guardian-traffic-%Y.%m.%d` (UTC date suffix), so a
  new index is created at each UTC midnight — rollover-by-time via naming, no rollover
  machinery needed.
- **Mappings** are pinned by index templates (`infra/opensearch/index-template.json`,
  `scores-template.json`, `alerts-template.json`), applied by `opensearch-init` at startup.
  The traffic template sets `ignore_malformed: true` so a single odd value cannot reject a
  document.
- **Retention.** ISM policy `guardian-traffic-ilm` (`infra/opensearch/ism-policy.json`)
  auto-attaches to `guardian-traffic-*` and deletes indices older than **7 days**.
- **1 shard / 0 replicas.** Single-node cluster: replicas could never be assigned and would
  only turn cluster health yellow.
- **Detection indices.** `guardian-scores-*` / `guardian-alerts-*` follow the same daily
  naming but are **not** under ISM: their volume is a tiny fraction of traffic's, and alert
  history is exactly what a compliance reviewer wants kept. All four score models
  (`argus`, `sentinel`, `cassandra`, `guardian`) share `guardian-scores-*` — the flattened
  envelope is identical, so Week 3 needed no new templates.

Useful checks:

```sh
# Which daily indices exist, and how many docs each holds
curl -sk -u 'admin:Guardian!Lti2026' 'https://localhost:9200/_cat/indices/guardian-*?v'

# Is the ISM policy attached?
curl -sk -u 'admin:Guardian!Lti2026' 'https://localhost:9200/_plugins/_ism/explain/guardian-traffic-*?pretty'

# Score docs per model — confirms all four scorers are writing
curl -sk -u 'admin:Guardian!Lti2026' \
  'https://localhost:9200/guardian-scores-*/_search?size=0&pretty' \
  -H 'Content-Type: application/json' \
  -d '{"aggs":{"by_model":{"terms":{"field":"score.model"}}}}'
```

Index-template changes only affect indices created *after* the change — at the latest, the
next day's index. To re-map today's data, delete today's index and let Vector re-create it
(only events still within the topic's retention window are replayed; older documents are
gone).

### 4.4 Checking pipeline health

**Container level:**

```sh
docker compose ps
```

Every long-running service has a healthcheck (Redpanda: `rpk cluster health`; OpenSearch:
cluster status green/yellow; Dashboards: `/api/status` green; the eight built services:
HTTP `/health` — guardian-pulse's is `/api/health`). `opensearch-init` is a one-shot
job — `Exited (0)` is its healthy state.

**What the health states mean:**

- **`status: "ok"`** — the service's Kafka consumer/producer is connected.
- **`status: "degraded"`** — it is up and answering HTTP, but **not connected to
  Redpanda**. Every service starts degraded and self-heals once Redpanda is up (they retry
  rather than crash-loop, which is why a slow broker boot doesn't take the stack down). If
  it stays degraded, Redpanda is the problem, not the service.
- **`warming_up: true`** (ARGUS, CASSANDRA) — **not a fault.** The detector lacks enough
  baseline history to alert safely and is deliberately staying quiet. It is still
  consuming and still emitting score documents. See [section 6](#6-warm-up-and-seeding).

**Detection layer, service by service:**

```sh
curl -s http://localhost:8002/health   # argus:     warming_up, buckets_observed, model_fitted
curl -s http://localhost:8004/health   # sentinel:  model_loaded, model_trees, windows_scored
curl -s http://localhost:8005/health   # cassandra: payers_tracked, payers_warm
curl -s http://localhost:8006/health   # fusion:    threat_level, entities_tracked
curl -s http://localhost:8003/health   # alerting:  mode (log-only / webhook), dedup_seconds
```

A healthy warm stack (verified live):

```json
{"status":"ok","service":"argus","consumer_connected":true,"warming_up":false,
 "buckets_observed":499,"warmup_buckets":15,"model_fitted":true,"topics":{...}}
{"status":"ok","service":"sentinel","consumer_connected":true,"model_loaded":true,
 "model_trees":40,"windows_scored":105721,"topics":{...}}
{"status":"ok","service":"cassandra","consumer_connected":true,"warming_up":false,
 "payers_tracked":700,"payers_warm":700,"warmup_buckets":30,"topics":{...}}
{"status":"ok","service":"fusion","consumer_connected":true,"threat_level":"elevated",
 "entities_tracked":23,"scores_folded":76,"emits":33,"topics":{...}}
{"status":"ok","service":"alerting","consumer_connected":true,"mode":"log-only",
 "dedup_seconds":300.0,"topic":"guardian.alerts"}
```

**Bootstrap job:**

```sh
docker compose logs opensearch-init
```

Expect the three index templates, the ISM policy (409 on re-run = already exists, fine),
the `guardian-alerting-webhook` notification channel, the `guardian-error-rate-spike`
monitor, and one `imported <bundle>.ndjson` line per file in `infra/dashboards/`, then a
final `[init] done`. The init script checks every HTTP status — a rejected call aborts the
job with the response body in the log, so a non-`Exited (0)` init container means exactly
one thing to fix.

**Vector (the usual first suspect when documents stop):**

```sh
docker compose logs -f vector
```

Healthy output is quiet. Look for Kafka connection errors (Redpanda down), VRL/remap errors
(schema drift), or HTTP 401/TLS errors against `https://opensearch:9200` (password
mismatch — see [section 2](#2-configuration)).

**Data level — walk the hops in pipeline order.** The first hop that shows nothing is where
to dig:

```sh
# 1. Is the generator emitting?
curl -s http://localhost:8000/admin/generator/status

# 2. Are events on the topic?
docker compose exec redpanda rpk topic consume guardian.telemetry.raw -n 5

# 3. Is Vector consuming (lag near zero)?
docker compose exec redpanda rpk group describe guardian-vector

# 4. Are documents landing in today's index?
curl -sk -u 'admin:Guardian!Lti2026' 'https://localhost:9200/guardian-traffic-*/_count?pretty'

# 5. Are the scorers consuming, warm, and emitting?
curl -s http://localhost:8002/stats   # buckets_finalized / scores_emitted / alerts_emitted
curl -s http://localhost:8004/stats
curl -s http://localhost:8005/stats

# 6. Are score documents landing?
curl -sk -u 'admin:Guardian!Lti2026' 'https://localhost:9200/guardian-scores-*/_count?pretty'

# 7. Is fusion folding them?
curl -s http://localhost:8006/threat   # counters.scores_folded should climb during an attack

# 8. Is the alerting service receiving/sending?
curl -s http://localhost:8003/stats

# 9. Is the HUD up, and can it see everything?
curl -s http://localhost:3000/api/pulse   # per-source ok/error for fusion + all three scorers
```

### 4.5 Guardian Pulse

Stateless presentation container — no volume, restart freely. The compose healthcheck
hits `GET /api/health` on `:3000` (liveness only: it stays healthy while scorers are
down — the panel-level offline states are the intended signal instead).

`GET /api/pulse` doubles as a one-call reachability probe of fusion plus all three
scorers (check #9 above): every upstream the HUD cannot reach reports `ok:false` with
the error string.

Development on the host without Docker: `cd dashboard && npm ci && npm run dev` — the
proxy falls back to the published `localhost` ports, so the HUD runs against a live
stack or renders offline states against a dead one. Pick another port with
`npm run dev -- -p 3100` if the container already owns `:3000`. Narrative engine tests:
`node --test lib/narrative/*.test.ts`.

## 5. Reset and recovery

### Restart a single service

```sh
docker compose restart vector          # plain restart, e.g. after a config edit
docker compose up -d --build mock-lti  # rebuild + recreate after a code change
```

Restarting is safe mid-stream: every consumer resumes from its committed offsets, so no
events within the topic's retention window are lost. ARGUS and CASSANDRA additionally
reload their baselines from their volumes, so they come back **warm** — a restart is not a
re-warm-up.

fusion is the exception, and deliberately so: its state is not persisted, because a decayed
threat picture with a 2-minute half-life re-forms from the live stream faster than it could
be usefully restored. Expect `/threat` to read `normal` for a minute or two after a fusion
restart.

### Full reset

```sh
docker compose down -v
docker compose up -d --build
python training/seed_history.py    # ← do not skip this
```

`down -v` removes the containers **and all four named volumes**, which destroys:

- all `guardian-traffic-*` / `guardian-scores-*` / `guardian-alerts-*` indices,
- all OpenSearch Dashboards state — index patterns, hand-built visualizations, and anything
  else not committed to `infra/dashboards/*.ndjson`,
- the OpenSearch security config, including any password set at first start (the next start
  re-initializes from `OPENSEARCH_ADMIN_PASSWORD`),
- all queued Redpanda messages and consumer-group offsets,
- ⚠ **ARGUS's learned baselines** (`argus-data`) — warm-up starts over (15 buckets/entity),
- ⚠ **CASSANDRA's learned baselines and open CUSUM excursions** (`cassandra-data`) —
  warm-up starts over (30 observed minutes/payer).

**The last two are the ones people forget.** After a `down -v` the detectors are cold and
will not alert on anything for the next ~30 minutes of live traffic, which looks exactly
like a broken pipeline. Re-seed with `python training/seed_history.py` (warms both) or
`python training/seed_baseline.py` (ARGUS only), or wait it out.

Container images are kept, so the restart is fast. On the way back up, `opensearch-init`
re-applies the templates, ISM policy, monitor, channel and dashboard bundles automatically
— which is what makes a clean-checkout demo reproducible.

### Re-run the bootstrap only

The init job is idempotent — safe to re-run any time, e.g. after editing a template or the
policy, or if it previously failed:

```sh
docker compose up opensearch-init
docker compose logs opensearch-init
```

## 6. Warm-up and seeding

A detector must never alert against a baseline it does not have. Both baseline-learning
detectors therefore enforce a warm-up, and both are silent until it completes:

| Detector | Requirement | Exposed at | On a cold stack |
|---|---|---|---|
| ARGUS | `WARMUP_BUCKETS` (15) one-minute buckets per entity | `:8002/health` → `warming_up`, `buckets_observed` | silent ~15 min |
| CASSANDRA | `warmup_buckets` (30) observed minutes per payer | `:8005/health` → `payers_warm`, `warming_up` | silent ~30 min |

SENTINEL needs no warm-up (it ships a pre-trained model); fusion's state re-forms in
minutes.

Two bootstrap paths:

1. **Queue replay (automatic).** CASSANDRA and ARGUS use `auto_offset_reset=earliest`, so a
   fresh consumer group replays the queue's ~6 h retention window. If the stack has been
   running, real history warms them with no action from you. (SENTINEL and fusion use
   `latest` on purpose — SENTINEL would otherwise page stale, hours-old alerts on boot, and
   fusion would light up today's picture with attacks that ended this morning.)
2. **Seeding (fresh stack, empty queue).**

   ```sh
   python training/seed_history.py    # 40 backdated minutes → warms CASSANDRA *and* ARGUS
   python training/seed_baseline.py   # 20 backdated minutes → warms ARGUS only
   ```

   Host Python 3.10+, stdlib only (no `pip install` — deliberately, since host Python 3.14
   cannot build aiokafka wheels). Both POST backdated benign events to capture-agent's
   `/ingest`, i.e. through the **real pipeline**, so the baselines built are exactly the
   ones live traffic would have built. Options: `--minutes`, `--events-per-minute`, `--url`.

**Both seeders are benign-only, on purpose.** Seeding attack traffic would teach the
baselines that attacks are normal — the exact failure a warm-up exists to prevent. Do not
"improve" them by seeding attacks.

Buckets finalize ~1 minute behind event time, so allow ~2 minutes after seeding (with the
live generator running) before `warming_up` flips to `false`.

## 7. Troubleshooting

| Symptom | Likely cause | Check / fix |
|---|---|---|
| A service is `unhealthy` or restart-looping in `docker compose ps` | Varies | `docker compose logs <service>` for the specific error, then the matching row below. |
| A service reports `"status": "degraded"` | Its Kafka client isn't connected to Redpanda | Normal for the first ~30 s of a boot. If it persists: `docker compose ps redpanda` — the broker is the problem, not the service. |
| **No alerts, ever — but everything is healthy** | **Warm-up not complete.** By far the most common false alarm. | `curl :8002/health` (`warming_up`) and `:8005/health` (`payers_warm`). Fix: `python training/seed_history.py` ([section 6](#6-warm-up-and-seeding)). Also confirm `ATTACK_MODE` ≠ `off`. |
| No alerts after a `docker compose down -v` | The `argus-data` / `cassandra-data` volumes were wiped with everything else | Same as above — re-seed. This is expected behaviour, not a bug. |
| OpenSearch exits or restart-loops at boot; logs say `max virtual memory areas vm.max_map_count [65530] is too low` | Docker VM kernel limit (common on Windows/WSL2) | `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`, then `docker compose up -d`. Persist via `%UserProfile%\.wslconfig`: `[wsl2]` / `kernelCommandLine = sysctl.vm.max_map_count=262144`, then `wsl --shutdown`. Native Linux: `sudo sysctl -w vm.max_map_count=262144`. |
| OpenSearch or Redpanda killed / flapping under load | Docker VM out of memory | Allocate ≥ 8 GB to the Docker VM; the stack needs ~4–5 GB with the full detection triad. |
| Dashboards login rejects `admin` + your `.env` password | Password in `.env` changed **after** the OpenSearch data volume was created | Log in with the original password, or full wipe: `docker compose down -v && docker compose up -d` (destroys data *and baselines* — [section 5](#5-reset-and-recovery)). |
| Dashboards shows "OpenSearch Dashboards server is not ready yet" | OpenSearch still within its ~60 s start period, or unhealthy | Wait for `docker compose ps` to show opensearch healthy; if it never does, `docker compose logs opensearch`. |
| No documents arriving in Discover | Any hop of the pipeline | Widen Discover's time range first. Then walk the hops ([4.4](#44-checking-pipeline-health)). The first silent hop is the broken one. |
| Vector logs show 401/auth or TLS errors against OpenSearch | Vector's `OPENSEARCH_ADMIN_PASSWORD` doesn't match the cluster's actual password | Align the value ([section 2](#2-configuration)), then `docker compose up -d --force-recreate vector`. |
| `docker compose up` fails with `port is already allocated` | Another process holds one of 8000–8006, 5601, 8080, 9200, 19092, 9644 | Windows: `netstat -ano \| findstr :8004` then stop that process; Linux/macOS: `lsof -i :8004`. |
| Index template or ISM policy missing (404) | `opensearch-init` failed or was interrupted | `docker compose logs opensearch-init`, fix the cause (usually OpenSearch not up or wrong password), re-run: `docker compose up opensearch-init`. |
| Events on the topic but indices stay empty | Vector down or mis-consuming | `docker compose logs -f vector`; `rpk group describe guardian-vector` (no members = not connected; growing lag = stuck). |
| No documents in `guardian-scores-*` | A scorer isn't consuming, or no finalized buckets yet | `/health` (consumer connected?) and `/stats` (`buckets_finalized` increasing?) on 8002/8004/8005. Buckets finalize ~1 min behind event time; a silent stream also flushes after ~75 s. |
| SENTINEL alerts but ARGUS doesn't (in `log_attack`) | **Working as designed** | `log_attack` injects malicious log *content* at normal rates. It is built to be invisible to rate/error detectors — that is the whole point of SENTINEL. Not a bug. |
| CASSANDRA never fires in `slow_exfil` | Payer not warm, or not enough elapsed time | `:8005/health` → `payers_warm`. Then watch `:8005/drift/top` — `cusum_volume` and `buckets_elevated` should climb for `wallet-user-0001`. Median detection delay is **~9 minutes**, tail to ~25: be patient before retuning. |
| fusion stuck at `normal` during an obvious attack | Scores below the contribution floor, or stale | `curl :8006/threat` → `counters`: `scores_below_floor` climbing means anomalous scores are arriving with `features.event_count < MIN_CONTRIB_EVENTS` (10) — that floor exists to reject ARGUS's benign small-bucket noise. `scores_stale` climbing means score docs are older than `STALE_AFTER_SECONDS` (replayed backlog). |
| fusion reads `normal` right after a restart | Expected — its state is in-memory by design | It re-forms from the live score stream within ~2 minutes. |
| One attack produced a flood of Slack messages | Dedup window misconfigured | Check `ALERT_DEDUP_SECONDS` (default 300). Distinct entities/types alert separately by design; per-window alert volume is additionally capped inside each scorer (`MAX_ALERTS_PER_WINDOW`). |
| Alerts in `guardian-alerts-*` but nothing in Slack | Log-only mode (no webhook) or delivery failing | `:8003/health` shows `mode`; `/stats` shows `delivered` vs `delivery_failures`; `docker compose logs alerting` has the formatted alerts in log-only mode. |
| `guardian-error-rate-spike` monitor never fires | Threshold not reached (by design at default rates), or channel broken | Alerting → Monitors in Dashboards shows last run/result. Test the channel: `curl -X POST http://localhost:8003/notify -H 'Content-Type: application/json' -d '{"alert":{"type":"test","summary":"manual test"}}'`. |

## 8. Retraining SENTINEL

SENTINEL is the only detector with a trained model artifact. It is **committed**
(`services/sentinel/model/sentinel_xgb.json` + `metadata.json`) and deterministic by
construction — fixed RNG seed, single-threaded hist training — so a rerun produces a
byte-identical file and the Docker build needs no network, no datasets, and no training
step. The service refuses to boot if the artifact's feature order or classes disagree with
the code, so a stale model fails loudly rather than scoring silently wrong.

```sh
pip install xgboost drain3 numpy pydantic-settings   # host Python
python training/train_sentinel.py                    # regenerates services/sentinel/model/
python -m pytest services/sentinel/tests -q          # revalidate before committing
docker compose up -d --build sentinel                # ship it
```

`train_sentinel.py` takes `--windows` (default 9000), `--seed` (1337) and `--out`.

**Retrain when** `app/features.FEATURE_NAMES` changes, the rule bands in `app/rules.py`
change, or the generator's log families change. That last one is the trap: the model is
trained on labeled windows generated from the pinned gateway log-line families, so editing
`services/mock-lti/app/generator.py`'s log lines without retraining leaves SENTINEL
classifying against templates that no longer occur. The generator carries a matching
warning.

Labels come from the rule engine's confidence bands (`app.rules.window_rule_level`), not
from hand-labeling, so the benign/suspicious/malicious classes are reproducible from code.

The other detectors need no training: ARGUS and CASSANDRA are unsupervised baseline
profilers that learn "normal" from the traffic they observe (that is what the warm-up
*is*), and fusion is a deterministic state machine.

## 9. Scaling notes

The MVP is single-node and demo-scaled on purpose. What would have to change:

- **The scorers are single-instance by design.** ARGUS, SENTINEL and CASSANDRA hold
  per-entity state (baselines, CUSUM charts, windows) in memory, and neither capture-agent
  nor Vector produces with a partition key — events land on partitions round-robin. Adding
  a second replica to the same consumer group would therefore split one entity's events
  across two instances, each learning half a baseline. To scale out horizontally, produce
  keyed by entity (payer / client_ip) first, so an entity's events always land on the same
  partition; only then does adding replicas up to the partition count (3) work.
- **fusion must stay a singleton.** It maintains one global threat state; two instances
  would each see half the scores and both be wrong.
- **OpenSearch: 1 shard / 0 replicas, 512 MB heap, single node.** Fine for demo volumes.
  Production sizing means a real multi-node cluster with replicas, a larger heap, and
  retention math done against actual ingest rate — out of scope for the MVP.
- **Redpanda: 3 partitions, replication 1, ~6 h retention, 1 GB.** The queue is a transit
  buffer, not a store. Replication 1 means a broker loss loses the buffer.
- **Throughput headroom.** The generator's default 10 events/s is throttled for laptop dev;
  LTI's production figure is 5M+ transactions/day (~58/s average). Raise
  `EVENTS_PER_SECOND` to load-test — the detection layer's per-minute bucketing cost grows
  with *entities*, not events, so event rate is the cheaper axis to push. Formal load
  testing is Week 4.

## 10. End-to-end verification checklist

A repeatable evidence run proving the system works from generator to fused threat level.
Execute top to bottom on a running, **warmed** stack; every step states its pass condition.

**Pipeline (Week 1):**

1. **All services healthy.** `docker compose ps` — all twelve long-running services
   `running (healthy)`; `opensearch-init` `Exited (0)`.
2. **Bootstrap applied.** `docker compose logs opensearch-init` ends with `[init] done`.
3. **Generator emitting.** `curl -s http://localhost:8000/admin/generator/status` twice,
   ~10 s apart — `counters.events_emitted.total` increases.
4. **Events on the queue.**
   `docker compose exec redpanda rpk topic consume guardian.telemetry.raw -n 5` prints 5
   JSON envelopes matching [architecture.md](architecture.md#event-schema).
5. **Consumer keeping up.** `rpk group describe guardian-vector` — active member, total lag
   near zero across two runs.
6. **Documents landing.** `_count` on `guardian-traffic-*` twice, ~10 s apart — increases;
   `_cat/indices/guardian-traffic-*?v` shows today's index.
7. **Attack traffic labeled.** Discover, filter `security.is_attack: true` — documents
   appear with `security.attack_pattern` set.
8. **Retention attached.** `_plugins/_ism/explain/guardian-traffic-*` shows policy
   `guardian-traffic-ilm` on every index.

**Detection (Week 2):**

9. **ARGUS warm.** `curl -s http://localhost:8002/health` — `consumer_connected: true`,
   `warming_up: false`. (If `true`: seed, [section 6](#6-warm-up-and-seeding).)
10. **Scores flowing.** `_count` on `guardian-scores-*` twice, ~90 s apart — increases.
    `:8002/stats` shows `buckets_finalized` and `scores_emitted` climbing.
11. **A burst is detected.** With `attack_mode` `burst` or `mixed`, within ~2 minutes:
    `curl -sk -u 'admin:Guardian!Lti2026' 'https://localhost:9200/guardian-alerts-*/_search?q=alert.source:argus&size=1&sort=@timestamp:desc&pretty'`
    returns a `rate_spike` alert naming the flooding entity.
12. **Dedup enforced.** `docker compose logs alerting` shows at most **one** delivered alert
    per `(entity, type)` per 5-minute window; `:8003/stats` shows `suppressed` climbing
    while a burst repeats.
13. **Benign traffic stays quiet.** Set `{"attack_mode": "off"}`, wait ~10 minutes:
    alerting's `sent` stops increasing (scores keep flowing — they just aren't anomalous).
    Restore `mixed`.

**The triad and fusion (Week 3):**

14. **All three scorers healthy and writing.** `:8004/health` → `model_loaded: true`;
    `:8005/health` → `payers_warm > 0`. Then confirm all four models are landing in the
    index:

    ```sh
    curl -sk -u 'admin:Guardian!Lti2026' \
      'https://localhost:9200/guardian-scores-*/_search?size=0&pretty' \
      -H 'Content-Type: application/json' \
      -d '{"aggs":{"by_model":{"terms":{"field":"score.model"}}}}'
    ```

    The `by_model` buckets include `argus`, `sentinel`, `cassandra` and `guardian`.
15. **SENTINEL catches what ARGUS cannot.** Set `{"attack_mode": "log_attack"}`. Within
    ~2 minutes a `log_classification` alert (`alert.source: sentinel`) names an attacker IP
    — **and no ARGUS alert fires for it.** Both halves are the pass condition: the second
    is what proves SENTINEL covers a real blind spot rather than duplicating ARGUS.
16. **CASSANDRA catches the slow exfil.** Set `{"attack_mode": "slow_exfil"}` on a warm
    stack. `:8005/drift/top` shows `cusum_volume` / `buckets_elevated` climbing for
    `wallet-user-0001` while benign payers stay near zero; a `slow_exfiltration` alert
    follows (median ~9 min, tail ~25 — do not call it a failure early).
17. **fusion escalates and corroborates.** During `mixed`, `curl -s
    http://localhost:8006/threat` shows `threat_level` at `elevated`/`critical`,
    `contributors` naming the models currently firing, and `top_entities` listing the
    entities to investigate. An entity flagged by two models shows `corroborated: true` —
    the corroboration boost is what pushes it past `critical_up` where one model alone
    would not.
18. **A level change alerts.** Every transition raises `threat_level_change`
    (`alert.source: guardian`) — visible in `docker compose logs alerting` and in
    `guardian-alerts-*`. `recent_transitions` in `/threat` carries the history.
19. **The picture heals.** Set `{"attack_mode": "off"}`. Within ~3–5 minutes `/threat`
    decays back to `threat_level: "normal"` on its own (2-minute contribution half-life)
    and a `normal` transition alert fires. Restore `mixed`.
20. **Dashboards populated.** Dashboards (Global tenant) → **Guardian Detection**:
    anomaly-score line moving, alerts-by-type showing the Week-3 types alongside ARGUS's,
    alert feed listing recent summaries. Then **Guardian Threat Fusion**: current threat
    level, per-model contributions, the SENTINEL and CASSANDRA panels, and any corroborated
    entities.
