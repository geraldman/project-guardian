# GUARDIAN User Manual

This manual is for anyone evaluating or operating GUARDIAN from a clean checkout: it
covers starting the stack, warming the detectors, driving each attack, and reading what
comes out. Deeper operational topics (configuration reference, tuning, retraining,
recovery, troubleshooting) live in the [Admin Manual](admin_manual.md); the system design
and cross-service contracts live in [architecture.md](architecture.md).

## 1. What GUARDIAN is

GUARDIAN is a self-contained SOC/SIEM pipeline for transaction telemetry. It ships with
its own **digital twin**: a synthetic transaction-routing API (`mock-lti`) that generates
realistic traffic — including deliberate attack patterns — inside the same Docker
network. Every event flows through the full pipeline:

```
mock-lti  →  capture-agent  →  Redpanda  →  Vector  →  OpenSearch  →  OpenSearch Dashboards
(traffic)    (ingestion)       (queue)      (normalize)  (storage)     (analysis UI)
                                                │
                                                │  guardian.telemetry.normalized
                                                ▼
                                     ┌──────────┼──────────┐
                                     ▼          ▼          ▼
                                  ARGUS     SENTINEL   CASSANDRA      the detection triad
                                     └──────────┼──────────┘
                                                ▼
                                        guardian.scores  →  fusion  →  GET /threat
                                        guardian.alerts       │
                                                │             │
                                                ▼             ▼
                                            alerting  →  Slack / Discord / log
                                          (5-min dedup)
```

Three independent scorers read the same normalized stream. Each one exists because the
others structurally cannot see its attack:

| Detector | Catches | Blind to |
|---|---|---|
| **ARGUS** | rate spikes, malformed payloads, error-ratio jumps — anything loud within one minute | anything that stays under a per-minute threshold |
| **SENTINEL** | malicious log *content* (SQLi, path traversal, credential stuffing, scanner probes) arriving at perfectly normal rates | volume; a benign burst must not trip it, and does not |
| **CASSANDRA** | slow, persistent per-payer drift — the low-and-slow exfiltration that is locally normal and only abnormal cumulatively | anything that happens in a single minute |

**fusion** watches all three and maintains one decayed threat state. Its signature move is
the **corroboration boost**: when two models independently flag the same entity (say ARGUS
sees a rate spike from an IP while SENTINEL sees SQL injection in that IP's log lines), the
entity scores higher than either model alone would justify. One scorer firing means
*elevated*; independent agreement means *critical*.

Because the traffic source is bundled, a single `docker compose up` demonstrates the
entire system with no external infrastructure and no real data.

## 2. Prerequisites

| Requirement | Detail |
|---|---|
| Docker Desktop | A recent version with Docker Compose v2.20 or later (the root compose file uses the `include` directive). Works on Windows (WSL2), macOS, and Linux. |
| RAM | Allocate **at least 8 GB** to the Docker VM (Docker Desktop → Settings → Resources). The stack uses roughly 4–5 GB under load; OpenSearch (512 MB JVM heap plus off-heap usage) and Redpanda (1 GB reserved) are the two big consumers, and the detection triad adds ~600 MB between them. |
| Disk | A few GB free for container images and indexed data. |
| Python 3.10+ on the host | Only for the warm-up seeders in `training/` — stdlib only, no `pip install` needed. |
| Git | To clone the repository. |

Shell note: command examples use POSIX shell syntax (`\` line continuations, single
quotes). Run them from Git Bash, WSL, or any Linux/macOS terminal. In Windows
PowerShell, use `curl.exe` (plain `curl` is an alias for `Invoke-WebRequest`) and adjust
quoting.

## 3. Getting started

Clone and start:

```sh
git clone https://github.com/geraldman/project-guardian.git
cd project-guardian
docker compose up -d --build
```

Run compose from the repository root; the thin root compose file includes the canonical
stack definition in `infra/docker-compose.yml`.

Optional: to override the default admin password, create a `.env` file at the repo root
**before the first start** (see the [Admin Manual](admin_manual.md#2-configuration)
for why it must be set before first start):

```
OPENSEARCH_ADMIN_PASSWORD=YourStrongPassword1!
```

### What to expect at startup

Startup is health-check gated, so services come up in dependency order:

1. **Redpanda** (queue) — healthy after ~20–30 s.
2. **capture-agent**, then **mock-lti** — a few seconds each once Redpanda is healthy.
3. **The detection services** (ARGUS, SENTINEL, CASSANDRA, fusion, alerting) — they also
   wait on Redpanda, and each comes up within ~15 s of it.
4. **OpenSearch** — the slow one: its healthcheck allows a **~60 s start period** and it
   can take 1–2 minutes on first boot.
5. **OpenSearch Dashboards**, **Vector**, and the one-shot **opensearch-init** bootstrap
   job — after OpenSearch reports healthy.

The first run builds seven service images and pulls the infrastructure images, which adds
several minutes depending on your network. After images exist locally, expect the whole
stack to be healthy in roughly **2–3 minutes**.

Confirm everything is up:

```sh
docker compose ps
```

All twelve long-running services should show `running` (with `healthy` where a healthcheck
is defined). `opensearch-init` runs once and exits — an `Exited (0)` status for it is
normal.

## 4. Warming the detectors

**Do this before you try to demo a detection.** On a fresh stack the detectors are
deliberately silent, and they will stay silent for the first half hour of real time.

A detector must never alert against a baseline it does not have — otherwise the first
minute of any deployment is one giant false positive. So each scorer enforces a warm-up:

| Detector | Needs | Why |
|---|---|---|
| **ARGUS** | 15 one-minute buckets per entity (`WARMUP_BUCKETS`) | it z-scores each entity against that entity's own history; with two buckets of history, every third bucket is a 3σ outlier |
| **CASSANDRA** | 30 observed minutes per payer (`warmup_buckets`) | its CUSUM charts need a calibrated per-payer mean/σ before "cumulative drift" means anything |
| **SENTINEL** | nothing | it ships a pre-trained model and classifies log content from the first window |
| **fusion** | nothing | it re-forms its picture from the live score stream within a couple of minutes |

The warm-up is compressed for the demo (production framing is a multi-day rolling window
per entity). You can wait it out with live traffic, or fast-forward it by replaying
backdated benign traffic through the real pipeline:

```sh
python training/seed_history.py
```

Host Python 3.10+, stdlib only. It POSTs 40 backdated minutes of benign events to
capture-agent's `/ingest` — the same path live traffic takes (raw topic → Vector →
normalized topic → the scorers), so the baselines the detectors build are exactly the ones
they would have built by running for 40 minutes. It warms **CASSANDRA and ARGUS together**
(ARGUS's 15-bucket requirement is a subset of CASSANDRA's 30).

There is also `python training/seed_baseline.py`, which replays 20 minutes and warms ARGUS
only. `seed_history.py` supersedes it for a cold start; `seed_baseline.py` is the lighter
option when you only care about ARGUS.

Both seeders take options: `--minutes`, `--events-per-minute`, `--url`.

**Both are benign-only on purpose.** Seeding attack traffic would teach the baselines that
attacks are normal — which is exactly the failure mode a warm-up is supposed to prevent.

Buckets finalize about a minute behind event time, so give it ~2 minutes with the live
generator running, then confirm:

```sh
curl -s http://localhost:8002/health    # ARGUS
curl -s http://localhost:8005/health    # CASSANDRA
```

Real responses on a warm stack (verified live):

```json
{"status":"ok","service":"argus","consumer_connected":true,"warming_up":false,
 "buckets_observed":499,"warmup_buckets":15,"model_fitted":true, ...}
```

```json
{"status":"ok","service":"cassandra","consumer_connected":true,"warming_up":false,
 "payers_tracked":700,"payers_warm":700,"warmup_buckets":30, ...}
```

`warming_up: false` on ARGUS and `payers_warm > 0` on CASSANDRA mean detection is live.

## 5. Web interfaces

| Service | URL | What it's for |
|---|---|---|
| OpenSearch Dashboards | http://localhost:5601 | The SIEM view: Discover, the Guardian Traffic Overview and Guardian Detection dashboards |
| Redpanda Console | http://localhost:8080 | Watch the queue (topics `guardian.telemetry.raw`, `.normalized`, `guardian.scores`, `guardian.alerts`) |
| mock-lti API | http://localhost:8000 | Synthetic traffic + attack generator — interactive API docs at `/docs` |
| capture-agent API | http://localhost:8001 | Ingestion boundary — `/docs` |
| ARGUS | http://localhost:8002 | Rate/payload scorer — `/health`, `/stats`, `/baseline/*` |
| alerting | http://localhost:8003 | Alert dedup + webhook delivery — `/health`, `/stats` |
| SENTINEL | http://localhost:8004 | Log classifier — `/health`, `/stats`, `/templates` |
| CASSANDRA | http://localhost:8005 | Slow-exfil detector — `/health`, `/stats`, `/drift/top`, `/baseline/payer/{id}` |
| fusion | http://localhost:8006 | **Unified threat picture** — `/health`, `/threat` |

**Dashboards login:** username `admin`, password is the value of
`OPENSEARCH_ADMIN_PASSWORD` (default `Guardian!Lti2026` if you did not override it).
If Dashboards asks you to select a tenant after login, choose **Global** so you see the
shared saved objects.

## 6. Exploring the data

### Discover

Events are indexed into **daily indices** named `guardian-traffic-YYYY.MM.DD` (retained
for 7 days — see the [Admin Manual](admin_manual.md#43-index-lifecycle)). To browse
them, open Dashboards → **Discover**.

All three index patterns (`guardian-traffic-*`, `guardian-scores-*`, `guardian-alerts-*`)
ship in the committed saved-objects bundles and are imported automatically at startup into
the **Global** tenant — no manual setup. If one is missing, check the bootstrap job:
`docker compose logs opensearch-init`.

With the time range set to "Last 15 minutes" you should see a steady stream of
documents (the generator's default rate is 10 events/second).

### The Guardian Traffic Overview dashboard

The single pane of glass for raw traffic: volume by event type, error rate over time,
channel breakdown, attack patterns, and event counters.

<!-- TODO: screenshot — add during the Week 5 evidence pass. -->

### The Guardian Detection dashboard

What the detectors make of that traffic:

- **Anomaly score over time** — the max `score.anomaly_score` per entity type. Benign
  traffic hugs zero; attacks spike it. (The visualization is titled for ARGUS but is not
  filtered by `score.model`, so since Week 3 it reflects the highest score any scorer
  assigned — including fusion's own `guardian` documents.)
- **Alerts over time by severity** and **Alerts by type** — what fired, when. Since Week 3
  `alert.type` can be any of `rate_spike`, `payload_anomaly`, `error_ratio_spike`,
  `multivariate_outlier`, `error_rate_spike`, `log_classification` (SENTINEL),
  `slow_exfiltration` (CASSANDRA), or `threat_level_change` (fusion).
- **Alert feed** — the most recent alert summaries in plain English, e.g.
  *"Request rate for client_ip 10.2.14.9 is 14.1x the cohort baseline."*

Empty at first? That is the warm-up ([section 4](#4-warming-the-detectors)), not a fault.

<!-- TODO: screenshot — add during the Week 5 evidence pass. -->

### How traffic appears in the raw index

| `event.type` | What it is | Telltale fields |
|---|---|---|
| `transaction` | Normal synthetic business traffic — and also the carrier for `slow_exfil` and `log_attack`, which hide inside ordinary-looking transactions | `security.is_attack` distinguishes them |
| `burst_spike` | Attack: sudden traffic burst | `security.attack_pattern: burst` |
| `malformed_payload` | Attack: structurally bad transaction data (negative amounts, junk currency, missing payer) | `security.attack_pattern: malformed`, `security.is_malformed: true`, `transaction.status: malformed` |

Two fields matter most when reading the data:

- **`security.is_attack`** — the ground-truth attack label. Filter Discover on
  `security.is_attack: true` to see only injected attack traffic;
  `security.attack_pattern` then tells you which of `burst` / `malformed` / `slow_exfil` /
  `log_attack` it was.
- **`log.message`** — the rendered API-gateway log line. This is SENTINEL's entire input,
  and the *only* place a `log_attack` is visible. Filter on
  `security.attack_pattern: log_attack` and read the `log.message` column to see the SQL
  injection or traversal payload sitting inside an otherwise unremarkable transaction.

Note that malformed traffic is still valid JSON end to end — malformation is expressed
in field *values*, so bad data flows through the pipeline and surfaces in the dashboard
instead of being dropped. The full field mapping is in
[architecture.md](architecture.md#normalized-fields).

## 7. Driving the attacks

The generator is controlled at runtime through its admin API — no restart needed:

```sh
# What is it doing right now?
curl -s http://localhost:8000/admin/generator/status

# Switch attack mode and/or rate (takes effect immediately)
curl -s -X POST http://localhost:8000/admin/generator/config \
  -H 'Content-Type: application/json' \
  -d '{"attack_mode": "burst", "events_per_second": 50}'
```

Valid `attack_mode` values: `off`, `burst`, `malformed`, `mixed` (default), `slow_exfil`,
`log_attack`. Anything else is rejected with a 422.

`GET /admin/generator/status` returns the effective config plus counters (verified live):

```json
{
  "implemented": true,
  "config": {"events_per_second": 10.0, "attack_mode": "mixed",
             "capture_ingest_url": "http://capture-agent:8001/ingest"},
  "counters": {
    "events_emitted": {"total": 312115, "transaction": 143306,
                       "burst_spike": 158218, "malformed_payload": 10591},
    "attacks_injected": {"burst": 158218, "malformed": 10591,
                         "slow_exfil": 971, "log_attack": 10265},
    "telemetry": {"sent": 312001, "failed": 113}
  },
  "uptime_seconds": 18175.0
}
```

Runtime changes do not survive a container restart — the service falls back to its
`EVENTS_PER_SECOND` / `ATTACK_MODE` environment defaults.

Below, what each mode does and what *should* happen. Detection is not instant: ARGUS,
SENTINEL and CASSANDRA all work on 1-minute tumbling windows that finalize about a minute
behind event time, so budget **1–2 minutes** from injection to alert (CASSANDRA is
deliberately slower — see below).

### `burst` → ARGUS

10–20× rate spikes lasting 5–10 s, fired every 60–120 s from ~4 attacker IPs.

**Expect:** within ~2 minutes, a `rate_spike` alert naming the flooding IP, and fusion's
threat level moving to `elevated` (a big enough burst reaches `critical`).

```sh
curl -s -X POST http://localhost:8000/admin/generator/config \
  -H 'Content-Type: application/json' -d '{"attack_mode": "burst"}'

docker compose logs -f alerting        # the alert, in plain English
curl -s http://localhost:8006/threat   # threat_level: elevated
```

You get **one** alert per (entity, type) per 5-minute window however long the burst lasts
— that is the alerting service's dedup working; the suppressed count is reported on the
next alert for the same key.

### `malformed` → ARGUS

~8% of events carry bad field *values* (negative amount, junk currency, missing payer)
with `raw_payload_valid: false`.

**Expect:** `payload_anomaly` and/or `error_ratio_spike` alerts from ARGUS, a visible jump
in the Traffic Overview dashboard's error-rate chart, and `security.is_malformed: true`
documents in Discover.

### `log_attack` → SENTINEL

SQL injection, path traversal, credential-stuffing auth failures, and scanner probes — in
the **log line only**, at normal traffic rates, spread across ~20 external-looking IPs.

**Expect:** `log_classification` alerts (`alert.source: sentinel`) naming the attacker IP,
within ~1–2 minutes. Crucially, expect **ARGUS to stay quiet**: the traffic rate never
moves and the payment status distribution is unchanged, so there is nothing for a rate or
error-ratio detector to see. This mode is the proof that SENTINEL covers a real blind spot.

```sh
curl -s -X POST http://localhost:8000/admin/generator/config \
  -H 'Content-Type: application/json' -d '{"attack_mode": "log_attack"}'

# What SENTINEL is mining out of the log lines
curl -s http://localhost:8004/stats
curl -s http://localhost:8004/templates
```

`GET /stats` shows `templates_mined` and `alerts_emitted` climbing; `/templates` shows the
live Drain3 template set, where the attack templates appear alongside the benign
route/balance/status/settlement families.

### `slow_exfil` → CASSANDRA

One designated payer (`wallet-user-0001` by default) receives a steady trickle of ~2
*extra* transactions per minute at ~1.8× normal amounts, layered on top of its ordinary
traffic.

This is the hardest mode, and the most interesting. Two extra events a minute is nothing:
it stays far under ARGUS's minimum-volume alert floor, and the elevated *amount* is not
even an ARGUS scoring feature. Per minute, the traffic is normal. It is only abnormal
**cumulatively** — which is precisely what CASSANDRA's CUSUM charts integrate.

**Expect:** a `slow_exfiltration` alert on the exfil payer — but **not quickly**. CASSANDRA
requires sustained drift (`min_drift_buckets`, default 6) before it will accuse anyone.
Measured detection delay against the shipped defaults is a **median of ~9 minutes, with a
tail to ~25**. That latency is the deliberate price of a low false-alarm rate; see the ARL
trade-off table in [services/cassandra/README.md](../services/cassandra/README.md).

Watch it build rather than waiting blind:

```sh
curl -s -X POST http://localhost:8000/admin/generator/config \
  -H 'Content-Type: application/json' -d '{"attack_mode": "slow_exfil"}'

# The payers closest to (or over) the alarm bar — re-run every minute
curl -s http://localhost:8005/drift/top

# One payer's charts and baseline in full
curl -s http://localhost:8005/baseline/payer/wallet-user-0001
```

`/drift/top` (verified live) returns the leaderboard — watch `cusum_volume` and
`buckets_elevated` climb for `wallet-user-0001` while benign payers hover near zero:

```json
{"top": [
  {"payer_id":"wallet-user-0489","cusum_volume":0.0,"cusum_amount":4.48,
   "buckets_elevated":2,"warming_up":false,"buckets_observed":298},
  {"payer_id":"merchant-0159","cusum_volume":2.25,"cusum_amount":3.16,
   "buckets_elevated":2,"warming_up":false,"buckets_observed":298}
]}
```

**If CASSANDRA never fires:** check `payers_warm` on `:8005/health` first. An unwarmed
payer cannot alarm by design.

### `mixed` (default) → everything

All four behaviours at once. This is the mode to leave running for a general demo: ARGUS
alerts on the bursts, SENTINEL on the log content, CASSANDRA eventually on the exfil payer,
and fusion escalates as they stack up.

### `off` → nobody

Benign traffic only. This is the **quiet-baseline check**, and it is as important as any
detection: leave it for ~10 minutes and alerting's `sent` counter should stop climbing.
Scores keep flowing (the detectors are still scoring every bucket) — they just aren't
anomalous. A system that alerts on benign traffic is worse than no system.

## 8. Reading the threat picture

`GET :8006/threat` is the fastest answer to "is anything happening right now". It is the
whole fused state in one document (verified live, mid-attack):

```json
{
  "threat_level": "elevated",
  "anomaly_score": 0.6554,
  "is_anomalous": true,
  "level_since": "2026-07-13T08:13:35Z",
  "contributors": {"sentinel": 0.7269, "argus": 0.9066},
  "corroboration": 1,
  "reasons": ["argus:rate_spike", "sentinel:sqli_probe"],
  "top_entities": [
    {"entity_type": "client_ip", "entity_id": "10.0.54.173", "score": 0.4986,
     "models": {"argus": 0.9066}, "corroborated": false,
     "reasons": ["argus:rate_spike"], "last_update": "2026-07-13T08:15:14Z"},
    {"entity_type": "client_ip", "entity_id": "45.148.10.17", "score": 0.4361,
     "models": {"sentinel": 0.7269}, "corroborated": false,
     "reasons": ["sentinel:sqli_probe"], "last_update": "2026-07-13T08:14:36Z"}
  ],
  "recent_transitions": [
    {"at": "2026-07-13T08:02:12Z", "from": "elevated", "to": "critical", "score": 0.7503},
    {"at": "2026-07-13T08:08:20Z", "from": "elevated", "to": "normal", "score": 0.2494},
    {"at": "2026-07-13T08:13:35Z", "from": "normal", "to": "elevated", "score": 0.7241}
  ],
  "entities_tracked": 23,
  "counters": {"scores_consumed": 1579, "scores_folded": 76, "alerts_emitted": 5},
  "config": {"weights": {"argus": 0.55, "sentinel": 0.6, "cassandra": 0.5},
             "half_life_seconds": 120.0,
             "thresholds": {"elevated_up": 0.4, "critical_up": 0.75}}
}
```

How to read it:

- **`threat_level`** — `normal` / `elevated` / `critical`, with hysteresis (separate up and
  down thresholds) so a score hovering at a boundary cannot flap the level. In the example
  above, two attacker IPs are lit and the level has been `elevated` since 08:13:35.
- **`contributors`** — which models are currently holding a contribution, and how strong.
  Here ARGUS (a burst) and SENTINEL (an SQLi probe) are both active.
- **`corroboration`** — how many models agree on the *worst* entity. `1` means the models
  are seeing different entities (two separate attacks). A `2` here means one entity is
  being flagged by two independent detectors, which is what pushes the score past
  `critical_up`.
- **`top_entities`** — who to actually go look at, worst first. `corroborated: true` marks
  an entity that more than one detector agrees on. These are your investigation targets.
- **`recent_transitions`** — the level history, so you can see an attack start and decay.

**The picture heals itself.** Contributions decay with a 2-minute half-life, so once an
attack stops, the level walks back down to `normal` on its own within roughly 3–5 minutes.
If the level is still `elevated`, something is still happening.

Every level transition also raises a `threat_level_change` alert, so a demo can be driven
entirely off the alerting log.

## 9. Interpreting alerts

Alerts arrive in `docker compose logs alerting` (the default log-only mode), in Slack or
Discord if a webhook is configured, and always in `guardian-alerts-*`.

| `alert.type` | Source | Means |
|---|---|---|
| `rate_spike` | ARGUS | an entity's request rate is far above its own (or its cohort's) baseline |
| `payload_anomaly` | ARGUS | mean payload size for an entity jumped |
| `error_ratio_spike` | ARGUS | an entity's error ratio jumped |
| `multivariate_outlier` | ARGUS | a payer's whole bucket shape is an outlier (Isolation Forest / k-NN) |
| `error_rate_spike` | opensearch-monitor | the SIEM's own scheduled monitor fired |
| `log_classification` | SENTINEL | malicious content in an entity's log lines |
| `slow_exfiltration` | CASSANDRA | sustained cumulative volume/amount drift on a payer |
| `threat_level_change` | guardian (fusion) | the global threat level moved |

Each alert carries `severity` (`low`/`medium`/`high`), the `entity_type`/`entity_id` it
concerns, a `score`, a plain-English `summary`, the `window` it covers, and `details`.

**Dedup:** the alerting service suppresses repeats of the same
`(entity_type, entity_id, type)` within 5 minutes (`ALERT_DEDUP_SECONDS`). Suppressed
occurrences are counted and reported on the next delivered alert for that key — nothing is
silently lost. Distinct entities alert separately, so a burst from four IPs is four alerts,
not one.

Check delivery health any time:

```sh
curl -s http://localhost:8003/stats
# {"sent":1243,"suppressed":749,"tracked_keys":47,"delivered":1243,
#  "delivery_failures":0,"malformed_messages":0,"mode":"log-only"}
```

To deliver to Slack or Discord instead of the log, set `SLACK_WEBHOOK_URL` and/or
`DISCORD_WEBHOOK_URL` in `.env` and `docker compose up -d alerting` — see the
[Admin Manual](admin_manual.md#2-configuration).

## 10. Stopping and resetting

```sh
docker compose down        # stop everything, keep indexed data, queue and baselines
docker compose down -v     # stop AND wipe all data
docker compose up -d       # start again
```

⚠ **`down -v` also wipes ARGUS's and CASSANDRA's learned baselines** (the `argus-data` and
`cassandra-data` volumes), on top of the indices, dashboards state and queue. Detection
goes cold. After a `down -v`, re-warm before demoing anything:

```sh
docker compose up -d --build
python training/seed_history.py
```

Details on exactly what is lost and how bootstrap re-runs are in the
[Admin Manual](admin_manual.md#5-reset-and-recovery).

## 11. If something looks wrong

Quick checks:

- `docker compose ps` — is anything `unhealthy` or restarting?
- No documents in Discover — widen the time range first; then follow the hop-by-hop
  pipeline check in the [Admin Manual](admin_manual.md#7-troubleshooting).
- No alerts, ever — the single most common cause is warm-up
  ([section 4](#4-warming-the-detectors)). Check `:8002/health` (`warming_up`) and
  `:8005/health` (`payers_warm`) before suspecting a bug. A detector staying quiet because
  it lacks a baseline is the system working as designed.
- Alerts for one detector only — check that the attack mode you set actually exercises the
  detector you're watching ([section 7](#7-driving-the-attacks)). `log_attack` will never
  produce an ARGUS alert, and it is not supposed to.

The Admin Manual has a full symptom → cause → fix table.
