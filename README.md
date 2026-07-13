# Project GUARDIAN

A self-contained SOC/SIEM system built for LTI as a part of the President University *Cyber Security Bootcamp Project* course

GUARDIAN runs as a **digital twin**: a synthetic LTI API generates realistic and attack-laced
traffic inside the same Docker network, so the entire security-observability pipeline — ingestion,
normalization, storage, detection, alerting — is demoable with one command and zero external
infrastructure.

## Architecture

```
Mock LTI API + traffic/attack generator (FastAPI)
        │ async, non-blocking, out-of-band telemetry
        ▼
capture-agent (FastAPI + aiokafka)  ──►  Redpanda (Kafka-API queue)
                                              │  guardian.telemetry.raw
                                              ▼
                                    Vector (parse + normalize + enrich)
                                              │
                     ┌────────────────────────┴────────────────────────┐
                     ▼                                                 ▼
          OpenSearch (storage, ISM lifecycle)          guardian.telemetry.normalized
                     │                                                 │
                     ▼                                    ┌────────────┼────────────┐
          OpenSearch Dashboards                           ▼            ▼            ▼
          (single pane of glass)                        ARGUS      SENTINEL     CASSANDRA
                                                          │            │            │
                                                          └─────┬──────┴────────────┘
                                                                ▼
                                                        guardian.scores  ──►  fusion
                                                        guardian.alerts        (unified
                                                                │               threat state)
                                                                ▼
                                                            alerting
                                                     (5-min dedup → Slack/Discord)
```

**The detection triad**, three independent scorers reading the same normalized stream, each
covering what the others structurally cannot:

| Service | Detects | Technique |
|---|---|---|
| **ARGUS** (:8002) | rate spikes, payload/error anomalies | per-entity EW z-scores (3σ) + Isolation Forest / k-NN on 1-minute buckets |
| **SENTINEL** (:8004) | malicious log *content* — SQLi, path traversal, credential stuffing, scanner probes | Drain3 template mining + rule pre-filter + windowed XGBoost |
| **CASSANDRA** (:8005) | low-and-slow exfiltration that hides under per-minute thresholds | per-payer CUSUM control charts on cumulative volume + amount |

**fusion** (:8006) consumes every scorer's output and folds it into one decayed threat state with a
**corroboration boost** — when two models independently flag the same entity, the entity scores
above either alone. It publishes a global threat level (`normal → elevated → critical`, with
hysteresis) and serves the current picture at `GET /threat`.

Vector is the single OpenSearch write path: no scorer talks to OpenSearch directly — they are all
pure Kafka-in/Kafka-out.

Full design, event schema contract, topic/port allocations, and the rationale for the two
deliberate stack deviations: [docs/architecture.md](docs/architecture.md).

## Quickstart

Prerequisites: Docker Desktop (Compose v2.20+) with ≥ 8 GB RAM allocated to the Docker VM (the
stack uses roughly 4–5 GB under load).

```sh
docker compose up -d --build
```

Run it from the repository root — the thin root compose file includes the canonical stack
definition in `infra/docker-compose.yml`. First start builds seven service images and pulls the
infrastructure images; after that the stack is healthy in ~2–3 minutes.

Then warm the detectors (host Python 3.10+, no extra packages — it replays backdated benign
traffic through the real pipeline):

```sh
python training/seed_history.py
```

This is worth the ~1 minute it takes. ARGUS needs 15 one-minute buckets of history and CASSANDRA
needs 30 before either may alert; `seed_history.py` replays 40 backdated minutes and warms **both**
(`seed_baseline.py` replays 20 minutes and warms ARGUS only). Without it, a fresh stack detects
nothing for the first half hour, by design — a detector must never alert off a baseline it does
not have.

Then open:

| Service | URL | Purpose |
|---|---|---|
| OpenSearch Dashboards | http://localhost:5601 | Single-pane SIEM view (login `admin` / see below) |
| Redpanda Console | http://localhost:8080 | Watch the telemetry, score, and alert topics |
| Mock LTI API | http://localhost:8000/docs | Synthetic traffic + attack generator controls |
| capture-agent | http://localhost:8001/docs | Ingestion boundary |
| ARGUS | http://localhost:8002/docs | Rate/payload anomaly scorer |
| alerting | http://localhost:8003/docs | Dedup + Slack/Discord delivery |
| SENTINEL | http://localhost:8004/docs | Log-content classifier |
| CASSANDRA | http://localhost:8005/docs | Slow-exfiltration detector |
| fusion | http://localhost:8006/threat | **Unified threat picture** |
| OpenSearch API | https://localhost:9200 | Storage/index (self-signed TLS) |

Default OpenSearch admin password is `Guardian!Lti2026` (override by exporting
`OPENSEARCH_ADMIN_PASSWORD` or putting it in a `.env` file **before first start** — see the
[Admin Manual](docs/admin_manual.md#2-configuration)).

## Where to see results

- **OpenSearch Dashboards** (http://localhost:5601) — the **Guardian Traffic Overview** dashboard
  for raw traffic, and **Guardian Detection** for anomaly scores and the live alert feed. Both are
  imported automatically at startup into the **Global** tenant.
- **`GET :8006/threat`** — the fastest read on "is anything happening right now". A real response
  during an attack (verified live):

  ```json
  {
    "threat_level": "elevated",
    "anomaly_score": 0.6554,
    "is_anomalous": true,
    "level_since": "2026-07-13T08:13:35Z",
    "contributors": {"argus": 0.9066, "sentinel": 0.7269},
    "corroboration": 1,
    "reasons": ["argus:rate_spike", "sentinel:sqli_probe"],
    "top_entities": [
      {"entity_type": "client_ip", "entity_id": "45.148.10.17", "score": 0.4361,
       "models": {"sentinel": 0.7269}, "corroborated": false,
       "reasons": ["sentinel:sqli_probe"], "last_update": "2026-07-13T08:14:36Z"}
    ],
    "recent_transitions": [
      {"at": "2026-07-13T08:13:35Z", "from": "normal", "to": "elevated", "score": 0.7241}
    ],
    "entities_tracked": 23
  }
  ```

- **Alerts** — `docker compose logs alerting` in the default log-only mode, or Slack/Discord once
  `SLACK_WEBHOOK_URL` / `DISCORD_WEBHOOK_URL` are set. Every alert also lands in
  `guardian-alerts-*`.

## Demo an attack

The generator is driven at runtime through its admin API — no restart, no rebuild:

```sh
# Drive SENTINEL: malicious log content at normal traffic rates
curl -s -X POST http://localhost:8000/admin/generator/config \
  -H 'Content-Type: application/json' \
  -d '{"attack_mode": "log_attack"}'

# Back to everything at once (the default)
curl -s -X POST http://localhost:8000/admin/generator/config \
  -H 'Content-Type: application/json' \
  -d '{"attack_mode": "mixed"}'
```

| `attack_mode` | What it injects | Who should catch it |
|---|---|---|
| `off` | nothing — benign traffic only | nobody (the quiet-baseline check) |
| `burst` | 10–20× rate spikes from a handful of IPs | ARGUS → `rate_spike` |
| `malformed` | bad field *values* (negative amounts, junk currency) | ARGUS → `payload_anomaly` / `error_ratio_spike` |
| `slow_exfil` | ~2 extra events/min on one payer at ~1.8× amounts | CASSANDRA → `slow_exfiltration` |
| `log_attack` | SQLi / traversal / credential stuffing / scanner probes in the log line | SENTINEL → `log_classification` |
| `mixed` | all of the above (default) | the full stack |

Any of them moves fusion's threat level and raises `threat_level_change`. The generator also
accepts `{"events_per_second": 50}`, and `GET /admin/generator/status` reports the effective config
plus counters (`counters.attacks_injected` breaks down by `burst` / `malformed` / `slow_exfil` /
`log_attack`).

`slow_exfil` and `log_attack` are deliberately built to be **invisible** to ARGUS — they stay under
its per-minute volume floors and never move the error rate. That is the point: they are the
evidence that SENTINEL and CASSANDRA earn their place. Walkthroughs of each mode, and what should
happen for each, are in the [User Manual](docs/user_manual.md#7-driving-the-attacks).

## Documentation

| Document | For |
|---|---|
| [docs/user_manual.md](docs/user_manual.md) | Operating the system: start it, warm it, drive attacks, read the dashboards, interpret alerts |
| [docs/admin_manual.md](docs/admin_manual.md) | Running and maintaining it: services, configuration, volumes, tuning, retraining, troubleshooting |
| [docs/architecture.md](docs/architecture.md) | The design and the pinned cross-service contracts |

Each service also documents its own design, knobs, and endpoints in its README —
[mock-lti](services/mock-lti/README.md), [capture](services/capture/README.md),
[argus](services/argus/README.md), [sentinel](services/sentinel/README.md),
[cassandra](services/cassandra/README.md), [fusion](services/fusion/README.md),
[alerting](services/alerting/README.md).

## Repository layout

```
infra/               docker-compose, Redpanda/OpenSearch/Vector configs, dashboards, bootstrap init
services/mock-lti/   synthetic LTI API + traffic/attack generator
services/capture/    ingestion boundary → Redpanda producer (MVP stand-in for eBPF mirror)
services/argus/      transaction-rate / payload anomaly scorer
services/sentinel/   log-line classifier (Drain3 + XGBoost)
services/cassandra/  slow-exfiltration detector (per-payer CUSUM)
services/fusion/     unified Guardian threat state + /threat endpoint
services/alerting/   dedup + Slack/Discord webhook alerter
dashboard/           Guardian Pulse HUD (Next.js)                  (Week 4 — stub)
training/            detector warm-up seeders + SENTINEL training script
docs/                architecture, user/admin manuals
```

## Full reset

```sh
docker compose down -v     # wipes indexed data, the queue, AND learned baselines
docker compose up -d --build
python training/seed_history.py    # re-warm ARGUS + CASSANDRA
```

⚠ `down -v` removes the named volumes, which includes **ARGUS's and CASSANDRA's learned
baselines**. Detection goes cold and stays cold until they re-warm — re-seed. Details in the
[Admin Manual](docs/admin_manual.md#5-reset-and-recovery).

## Project status

| Week | Checkpoint | Status |
|---|---|---|
| 1 | Mandatory pipeline end-to-end | ✅ done |
| 2 | ARGUS scorer + alerting | ✅ done |
| 3 | SENTINEL + CASSANDRA + unified Guardian score | ✅ done |
| 4 | Guardian Pulse HUD + load testing | ⬜ |
| 5 | Docs, evidence, presentation | ⬜ |
