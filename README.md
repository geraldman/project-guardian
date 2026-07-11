# Project GUARDIAN

A self-contained SOC/SIEM system built for LTI as a part of the President University *Cyber Security Bootcamp Project* course

GUARDIAN runs as a **digital twin**: a synthetic LTI API generates realistic and attack-laced
traffic inside the same Docker network, so the entire security-observability pipeline is demoable
with one command and zero external infrastructure.

## Architecture

```
Mock LTI API + traffic/attack generator (FastAPI)
        │ async, non-blocking, out-of-band telemetry
        ▼
capture-agent (FastAPI + aiokafka)  ──►  Redpanda (Kafka-API queue)
                                              │
                                              ▼
                                    Vector (parse + normalize + enrich)
                                              │
                                              ▼
                                    OpenSearch (storage/index, ISM lifecycle)
                                              │
                                              ▼
                                    OpenSearch Dashboards (single pane of glass)
```

Full design, event schema contract, and rationale for stack deviations:
[docs/architecture.md](docs/architecture.md).

## Quickstart

Prerequisites: Docker Desktop with ≥ 8 GB RAM allocated to the Docker VM (the stack uses
roughly 3.5–4.5 GB under load).

```sh
docker compose up -d
```

Then open:

| Service | URL | Purpose |
|---|---|---|
| OpenSearch Dashboards | http://localhost:5601 | Single-pane SIEM view (login `admin` / see below) |
| Redpanda Console | http://localhost:8080 | Watch the raw telemetry topic |
| Mock LTI API | http://localhost:8000/docs | Synthetic traffic generator controls |
| capture-agent | http://localhost:8001/docs | Ingestion boundary |
| OpenSearch API | https://localhost:9200 | Storage/index (self-signed TLS) |

Default OpenSearch admin password is `Guardian!Lti2026` (override by exporting
`OPENSEARCH_ADMIN_PASSWORD` or putting it in a `.env` file before first start).

Full reset (wipes indexed data and queue — used to re-record clean demos):

```sh
docker compose down -v
```

## Repository layout

```
infra/               docker-compose, Redpanda/OpenSearch/Vector configs, bootstrap init
services/mock-lti/   synthetic LTI API + traffic/attack generator
services/capture/    ingestion boundary → Redpanda producer (MVP stand-in for eBPF mirror)
services/argus/      transaction-rate/payload anomaly scorer      (Week 2 — stub)
services/sentinel/   log classifier                                (Week 3 — stub)
services/cassandra/  slow-exfiltration detector                    (Week 3 — stub)
services/alerting/   dedup + Slack/Discord webhook alerter         (Week 2 — stub)
dashboard/           Guardian Pulse HUD (Next.js)                  (Week 4 — stub)
training/            model training scripts + dataset notes        (stub)
docs/                architecture, user/admin manuals, AI usage disclosure
```

## Project status

| Week | Checkpoint | Status |
|---|---|---|
| 1 (Jul 11–18) | Mandatory pipeline end-to-end | 🚧 in progress |
| 2 | ARGUS scorer + alerting | ⬜ |
| 3 | SENTINEL + CASSANDRA + unified Guardian score | ⬜ |
| 4 | Guardian Pulse HUD + load testing | ⬜ |
| 5 | Docs, evidence, presentation | ⬜ |
