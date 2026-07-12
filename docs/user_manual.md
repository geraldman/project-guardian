# GUARDIAN User Manual

This manual is for anyone evaluating or operating GUARDIAN from a clean checkout: it
covers starting the stack, logging in, reading the data, and driving the traffic
generator. Deeper operational topics (configuration reference, queue inspection,
recovery, troubleshooting) live in the [Admin Manual](admin_manual.md); the system
design and cross-service contracts live in [architecture.md](architecture.md).

## 1. What GUARDIAN is

GUARDIAN is a self-contained SOC/SIEM pipeline for transaction telemetry. It ships with
its own **digital twin**: a synthetic transaction-routing API (`mock-lti`) that generates
realistic traffic — including deliberate attack patterns — inside the same Docker
network. Every event flows through the full pipeline:

```
mock-lti  →  capture-agent  →  Redpanda  →  Vector  →  OpenSearch  →  OpenSearch Dashboards
(traffic)    (ingestion)       (queue)      (normalize)  (storage)     (analysis UI)
```

Because the traffic source is bundled, a single `docker compose up` demonstrates the
entire system with no external infrastructure and no real data.

## 2. Prerequisites

| Requirement | Detail |
|---|---|
| Docker Desktop | A recent version with Docker Compose v2.20 or later (the root compose file uses the `include` directive). Works on Windows (WSL2), macOS, and Linux. |
| RAM | Allocate **at least 8 GB** to the Docker VM (Docker Desktop → Settings → Resources). The stack uses roughly 3.5–4.5 GB under load; OpenSearch (512 MB JVM heap plus off-heap usage) and Redpanda (1 GB reserved) are the two big consumers. |
| Disk | A few GB free for container images and indexed data. |
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
docker compose up -d
```

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
3. **OpenSearch** — the slow one: its healthcheck allows a **~60 s start period** and it
   can take 1–2 minutes on first boot.
4. **OpenSearch Dashboards**, **Vector**, and the one-shot **opensearch-init** bootstrap
   job — after OpenSearch reports healthy.

The first run also builds the two service images and pulls the infrastructure images,
which adds several minutes depending on your network. After images exist locally,
expect the whole stack to be healthy in roughly **2–3 minutes**.

Confirm everything is up:

```sh
docker compose ps
```

All long-running services should show `running` (with `healthy` where a healthcheck is
defined). `opensearch-init` runs once and exits — an `Exited (0)` status for it is
normal.

## 4. Web interfaces

| Service | URL | What it's for |
|---|---|---|
| OpenSearch Dashboards | http://localhost:5601 | The SIEM view: Discover, visualizations, the Guardian Traffic Overview dashboard |
| Redpanda Console | http://localhost:8080 | Watch the raw telemetry queue (topic `guardian.telemetry.raw`) |
| mock-lti API | http://localhost:8000 | Synthetic traffic generator — interactive API docs at http://localhost:8000/docs |
| capture-agent API | http://localhost:8001 | Ingestion boundary — interactive API docs at http://localhost:8001/docs |

**Dashboards login:** username `admin`, password is the value of
`OPENSEARCH_ADMIN_PASSWORD` (default `Guardian!Lti2026` if you did not override it).
If Dashboards asks you to select a tenant after login, choose **Global** so you see the
shared saved objects.

## 5. Exploring the data

### Discover

Events are indexed into **daily indices** named `guardian-traffic-YYYY.MM.DD` (retained
for 7 days — see the [Admin Manual](admin_manual.md#33-index-lifecycle)). To browse
them, open Dashboards → **Discover**.

Discover needs an index pattern. The `guardian-traffic-*` pattern ships in the saved
dashboards bundle and is imported automatically at startup; if it is not present yet
(the bundle is committed after pipeline integration), create it once by hand:

1. Dashboards menu → **Dashboards Management** → **Index patterns** → **Create index pattern**.
2. Pattern: `guardian-traffic-*`
3. Time field: `@timestamp`
<!-- TODO: verify at integration — remove the manual index-pattern steps once
saved_objects.ndjson is committed and auto-imported by opensearch-init. -->

With the time range set to "Last 15 minutes" you should see a steady stream of
documents (the generator's default rate is 10 events/second).

### The Guardian Traffic Overview dashboard

The **Guardian Traffic Overview** dashboard is the single pane of glass: traffic volume
over time, error rate, and channel breakdown.

<!-- TODO: screenshot after integration — dashboard is built in the Dashboards UI once
data is flowing, then exported to infra/dashboards/saved_objects.ndjson and
auto-imported on startup. Add the walkthrough + screenshots then. -->

### How traffic types appear

The generator emits three event types, distinguishable in Discover and on the dashboard:

| `event.type` | What it is | Telltale fields |
|---|---|---|
| `transaction` | Normal synthetic business traffic | `security.is_attack: false`, `transaction.status` mostly `approved` |
| `burst_spike` | Attack: sudden traffic burst | `security.is_attack: true`, `security.attack_pattern: burst` |
| `malformed_payload` | Attack: structurally bad transaction data (negative amounts, junk currency, missing payer) | `security.is_attack: true`, `security.attack_pattern: malformed`, `security.is_malformed: true`, `transaction.status: malformed` |

Two fields matter most when reading the data:

- **`security.is_attack`** — the ground-truth attack label. Filter Discover on
  `security.is_attack: true` to see only injected attack traffic.
- **`error`** — `true` when the transaction status is `declined`, `error`, or
  `malformed`. The dashboard's error-rate visualization aggregates on this field.

Note that malformed traffic is still valid JSON end to end — malformation is expressed
in field *values*, so bad data flows through the pipeline and surfaces in the dashboard
instead of being dropped. The full field mapping is in
[architecture.md](architecture.md#normalized-fields).

## 6. Trying it out

### Route a transaction by hand

The mock-lti API exposes the same endpoint a real routing API would. Send one
transaction and watch it appear in Discover a few seconds later:

```sh
curl -s -X POST http://localhost:8000/transactions/route \
  -H 'Content-Type: application/json' \
  -d '{
    "payer_id": "merchant-0042",
    "payee_id": "bank-007",
    "channel": "ecommerce",
    "amount": 125000.0,
    "currency": "IDR"
  }'
```

Telemetry for the request is emitted asynchronously (out-of-band), so the response
returns without waiting on the pipeline.

<!-- TODO: verify at integration — POST /transactions/route lands on the mock-lti
feature branch; confirm the exact request body and response shape against
services/mock-lti once merged, and paste a real response example here. -->

### Change the traffic rate or attack mode at runtime

The generator is controlled through the admin endpoints — no restart needed:

```sh
# Inspect the current generator configuration (and status counters)
curl -s http://localhost:8000/admin/generator/status

# Crank the rate up and switch to burst-only attacks
curl -s -X POST http://localhost:8000/admin/generator/config \
  -H 'Content-Type: application/json' \
  -d '{"events_per_second": 50, "attack_mode": "burst"}'
```

Valid `attack_mode` values: `off`, `burst`, `malformed`, `mixed` (default).

<!-- TODO: verify at integration — the config endpoint contract is per
services/mock-lti/README.md; confirm the request body field names, response shape, and
the status endpoint's counter fields once the generator lands. -->

After changing the config, watch the effect live: message throughput rises in Redpanda
Console (http://localhost:8080, topic `guardian.telemetry.raw`), and the traffic-volume
chart in Dashboards shows the burst within the flush interval.

## 7. Stopping and resetting

```sh
docker compose down        # stop everything, keep indexed data and queue
docker compose down -v     # stop AND wipe all data (indices, dashboards state, queue)
docker compose up -d       # start again
```

A full reset (`down -v`) is useful for re-recording a clean demo; details on exactly
what is lost and how bootstrap re-runs are in the
[Admin Manual](admin_manual.md#4-reset-and-recovery).

## 8. If something looks wrong

Quick checks:

- `docker compose ps` — is anything `unhealthy` or restarting?
- No documents in Discover — widen the time range first; then follow the hop-by-hop
  pipeline check in the [Admin Manual](admin_manual.md#5-troubleshooting).

The Admin Manual has a full symptom → cause → fix table.
