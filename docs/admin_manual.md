# GUARDIAN Admin Manual

Operator and maintainer runbook: configuration reference, day-to-day operations,
reset/recovery procedures, troubleshooting, and the end-to-end verification checklist.
For a first-time walkthrough see the [User Manual](user_manual.md).

Conventions used below:

- Run `docker compose ...` commands from the repository root (the root compose file
  includes the canonical stack definition in `infra/docker-compose.yml`).
- `curl` examples use POSIX shell syntax and the default admin password
  `Guardian!Lti2026` — substitute your own if you overrode
  `OPENSEARCH_ADMIN_PASSWORD`. In Windows PowerShell use `curl.exe`.

## 1. Architecture recap

The pipeline, its port allocations, the telemetry event schema, the normalized field
mapping, and the rationale for the two deliberate stack choices (Redpanda instead of
Kafka; an HTTP capture-agent as the MVP stand-in for eBPF traffic mirroring) are all
pinned in [architecture.md](architecture.md) — that document is the contract; this
manual does not restate it. The one-line version:

```
mock-lti → capture-agent → Redpanda (guardian.telemetry.raw) → Vector → OpenSearch → Dashboards
```

Component-level detail lives with each component: `services/mock-lti/README.md`,
`services/capture/README.md`, `infra/vector/vector.yaml`,
`infra/opensearch/index-template.json`, `infra/opensearch/ism-policy.json`,
`infra/opensearch-init/init.sh`, `infra/dashboards/README.md`.

## 2. Configuration

All tunables are environment variables read by `infra/docker-compose.yml`. Put
overrides in a `.env` file at the repository root (or export them) before `docker
compose up`.

### Overridable via `.env`

| Variable | Default | Consumed by | Effect |
|---|---|---|---|
| `OPENSEARCH_ADMIN_PASSWORD` | `Guardian!Lti2026` | opensearch, opensearch-dashboards, vector, opensearch-init | The single admin credential for the storage layer. **Applied only on first start** — see below. |
| `EVENTS_PER_SECOND` | `10` | mock-lti | Baseline synthetic-traffic generation rate. Also adjustable at runtime (see [3.1](#31-runtime-generator-control)). |
| `ATTACK_MODE` | `mixed` | mock-lti | Attack injection: `off` \| `burst` \| `malformed` \| `mixed`. Also adjustable at runtime. |

### Fixed in the compose file

These are wired to service hostnames on the internal `guardian-net` network; changing
them means editing `infra/docker-compose.yml`:

| Variable | Value | Consumed by | Effect |
|---|---|---|---|
| `CAPTURE_INGEST_URL` | `http://capture-agent:8001/ingest` | mock-lti | Where telemetry events are POSTed (asynchronously, out-of-band). |
| `REDPANDA_BROKERS` | `redpanda:9092` | capture-agent | Kafka-API bootstrap address (internal listener). |
| `TELEMETRY_TOPIC` | `guardian.telemetry.raw` | capture-agent | Topic the raw telemetry is produced to. |

mock-lti additionally has a service-level `EMIT_TIMEOUT_SECONDS` setting (default
`2.0`, defined in `services/mock-lti/app/config.py`) bounding each fire-and-forget
telemetry POST; it is not surfaced in the compose file.

### The password caveat

OpenSearch consumes `OPENSEARCH_ADMIN_PASSWORD` as its *initial* admin password: it is
written into the security index **only when the `opensearch-data` volume is first
created**. Changing `.env` later does not change the actual password — Dashboards,
Vector, and the init job will then be using a wrong credential. To change the password,
either do it before first start, or wipe and re-init: `docker compose down -v` then
`docker compose up -d` (destroys all indexed data — see [section 4](#4-reset-and-recovery)).

## 3. Operations

### 3.1 Runtime generator control

Traffic rate and attack mode can be changed while the stack runs, via the mock-lti
admin API on http://localhost:8000:

```sh
# Current configuration and status counters
curl -s http://localhost:8000/admin/generator/status

# Change rate and/or attack mode (takes effect without a restart)
curl -s -X POST http://localhost:8000/admin/generator/config \
  -H 'Content-Type: application/json' \
  -d '{"events_per_second": 50, "attack_mode": "burst"}'
```

Runtime changes do not persist across a container restart — the service falls back to
its environment defaults (`EVENTS_PER_SECOND`, `ATTACK_MODE`).

<!-- TODO: verify at integration — the config endpoint contract is per
services/mock-lti/README.md; confirm request field names, response shape, the status
endpoint's counter fields, and the restart/persistence behavior once the generator
lands on the mock-lti feature branch. -->

### 3.2 Inspecting the queue

**Redpanda Console** (http://localhost:8080) is the quickest view:

1. **Topics → `guardian.telemetry.raw`** — the Messages tab live-tails events (each
   should be a schema-valid JSON telemetry envelope); the topic view shows the 3
   partitions and produce throughput.
2. **Consumer Groups → `guardian-vector`** — Vector's consumer group. Lag near zero
   means Vector is keeping up; steadily growing lag means events are arriving faster
   than they are being indexed (check Vector and OpenSearch).

Command-line equivalents via `rpk` inside the Redpanda container:

```sh
# List topics — guardian.telemetry.raw should exist
docker compose exec redpanda rpk topic list

# Tail 5 raw events off the topic
docker compose exec redpanda rpk topic consume guardian.telemetry.raw -n 5

# Partitions, retention, and offsets
docker compose exec redpanda rpk topic describe guardian.telemetry.raw

# Vector's consumer group: members and lag
docker compose exec redpanda rpk group describe guardian-vector
```

For host-side Kafka tooling (kcat, a local `rpk`, custom clients), the external
listener is `localhost:19092`; the Redpanda Admin API is on `localhost:9644`.

Remember the topic is a transit buffer, not the store: ~6 hours retention, 3
partitions. OpenSearch holds the durable data.

### 3.3 Index lifecycle

- **Daily indices.** Vector writes to `guardian-traffic-%Y.%m.%d` (UTC date suffix), so
  a new index is created at each UTC midnight — rollover-by-time via naming, no
  rollover machinery needed.
- **Mappings** are pinned by the index template `guardian-traffic-template`
  (`infra/opensearch/index-template.json`), applied by `opensearch-init` at startup.
  The template also sets `ignore_malformed: true` so a single odd value cannot reject a
  document.
- **Retention.** ISM policy `guardian-traffic-ilm`
  (`infra/opensearch/ism-policy.json`) auto-attaches to `guardian-traffic-*` and
  deletes indices older than **7 days**.
- **1 shard / 0 replicas.** This is a single-node cluster: replicas could never be
  assigned and would only turn cluster health yellow. Demo-scale on purpose;
  production-scale retention sizing is out of scope for the MVP.

Useful checks:

```sh
# Which daily indices exist, and how many docs each holds
curl -sk -u 'admin:Guardian!Lti2026' 'https://localhost:9200/_cat/indices/guardian-traffic-*?v'

# Is the ISM policy attached to the indices?
curl -sk -u 'admin:Guardian!Lti2026' 'https://localhost:9200/_plugins/_ism/explain/guardian-traffic-*?pretty'

# Inspect the installed template / policy
curl -sk -u 'admin:Guardian!Lti2026' 'https://localhost:9200/_index_template/guardian-traffic-template?pretty'
curl -sk -u 'admin:Guardian!Lti2026' 'https://localhost:9200/_plugins/_ism/policies/guardian-traffic-ilm?pretty'
```

Note: index-template changes only affect indices created *after* the change — at the
latest, the next day's index. To re-map today's data, delete today's index and let
Vector re-create it (queued events within the topic's retention window are the only
ones replayed; older documents are gone).

### 3.4 Checking pipeline health

**Container level:**

```sh
docker compose ps
```

Every long-running service has a healthcheck (Redpanda: `rpk cluster health`;
OpenSearch: cluster status green/yellow; Dashboards: `/api/status` green; mock-lti and
capture-agent: HTTP `/health`). `opensearch-init` is a one-shot job — `Exited (0)` is
its healthy state.

**Bootstrap job:**

```sh
docker compose logs opensearch-init
```

Expect `[init] applying index template`, `[init] applying ISM policy` (a 409 on re-run
means it already exists — fine), and a final `[init] done`. The line
`no saved_objects.ndjson yet — skipping dashboards import` is normal until the
dashboards bundle is committed to `infra/dashboards/`.

**Vector (the usual first suspect when documents stop):**

```sh
docker compose logs -f vector
```

Healthy output is quiet. Look for Kafka connection errors (Redpanda down), VRL/remap
errors (schema drift), or HTTP 401/TLS errors against `https://opensearch:9200`
(password mismatch — see [section 2](#2-configuration)).

**Data level — walk the hops in pipeline order:**

```sh
# 1. Is the generator emitting?
curl -s http://localhost:8000/admin/generator/status

# 2. Are events on the topic?
docker compose exec redpanda rpk topic consume guardian.telemetry.raw -n 5

# 3. Is Vector consuming (lag near zero)?
docker compose exec redpanda rpk group describe guardian-vector

# 4. Are documents landing in today's index?
curl -sk -u 'admin:Guardian!Lti2026' 'https://localhost:9200/guardian-traffic-*/_count?pretty'
```

The first hop that shows nothing is where to dig.

## 4. Reset and recovery

### Restart a single service

```sh
docker compose restart vector          # plain restart, e.g. after a config edit
docker compose up -d --build mock-lti  # rebuild + recreate after a code change
```

Restarting Vector is safe mid-stream: it resumes from its committed consumer-group
offsets, so no events within the topic's retention window are lost.

### Full reset

```sh
docker compose down -v
docker compose up -d
```

`down -v` removes the containers **and both named volumes**, which destroys:

- all `guardian-traffic-*` indices (every indexed event),
- all OpenSearch Dashboards state — index patterns, hand-built visualizations, and
  anything else not committed to `infra/dashboards/saved_objects.ndjson`,
- the OpenSearch security config, including any password set at first start (the next
  start re-initializes from `OPENSEARCH_ADMIN_PASSWORD`),
- all queued Redpanda messages and consumer-group offsets.

Container images are kept, so the restart is fast. On the way back up,
`opensearch-init` re-applies the index template and ISM policy automatically (and
re-imports the dashboards bundle once it exists), which is what makes a clean-checkout
demo reproducible.

### Re-run the bootstrap only

The init job is idempotent — safe to re-run any time, e.g. after editing the template
or policy, or if it previously failed:

```sh
docker compose up opensearch-init
docker compose logs opensearch-init
```

## 5. Troubleshooting

| Symptom | Likely cause | Check / fix |
|---|---|---|
| A service is `unhealthy` or restart-looping in `docker compose ps` | Varies | `docker compose logs <service>` for the specific error, then the matching row below; `docker compose restart <service>` after fixing. |
| OpenSearch exits or restart-loops at boot; logs say `max virtual memory areas vm.max_map_count [65530] is too low` | Docker VM kernel limit (common on Windows/WSL2) | `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`, then `docker compose up -d`. Persist across Docker Desktop restarts via `%UserProfile%\.wslconfig`: `[wsl2]` / `kernelCommandLine = sysctl.vm.max_map_count=262144`, then `wsl --shutdown`. Native Linux: `sudo sysctl -w vm.max_map_count=262144`. |
| OpenSearch or Redpanda killed / flapping under load | Docker VM out of memory | Allocate ≥ 8 GB to the Docker VM (Docker Desktop → Settings → Resources); the stack needs ~3.5–4.5 GB. |
| Dashboards login rejects `admin` + your `.env` password | Password in `.env` changed **after** the OpenSearch data volume was created; the initial password still applies | Log in with the original password, or reset it via full wipe: `docker compose down -v && docker compose up -d` (destroys data — [section 4](#4-reset-and-recovery)). |
| Dashboards shows "OpenSearch Dashboards server is not ready yet" | OpenSearch still within its ~60 s start period, or unhealthy | Wait for `docker compose ps` to show opensearch healthy; if it never does, `docker compose logs opensearch`. |
| No documents arriving in Discover | Any hop of the pipeline | First widen Discover's time range. Then walk the hops in order ([3.4](#34-checking-pipeline-health)): generator status counters → `rpk topic consume` → `rpk group describe guardian-vector` / vector logs → `_cat/indices` doc counts. The first silent hop is the broken one. |
| Vector logs show 401/auth or TLS errors against OpenSearch | Vector's `OPENSEARCH_ADMIN_PASSWORD` doesn't match the cluster's actual password | Align the value (see the password caveat in [section 2](#2-configuration)), then `docker compose up -d --force-recreate vector`. |
| `docker compose up` fails with `port is already allocated` | Another process holds one of the host ports 8000, 8001, 5601, 8080, 9200, 19092, 9644 | Windows: `netstat -ano \| findstr :5601` then stop that process; Linux/macOS: `lsof -i :5601`. Retry `docker compose up -d`. |
| Index template or ISM policy missing (`_index_template` / `_plugins/_ism` return 404) | `opensearch-init` failed or was interrupted | `docker compose logs opensearch-init`, fix the cause (usually OpenSearch not up or wrong password), re-run: `docker compose up opensearch-init`. |
| `guardian.telemetry.raw` topic missing | capture-agent hasn't completed its topic bootstrap | `docker compose logs capture-agent`; verify Redpanda is healthy; restart capture-agent. <!-- TODO: verify at integration — topic bootstrap lands on the capture-agent feature branch. --> |
| Events visible on the topic but indices stay empty | Vector down or mis-consuming | `docker compose logs -f vector`; `rpk group describe guardian-vector` (no members = Vector not connected; growing lag = Vector stuck). |

## 6. End-to-end verification checklist

A repeatable evidence run proving the pipeline works from generator to dashboard.
Execute top to bottom on a running stack; every step states its pass condition.

1. **All services healthy.** `docker compose ps` — every long-running service
   `running (healthy)`; `opensearch-init` `Exited (0)`.
2. **Bootstrap applied.** `docker compose logs opensearch-init` ends with `[init] done`,
   with template and ISM lines above it.
3. **Generator emitting.** Run
   `curl -s http://localhost:8000/admin/generator/status` twice, ~10 s apart — the
   emitted-events counter increases between calls.
   <!-- TODO: verify at integration — exact counter field names in the status response. -->
4. **Events on the queue.**
   `docker compose exec redpanda rpk topic consume guardian.telemetry.raw -n 5`
   prints 5 JSON envelopes matching the schema in
   [architecture.md](architecture.md#event-schema). In Redpanda Console, the topic's
   Messages view live-tails the same stream and the topic shows nonzero produce
   throughput. <!-- TODO: screenshot after integration — Console topic throughput view. -->
5. **Consumer keeping up.**
   `docker compose exec redpanda rpk group describe guardian-vector` — group has an
   active member and total lag stays near zero across two runs.
6. **Documents landing.**
   `curl -sk -u 'admin:Guardian!Lti2026' 'https://localhost:9200/guardian-traffic-*/_count?pretty'`
   twice, ~10 s apart — count increases; `_cat/indices/guardian-traffic-*?v` shows
   today's daily index.
7. **Attack traffic labeled.** In Discover (index pattern `guardian-traffic-*`,
   last 15 minutes), filter `security.is_attack: true` — documents of type
   `burst_spike` and/or `malformed_payload` appear, with `security.attack_pattern`
   set. CLI equivalent:
   `curl -sk -u 'admin:Guardian!Lti2026' 'https://localhost:9200/guardian-traffic-*/_search?q=security.is_attack:true&size=1&pretty'`
   returns hits. <!-- TODO: screenshot after integration — Discover filtered on security.is_attack:true. -->
8. **Error rate visible.** The Guardian Traffic Overview dashboard's error-rate
   visualization (aggregating on the `error` field) shows a nonzero series while
   attack modes are active.
   <!-- TODO: screenshot after integration — dashboard ships via the saved-objects bundle. -->
9. **Attack burst visible end-to-end.** Trigger a burst:
   `curl -s -X POST http://localhost:8000/admin/generator/config -H 'Content-Type: application/json' -d '{"events_per_second": 50, "attack_mode": "burst"}'`
   — within a minute, Console shows a produce-throughput jump and the dashboard's
   traffic-volume chart (split on `event.type` / `security.is_attack`) shows the spike.
   Restore defaults afterwards:
   `curl -s -X POST http://localhost:8000/admin/generator/config -H 'Content-Type: application/json' -d '{"events_per_second": 10, "attack_mode": "mixed"}'`
   <!-- TODO: screenshot after integration — one visible burst window on the dashboard. -->
10. **Retention attached.**
    `curl -sk -u 'admin:Guardian!Lti2026' 'https://localhost:9200/_plugins/_ism/explain/guardian-traffic-*?pretty'`
    shows policy `guardian-traffic-ilm` on every `guardian-traffic-*` index.
