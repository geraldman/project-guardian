# mock-lti

Synthetic "digital twin" of LTI's transaction-routing API: generates realistic B2B
micro-transaction traffic plus attack-laced patterns (burst spikes, malformed payloads),
and emits every event as telemetry — asynchronously, out-of-band — to `capture-agent`.

Branch: **feat/mock-lti** owns `services/mock-lti/**`.

Components:
- `app/generator.py` — background traffic loop (asyncio task started in FastAPI lifespan),
  paced by `EVENTS_PER_SECOND`; attack injection per `ATTACK_MODE`. Every event also
  carries a rendered API-gateway log line (`log_message`) — benign traffic uses a stable
  set of endpoint families (values vary, structure doesn't), attack traffic hides its
  signature in the log content.
- `app/telemetry.py` — fire-and-forget async POST to `CAPTURE_INGEST_URL` (short timeout,
  try/except so a capture hiccup never stalls generation; failures are counted)
- `POST /transactions/route` — demo-curlable endpoint; telemetry via `BackgroundTasks`
  (async/non-blocking: the response is sent first, telemetry emitted out-of-band)
- `POST /admin/generator/config` — runtime toggle for rate + attack mode
- `GET /admin/generator/status` — config, counters (events by type, attacks, telemetry
  sent/failed), uptime

### Attack modes (`ATTACK_MODE`)

| Mode | Behaviour | Designed to exercise |
|---|---|---|
| `off` | clean baseline only | — |
| `burst` | 10–20× rate spike for 5–10s every 60–120s from ~4 IPs | ARGUS rate detector |
| `malformed` | ~8% of events carry bad *values* (`raw_payload_valid=false`) | ARGUS payload/error, malformed metrics |
| `slow_exfil` | one designated payer gets a steady trickle of extra transactions (~2/min) with modestly elevated amounts; stays under ARGUS's per-minute detectors, obvious only in cumulative volume/amount | CASSANDRA (CUSUM on aggregated per-payer buckets) |
| `log_attack` | malicious log *content* at normal rates from a modest attacker-IP pool (SQLi, path traversal, credential stuffing, scanner probes); schema-valid, normal status distribution | SENTINEL (log-line classification) |
| `mixed` | all four attack behaviours together (default) | full detection stack |

Ground truth: `slow_exfil` and `log_attack` events are labelled `is_attack=true` with
`attack_pattern` `slow_exfil` / `log_attack`, but are otherwise schema-valid and
benign-looking to the volumetric layer — that is the point.

Event envelope contract: `app/schemas.py` (canonical spec: docs/architecture.md#event-schema).

Env vars: `EVENTS_PER_SECOND` (default 10), `ATTACK_MODE` (default mixed),
`CAPTURE_INGEST_URL`. slow_exfil tunables: `EXFIL_PAYER_ID` (default `wallet-user-0001`),
`EXFIL_EVENTS_PER_MINUTE` (default 2), `EXFIL_AMOUNT_MULTIPLIER` (default 1.8);
log_attack tunable: `LOG_ATTACK_PROBABILITY` (default 0.08). Port **8000**.
