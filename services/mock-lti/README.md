# mock-lti

Synthetic "digital twin" of LTI's transaction-routing API: generates realistic B2B
micro-transaction traffic plus attack-laced patterns (burst spikes, malformed payloads),
and emits every event as telemetry — asynchronously, out-of-band — to `capture-agent`.

Branch: **feat/mock-lti** owns `services/mock-lti/**`.

Components:
- `app/generator.py` — background traffic loop (asyncio task started in FastAPI lifespan),
  paced by `EVENTS_PER_SECOND`; attack injection per `ATTACK_MODE` (off|burst|malformed|mixed)
- `app/telemetry.py` — fire-and-forget async POST to `CAPTURE_INGEST_URL` (short timeout,
  try/except so a capture hiccup never stalls generation; failures are counted)
- `POST /transactions/route` — demo-curlable endpoint; telemetry via `BackgroundTasks`
  (the §5.1.2 async/non-blocking proof point)
- `POST /admin/generator/config` — runtime toggle for rate + attack mode
- `GET /admin/generator/status` — config, counters (events by type, attacks, telemetry
  sent/failed), uptime

Event envelope contract: `app/schemas.py` (canonical spec: docs/architecture.md#event-schema).

Env vars: `EVENTS_PER_SECOND` (default 10), `ATTACK_MODE` (default mixed),
`CAPTURE_INGEST_URL`. Port **8000**.
