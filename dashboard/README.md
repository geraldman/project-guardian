# Guardian Pulse HUD

Next.js single-pane SOC HUD for the GUARDIAN stack: threat-level indicator,
heartbeat panels for the ARGUS/SENTINEL/CASSANDRA triad, a template-based
plain-English incident narrative, and one-click Freeze-to-PDF compliance
snapshots. OpenSearch Dashboards remains the workhorse SIEM view; this is the
single pane an operator keeps open.

## How it talks to the stack

The browser only ever calls same-origin `/api/*`. The Next.js server proxies:

- `GET /api/health` — liveness for the compose healthcheck (never gated on
  upstream reachability).
- `GET /api/pulse` — one aggregate snapshot: fusion `/threat` plus each
  scorer's `/health` + `/stats` (and cassandra's `/drift/top`), fetched
  server-side in parallel with a 2.5 s timeout per source. Always returns 200
  with per-source `ok`/`error`, so a dead scorer degrades one panel instead of
  the page.

Upstream base URLs come from `FUSION_URL`, `ARGUS_URL`, `SENTINEL_URL`,
`CASSANDRA_URL` (set by the compose block to docker-internal hostnames) and
fall back to the published `localhost` ports for development on the host.

## Development

```bash
npm ci
npm run dev            # http://localhost:3000
npm run dev -- -p 3100 # if the guardian-pulse container already owns :3000
```

Works with the stack up (live data) or down (panels show offline states).

Narrative engine tests (pure TypeScript, run via Node's built-in runner):

```bash
node --test lib/narrative/*.test.ts
```

## Container

`docker compose up -d --build guardian-pulse` from `infra/` (or the repo
root). The Dockerfile is a multi-stage standalone build; the runner serves on
:3000 and answers `/api/health` for the compose healthcheck.
