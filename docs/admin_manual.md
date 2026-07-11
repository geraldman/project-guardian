# Admin Manual (stub — expanded in Week 5)

## Configuration knobs (env vars / `.env` file at repo root)

| Variable | Default | Effect |
|---|---|---|
| `OPENSEARCH_ADMIN_PASSWORD` | `Guardian!Lti2026` | OpenSearch/Dashboards admin password (set before first start) |
| `EVENTS_PER_SECOND` | `10` | mock-lti traffic generation rate |
| `ATTACK_MODE` | `mixed` | `off` \| `burst` \| `malformed` \| `mixed` |

## Operations

- **Full reset:** `docker compose down -v` (wipes OpenSearch indices and the Redpanda queue).
- **Watch the queue:** Redpanda Console at http://localhost:8080.
- **Re-run bootstrap** (index template / ISM / dashboard import): `docker compose up opensearch-init`.
- **Memory:** stack needs ~3.5–4.5 GB inside the Docker VM; allocate ≥ 8 GB in
  Docker Desktop → Settings → Resources.

*(To be expanded: credential rotation, index management, scaling notes, VPS deployment.)*
