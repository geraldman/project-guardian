# alerting — dedup + webhook alerter

The brief's extra-credit alerter: consumes `guardian.alerts`, applies a **5-minute
dedup window** keyed on `(entity_type, entity_id, alert type)`, and posts to Slack
and/or Discord. Suppressed occurrences are counted and surfaced on the next sent alert
for the same key, so nothing is silently lost.

Two inlets, one dedup window:

- **Kafka** — ARGUS alerts from `guardian.alerts` (group `guardian-alerting`).
- **HTTP `POST /notify`** — OpenSearch Alerting monitors, via the
  `guardian-alerting-webhook` notification channel created by opensearch-init.

## Configuration (compose env)

| Variable | Default | Meaning |
|---|---|---|
| `SLACK_WEBHOOK_URL` | *(empty)* | Slack incoming-webhook URL |
| `DISCORD_WEBHOOK_URL` | *(empty)* | Discord webhook URL |
| `ALERT_DEDUP_SECONDS` | `300` | dedup window |

With neither webhook set the service runs in **log-only mode**: formatted alerts land
in `docker compose logs alerting`. That's the local-dev default — the whole demo works
with zero secrets, and no webhook URL is ever committed.

## Endpoints (:8003)

| Endpoint | Purpose |
|---|---|
| `GET /health` | consumer status, delivery mode, dedup window |
| `GET /stats` | sent / suppressed / delivered / failures counters |
| `POST /notify` | HTTP inlet — accepts `{"alert": {...}}` (topic contract) or a bare alert object |

Delivery failures are logged and counted, never retried into the dedup window — a
Slack outage must not turn one alert into thirty on recovery.
