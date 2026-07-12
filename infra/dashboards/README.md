# Dashboards saved objects

`opensearch-init` auto-imports **every** `*.ndjson` in this folder on `docker compose
up` (Global tenant), which is what makes the dashboards reproducible from a clean
checkout.

- `saved_objects.ndjson` — Week 1 bundle, exported from a live Dashboards session:
  index pattern `guardian-traffic-*`, the traffic-volume / error-rate /
  channel-breakdown / attack-pattern / counter visualizations, and the
  **Guardian Traffic Overview** dashboard.
- `detection_objects.ndjson` — Week 2 bundle, generated (not UI-exported): index
  patterns `guardian-scores-*` / `guardian-alerts-*`, ARGUS anomaly-score line
  (0.5 threshold marker), alerts-over-time-by-severity, alerts-by-type donut, alert
  feed table, and the **Guardian Detection** dashboard.

To change a dashboard: edit it in the UI (http://localhost:5601), then Stack
Management → Saved objects → Export the affected objects and overwrite the bundle here
— committed ndjson is the source of truth, a UI-only change dies with `down -v`.
