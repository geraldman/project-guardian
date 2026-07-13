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
- `detection_w3.ndjson` — Week 3 bundle, generated: the **Guardian Threat Fusion**
  dashboard (18 panels) covering the fusion threat level and its model contributions,
  SENTINEL log classification, CASSANDRA cumulative drift, and cross-model corroboration.
  It re-declares the two Week-2 index patterns under their existing ids rather than
  referencing them: `init.sh` globs this folder in shell order, so a bundle that only
  *referenced* a pattern would fail to import whenever it ran first. The definitions are
  identical, so the re-import is a no-op.

Field gotchas when editing these by hand (verified against the live mappings):
`score.threat_level` is `text` (aggregate on `score.threat_level.keyword`), but
`score.reasons`, `alert.source`, `alert.type`, `alert.severity` and `alert.entity_id`
are plain `keyword` — appending `.keyword` to those silently returns zero buckets.
`score.features.*` is model-specific (only cassandra has `cusum_*`, only sentinel has
`template_counts.*`, only guardian has `contributors.*`), so every panel scopes itself
with a `score.model` filter; drop it and the metric goes null instead of erroring.

To change a dashboard: edit it in the UI (http://localhost:5601), then Stack
Management → Saved objects → Export the affected objects and overwrite the bundle here
— committed ndjson is the source of truth, a UI-only change dies with `down -v`.
