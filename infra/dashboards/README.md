# Dashboards saved objects

`saved_objects.ndjson` (not yet committed) is the exported OpenSearch Dashboards bundle:
index pattern `guardian-traffic-*`, the traffic-volume / error-rate / channel-breakdown
visualizations, and the combined **Guardian Traffic Overview** dashboard.

Workflow (`feat/dashboards`, after the pipeline is integrated and data is flowing):

1. Build the visualizations by hand in the Dashboards UI (http://localhost:5601).
2. Stack Management → Saved objects → Export → save as `saved_objects.ndjson` here.
3. Commit it. `opensearch-init` auto-imports it on every `docker compose up`, which is
   what makes the dashboard reproducible from a clean checkout.
