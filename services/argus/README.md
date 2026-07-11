# ARGUS — transaction-rate / payload-size anomaly scorer

**Week 2 — not implemented yet.** FastAPI microservice scoring per-token transaction-rate
and payload-size outliers (Isolation Forest / k-NN, 3σ outside a 7-day rolling baseline).
Consumes normalized events, emits scores back into OpenSearch. Extra-credit layer per
§5.1 of the assignment brief.
