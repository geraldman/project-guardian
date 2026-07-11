# CASSANDRA — slow-exfiltration detector

**Week 3 — not implemented yet.** Detects low-and-slow exfiltration on hourly/daily
aggregated per-entity feature vectors. CUSUM/EWMA control charts are the production
backbone (quantifiable false-alarm rate); an LSTM autoencoder on the aggregated vectors
is a secondary shape detector, attempted only if ahead of schedule. Per-entity threshold
calibration; needs ~14 days of clean history per entity before activation.
