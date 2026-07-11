# training

Model training scripts/notebooks land here (Weeks 2–3). Datasets are NOT committed —
download into `training/datasets/` (gitignored).

Planned sources (calibration/validation for the synthetic LTI generator, not literal
training data — no public dataset matches per-API-token FinTech telemetry):

- **ARGUS**: CICIDS2017 / CICDDoS2019 (burst/volumetric shapes); PaySim + IEEE-CIS Fraud
  Detection (financial payload realism)
- **SENTINEL**: AIT Log Data Set v2.0 (line-level ground truth — external validation set);
  Loghub/Loghub-2.0 supplementary; Splunk BOTS v2/v3 for attack-scenario inspiration
- **CASSANDRA**: CERT Insider Threat Dataset r4.2–r6.2 (dedicated slow-exfiltration
  scenario); LANL Unified Host & Network as authenticity cross-check
