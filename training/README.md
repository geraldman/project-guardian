# training

Model training scripts/notebooks land here (Weeks 2–3). Datasets are NOT committed —
download into `training/datasets/` (gitignored).

## Scripts

- `seed_baseline.py` — fast-forwards ARGUS's warmup on a fresh stack by replaying
  backdated benign traffic through capture-agent (real pipeline path, stdlib-only so it
  runs on host Python 3.14). See the ARGUS README for when to use it.

ARGUS itself needs no external training data: it is an unsupervised baseline profiler
that learns "normal" from the traffic it observes. The datasets below calibrate the
generator's realism and provide external validation (planned Week 4), and are never
used as production training data.

Planned sources (calibration/validation for the synthetic LTI generator, not literal
training data — no public dataset matches per-API-token FinTech telemetry):

- **ARGUS**: CICIDS2017 / CICDDoS2019 (burst/volumetric shapes); PaySim + IEEE-CIS Fraud
  Detection (financial payload realism)
- **SENTINEL**: AIT Log Data Set v2.0 (line-level ground truth — external validation set);
  Loghub/Loghub-2.0 supplementary; Splunk BOTS v2/v3 for attack-scenario inspiration
- **CASSANDRA**: CERT Insider Threat Dataset r4.2–r6.2 (dedicated slow-exfiltration
  scenario); LANL Unified Host & Network as authenticity cross-check
