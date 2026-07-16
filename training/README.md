# training

Model training scripts/notebooks land here (Weeks 2–3). Datasets are NOT committed —
download into `training/datasets/` (gitignored).

## Scripts

- `seed_baseline.py` / `seed_history.py` — fast-forward ARGUS's / CASSANDRA's warmup on a
  fresh stack by replaying backdated benign traffic through capture-agent (real pipeline
  path, stdlib-only so they run on host Python 3.14). See the ARGUS/CASSANDRA READMEs.
- `validate_sentinel_ait.py` — external validation of SENTINEL against AIT-LDS v1.1
  (independent per-line ground truth). Needs `numpy`/`xgboost`/`drain3`; those pinned
  versions lack Python 3.14 wheels, so run it in a 3.13 venv (see below).
- `validate_cassandra_cert.py` — external validation of CASSANDRA against CERT r4.2
  (insider-threat exfiltration ground truth). Stdlib-only, host Python 3.14.

Both validators reuse the **shipped** detection code and never retrain the models — see
[docs/external_validation.md](../docs/external_validation.md) for method and results.

ARGUS itself needs no external training data: it is an unsupervised baseline profiler
that learns "normal" from the traffic it observes.

### Running the external validators

```sh
# datasets go under training/datasets/ (gitignored)
#   AIT-LDS v1.1  -> https://zenodo.org/records/4264796  (AIT-LDS-v1_1.zip, ~3.4 GB)
#   CERT r4.2     -> https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247

# SENTINEL needs a 3.13 venv (numpy/xgboost/drain3 lack 3.14 wheels):
py -3.13 -m venv .venv-val
.venv-val/Scripts/python.exe -m pip install numpy==2.2.4 xgboost==3.3.0 drain3==0.9.11 pydantic-settings==2.8.1
.venv-val/Scripts/python.exe training/validate_sentinel_ait.py --dataset training/datasets/AIT-LDS-v1_1

# CASSANDRA is stdlib-only on host Python 3.14:
python training/validate_cassandra_cert.py --dataset training/datasets/r4.2
```

Each validator has a `--self-test` that checks its adapter without the dataset.

### Datasets referenced

Calibration/validation for the synthetic LTI generator, not literal training data — no
public dataset matches per-API-token FinTech telemetry:

- **ARGUS**: CICIDS2017 / CICDDoS2019 (burst/volumetric shapes); PaySim + IEEE-CIS Fraud
  Detection (financial payload realism)
- **SENTINEL**: **AIT Log Data Set v1.1** — line-level ground truth, wired up as the
  external validation set (Zenodo 4264796; v1.1 chosen over v2.0's 130 GB); Loghub /
  Splunk BOTS as supplementary inspiration
- **CASSANDRA**: **CERT Insider Threat Dataset r4.2** — removable-media exfiltration
  scenario with ground truth; LANL Unified Host & Network as an authenticity cross-check
