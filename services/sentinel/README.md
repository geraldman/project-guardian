# SENTINEL — log classifier

**Week 3 — not implemented yet.** FastAPI microservice classifying log windows
malicious/suspicious/benign. Approach (per methodology review): Drain3 template parsing →
sliding-window aggregated features per source/session → XGBoost, with a rule/regex
pre-filter for known-bad templates. External validation against AIT-LDS v2.0 ground truth.
