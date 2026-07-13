# SENTINEL — log-line classification

FastAPI + aiokafka microservice that classifies API-gateway log content.
Consumes `guardian.telemetry.normalized` (consumer group `guardian-sentinel`),
scores 1-minute windows per `client_ip`, and publishes score documents to
`guardian.scores` (`score.model: "sentinel"`) and `log_classification` alerts
to `guardian.alerts` (`alert.source: "sentinel"`) — the same flattened
envelopes ARGUS emits, so Vector and the alerting service need zero changes.
Contracts: docs/architecture.md ("Detection layer — Week 3 scorers").

Its niche is the generator's `log_attack` mode: malicious log *content* at
normal traffic rates (SQL injection, path traversal, credential stuffing,
scanner probes) that never moves ARGUS's rate/error detectors. Conversely,
rate spikes are ARGUS's niche: benign bursts must not — and do not — trip
SENTINEL.

## Detection design

Three stages, all pure Python (no Kafka imports) in `app/{logparse,rules,features,pipeline}.py`:

1. **Template mining (Drain3).** Each event's `log.message`
   (`<ip> - <payer> [<ts>] "<METHOD> <path> HTTP/1.1" <code> <bytes> <lat>ms "<msg>"`)
   is regex-parsed into structured fields, then the content
   (`method path code "msg"`) is mined by Drain3 with aggressive masking
   (IPs, entity ids, hex ids, numbers). All downstream signals are computed
   over stable templates, never incidental values. Live template set:
   `GET /templates`.
2. **Rule pre-filter (level 0).** Unambiguous signatures score immediately —
   SQL metacharacters in the query, `../` / `..%2f` traversal, sensitive-file
   and admin-panel probes (`/.env`, `/.git`, `*.php`, `/actuator/`), and
   auth-failure storms (≥ `AUTH_FAIL_STORM` 401s from one IP in one window).
   One SQLi line is sufficient evidence: no volume floor applies.
3. **Windowed XGBoost (the ambiguous middle).** Events aggregate into
   1-minute tumbling windows per `client_ip` (same per-partition watermark +
   wall-clock flush scheme as ARGUS). Window features — per-family template
   counts, distinct templates, auth-fail/4xx ratios, window size — feed a
   3-class XGBoost model (benign / suspicious / malicious).
   `model_score = P(malicious) + 0.5 · P(suspicious)`; ≥ `ANOMALY_THRESHOLD`
   with ≥ `MIN_WINDOW_EVENTS` events is anomalous, the
   [`SUSPICIOUS_THRESHOLD`, `ANOMALY_THRESHOLD`) band is surfaced in score
   docs but never alerts. The *suspicious* class is defined by the rule
   engine's confidence bands (`rules.window_rule_level`), so labels are
   reproducible from code — no manual labeling.

Alerts are capped at `MAX_ALERTS_PER_WINDOW` per minute (flood guard, worst
first, mirroring ARGUS); every anomalous window still lands in
`guardian-scores-*`, and the alerting service's `(entity_type, entity_id,
type)` dedup keys distinct IPs separately.

Events without a `log` object (queued events predating the Week-3 envelope)
advance the stream's watermark but are skipped, never fatal.

`auto_offset_reset` is `latest`, deliberately unlike ARGUS: SENTINEL ships a
pre-trained model and needs no replay for baselines; an `earliest` first boot
would re-score ~6h of backlog and page stale, old-timestamped alerts.
Committed offsets still resume normally across restarts.

## Model artifact

`model/sentinel_xgb.json` (+ `metadata.json`) is a committed, deterministic
artifact: `training/train_sentinel.py` uses a fixed seed and single-threaded
hist training, so a rerun is byte-identical. The Docker build therefore needs
no network, datasets, or training step. The service refuses to boot if the
artifact's feature order or classes disagree with the code.

Retrain (host Python, after `pip install xgboost drain3 numpy pydantic-settings`):

```
python training/train_sentinel.py            # regenerates services/sentinel/model/
python -m pytest services/sentinel/tests -q  # revalidate before committing
```

Retrain whenever `app/features.FEATURE_NAMES`, the rule bands, or the
generator's log families change (`services/mock-lti/app/generator.py` carries
a matching warning).

## Configuration (env)

| Env | Default | Meaning |
|---|---|---|
| `REDPANDA_BROKERS` | `redpanda:9092` | Kafka bootstrap |
| `INPUT_TOPIC` | `guardian.telemetry.normalized` | consumed (group `guardian-sentinel`) |
| `SCORES_TOPIC` | `guardian.scores` | score documents out |
| `ALERTS_TOPIC` | `guardian.alerts` | alerts out |
| `WINDOW_SECONDS` | `60` | tumbling window size |
| `ANOMALY_THRESHOLD` | `0.70` | model-score alert bar |
| `SUSPICIOUS_THRESHOLD` | `0.40` | bottom of the suspicious band |
| `AUTH_FAIL_STORM` | `3` | 401s/window that make credential stuffing unambiguous |
| `MIN_WINDOW_EVENTS` | `3` | volume floor for model-only anomalies (level-0 exempt) |
| `MIN_SCORE_EVENTS` | `3` | volume floor for score-doc emission |
| `MAX_ALERTS_PER_WINDOW` | `5` | per-minute alert flood guard |
| `MODEL_PATH` | `model/sentinel_xgb.json` | committed XGBoost artifact |
| `FLUSH_AFTER_SECONDS` / `FLUSH_IDLE_SECONDS` | `75` / `15` | stalled-stream window flush |

## Endpoints

- `GET /health` — `ok` / `degraded` (consumer connectivity), model info.
- `GET /stats` — pipeline counters, mined-template count, effective config.
- `GET /templates` — the live Drain3 template set (top 100 by frequency).

## Offline validation

`tests/test_pipeline.py` runs the pure pipeline without Kafka or the stack:
every pinned benign family, each attack technique, envelope-contract checks,
robustness cases, and a 6-minute soak simulation (10 ev/s, `log_attack`
p=0.08 over 20 attacker IPs, then a benign burst) asserting attacker IPs
alert on the first finalized window while no benign IP — burst included —
ever does.
