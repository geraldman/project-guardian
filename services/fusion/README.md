# fusion — unified Guardian threat state

FastAPI + aiokafka microservice. Consumes `guardian.scores` (consumer group
`guardian-fusion`) — the combined output of ARGUS, SENTINEL and CASSANDRA — and folds
every anomalous score into a decayed per-entity threat state plus a global threat level.
It publishes `score.model: "guardian"` documents back to `guardian.scores` (~every 30s
and on any significant change) and `threat_level_change` alerts to `guardian.alerts` on
level transitions. Pure Kafka-in/Kafka-out — Vector carries both topics into OpenSearch.

Its own `score.model == "guardian"` documents are filtered out on consume (it publishes
to the topic it reads), so there is no self-feedback loop.

Contracts (envelope, alert type, `/threat`): `docs/architecture.md#fusion--unified-guardian-threat-state`.

## Threat model math

**Per-entity, per-model contributions.** An incoming anomalous score from model *m* for
entity *e* sets that model's contribution on the entity to

```
c[e][m] = max(decayed current value, weight_m x anomaly_score)
```

`max`, not sum: a sustained attack re-detected every minute pegs the contribution at its
strongest hit (bounded by the model weight) instead of growing without limit; decay
starts the moment hits stop. Contributions decay exponentially with wall time:
`value x 0.5^(age / HALF_LIFE_SECONDS)` — so the picture recovers to normal on its own
after an attack ends.

**Corroboration boost (the signature feature).** When 2+ models hold an active
contribution (>= `ACTIVE_FLOOR`) on the same entity within the decay window — e.g.
ARGUS rate + SENTINEL log content on one client_ip — the entity scores above the plain
weighted sum:

```
entity_score = min(1, sum(contributions) x (1 + CORROBORATION_BOOST x (models - 1)))
```

With defaults, one model alone tops out at its weight (~0.55 → *elevated*); two
corroborating models blow past `CRITICAL_UP` where either alone would not — one scorer
firing means *elevated*, independent agreement means *critical*. Corroborated entities
carry `"corroborated:N models"` in `reasons` and `features.corroboration = N`.

**Global score.** The worst entity plus a small breadth term for how many entities are
lit simultaneously:

```
global = min(1, max(entity_scores) + BREADTH_WEIGHT x log1p(lit_entities - 1))
```

**Threat level with hysteresis.** `normal -> elevated -> critical` on the decayed global
score, with separate up/down thresholds so a score hovering at a boundary cannot flap
the level: escalate at `ELEVATED_UP` / `CRITICAL_UP`, but de-escalate only below
`ELEVATED_DOWN` / `CRITICAL_DOWN`.

**Noise floor (measured on the live stack).** ARGUS emits a steady trickle of
`is_anomalous: true` payer score docs for 1–6-event buckets (~13k/hour observed on
benign steady state), while real attack windows are the only source of anomalies with
`event_count >= 10`. A score therefore only contributes when `features.event_count`
(if present) is >= `MIN_CONTRIB_EVENTS`. SENTINEL/CASSANDRA docs don't carry
`event_count` and are exempt — malicious log content or cumulative drift is meaningful
at any volume. Unknown `score.model` values fold in at `WEIGHT_DEFAULT` (logged once);
docs whose `@timestamp` is older than `STALE_AFTER_SECONDS` (replayed backlog after a
restart) are skipped.

### Tuning (env, all with working defaults)

| Env | Default | Meaning |
|---|---|---|
| `WEIGHT_ARGUS` / `WEIGHT_SENTINEL` / `WEIGHT_CASSANDRA` | 0.55 / 0.60 / 0.50 | value of a full-confidence hit per model |
| `WEIGHT_DEFAULT` | 0.40 | weight for unknown `score.model` values |
| `HALF_LIFE_SECONDS` | 120 | contribution decay half-life |
| `CORROBORATION_BOOST` | 0.25 | per extra corroborating model |
| `ACTIVE_FLOOR` | 0.05 | decayed contribution below this stops counting |
| `BREADTH_WEIGHT` | 0.05 | global bonus per log-scale lit entity |
| `MIN_CONTRIB_EVENTS` | 10 | volume floor when `features.event_count` present |
| `STALE_AFTER_SECONDS` | 300 | skip score docs older than this |
| `ELEVATED_UP` / `ELEVATED_DOWN` | 0.40 / 0.25 | elevated hysteresis band |
| `CRITICAL_UP` / `CRITICAL_DOWN` | 0.75 / 0.55 | critical hysteresis band |
| `EMIT_INTERVAL_SECONDS` / `EMIT_DELTA` | 30 / 0.15 | emit cadence / significant-change trigger |
| `TICK_SECONDS` | 2 | internal decay/level-check cadence |

Expected pacing with defaults: a burst elevates the level on the first anomalous ARGUS
score (~60–90s after attack start, dominated by ARGUS's 1-minute buckets) and decays
back to `normal` roughly 3–5 minutes after the attack stops (last ARGUS bucket + ~1.4
half-lives).

## Emissions

- **Score doc** (`guardian.scores` → `guardian-scores-*`): `score.model: "guardian"`,
  `entity_type/entity_id: "global"`, `anomaly_score`, `threat_level`, `is_anomalous`
  (level != normal), `reasons` (`"argus:rate_spike"`, `"corroborated:2 models"`, ...),
  `features.contributors` (per-model decayed peak anomaly score), `features.corroboration`,
  `features.top_entities`, `window` covering the emit interval. Emitted every
  `EMIT_INTERVAL_SECONDS`, on any level transition, and whenever the global score moved
  by >= `EMIT_DELTA` since the last emission.
- **Alert** (`guardian.alerts` → alerting + `guardian-alerts-*`): on every level
  transition, either direction — `alert.type: "threat_level_change"`,
  `alert.source: "guardian"`, severity by target level (critical=high, elevated=medium,
  normal=low), `details.from/to/contributors/corroboration/top_entities`. The alerting
  service's `(entity_type, entity_id, type)` 300s dedup applies: rapid multi-step
  transitions inside one dedup window reach Slack/Discord once (all of them still land
  in `guardian-alerts-*`).

## Endpoints (:8006)

| Endpoint | Purpose |
|---|---|
| `GET /health` | consumer status, current level, entities tracked, topics |
| `GET /threat` | the full current picture (Guardian Pulse HUD feed) |

`GET /threat` shape:

```json
{
  "threat_level": "elevated",
  "anomaly_score": 0.58,
  "is_anomalous": true,
  "level_since": "2026-07-13T04:02:10Z",
  "contributors": {"argus": 1.0},
  "corroboration": 1,
  "reasons": ["argus:rate_spike"],
  "top_entities": [
    {"entity_type": "client_ip", "entity_id": "10.1.67.14", "score": 0.55,
     "models": {"argus": 1.0}, "corroborated": false,
     "reasons": ["argus:rate_spike"], "last_update": "2026-07-13T04:03:00Z"}
  ],
  "recent_transitions": [
    {"at": "2026-07-13T04:02:10Z", "from": "normal", "to": "elevated", "score": 0.58}
  ],
  "entities_tracked": 3,
  "unknown_models": [],
  "counters": {"scores_consumed": 1234, "scores_folded": 6, "...": 0},
  "config": {"weights": {}, "half_life_seconds": 120, "thresholds": {}}
}
```

## Offset reset / persistence

`auto_offset_reset="latest"`: fusion models the *current* threat state — replaying the
queue's ~6h score retention on first boot would light up today's picture with attacks
that ended hours ago. Skipping history costs nothing (the state's half-life is minutes).
For the same reason the state is not persisted across restarts: it re-forms from the
live stream within a couple of minutes, unlike ARGUS baselines which take far longer to
learn and are therefore snapshotted.

## Local dev / offline validation

Host Python 3.14 cannot build aiokafka wheels — run the service in the container:
`docker compose up -d --build fusion && docker compose logs -f fusion`.

All fusion math lives in the pure `app/engine.py` (stdlib only, injected clock), so the
full state machine — decay, weighting, corroboration, hysteresis, envelopes — validates
offline on any Python:

```
python services/fusion/tests/test_engine.py
```
