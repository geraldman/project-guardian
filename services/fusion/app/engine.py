"""Fusion engine — the pure Guardian threat-state machine.

Anomalous score documents from the scorer fleet (ARGUS / SENTINEL /
CASSANDRA) fold into per-entity, per-model contributions that decay
exponentially with wall time. The global picture is derived from the decayed
entity scores with a corroboration boost (2+ models on one entity) and moves
through normal -> elevated -> critical with hysteresis.

Pure stdlib on an injected clock: no aiokafka, no wall-clock reads — every
public method takes `now` (epoch seconds), so tests/test_engine.py drives the
whole machine on a simulated clock (host Python 3.14 cannot run aiokafka).

Noise guard (measured on the live stack): ARGUS emits a steady trickle of
`is_anomalous: true` payer docs for 1–6 event buckets (multivariate / rate-z
on near-empty buckets) — ~13k/hour observed — while real attack windows are
the only source of anomalies with `event_count >= 10`. Contributions
therefore require `features.event_count >= min_contrib_events` when that key
is present; content/drift scorers (SENTINEL, CASSANDRA) don't carry
`event_count` and are exempt — malicious log content is malicious at any
volume.
"""
from __future__ import annotations

import logging
import math
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

log = logging.getLogger("fusion.engine")

NORMAL, ELEVATED, CRITICAL = "normal", "elevated", "critical"
LEVELS = (NORMAL, ELEVATED, CRITICAL)
_SEVERITY = {CRITICAL: "high", ELEVATED: "medium", NORMAL: "low"}
_PRUNE_FLOOR = 0.01  # drop an entity once every contribution decayed below this


@dataclass
class FusionConfig:
    """All tunables with their defaults — single source of truth (the
    pydantic Settings in config.py mirrors these for env overrides)."""

    # Per-model weights: how much a full-confidence (anomaly_score=1.0) hit
    # from one model is worth. Each is below elevated<->critical headroom so
    # a single model alone tops out at "elevated"; corroboration or very
    # broad attacks are what reach "critical".
    weight_argus: float = 0.55
    weight_sentinel: float = 0.60
    weight_cassandra: float = 0.50
    weight_default: float = 0.40  # unknown models fold in at this weight

    half_life_seconds: float = 120.0  # contribution decay half-life
    corroboration_boost: float = 0.25  # entity score *= 1 + boost*(models-1)
    active_floor: float = 0.05  # decayed contribution below this stops counting
    breadth_weight: float = 0.05  # global += breadth_weight * log1p(lit_entities-1)
    min_contrib_events: int = 10  # volume floor when features.event_count present
    stale_after_seconds: float = 300.0  # skip score docs older than this

    # Global threat-level hysteresis (separate up/down thresholds).
    elevated_up: float = 0.40
    elevated_down: float = 0.25
    critical_up: float = 0.75
    critical_down: float = 0.55

    emit_interval_seconds: float = 30.0  # periodic guardian doc cadence
    emit_delta: float = 0.15  # also emit when the score moved this much
    top_entities: int = 5
    transitions_kept: int = 20


@dataclass
class _Contribution:
    """One model's decayed, weighted claim on one entity."""

    value: float = 0.0  # weighted contribution as of .ts
    ts: float = 0.0  # epoch seconds of last fold
    weight: float = 1.0  # weight used (kept per-contribution for unweighted view)
    raw_score: float = 0.0  # last incoming anomaly_score
    tag: str = "anomalous"  # short reason tag, e.g. "rate_spike"
    hits: int = 0

    def decayed(self, now: float, half_life: float) -> float:
        if now <= self.ts:
            return self.value
        return self.value * 0.5 ** ((now - self.ts) / half_life)


@dataclass
class _EntityState:
    """Computed (not stored) per-entity picture at a point in time."""

    score: float
    active_models: list[str]  # sorted by contribution, desc
    unweighted: dict[str, float]  # model -> decayed anomaly_score (0..1)
    tags: dict[str, str]  # model -> reason tag
    last_update: float


def _iso(epoch: float) -> str:
    return (
        datetime.fromtimestamp(epoch, tz=timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _parse_ts(value) -> float | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def _reason_tag(reasons) -> str:
    """Compress a scorer's reasons[] into a short tag for guardian reasons
    ("argus:rate_spike"). Tolerant: unknown shapes fall back to a trimmed
    copy of the first reason."""
    if not isinstance(reasons, list) or not reasons:
        return "anomalous"
    r = str(reasons[0])
    if r.startswith(("rate_z", "cohort_rate_z")):
        return "rate_spike"
    if r.startswith("payload_z"):
        return "payload_anomaly"
    if r.startswith("error_ratio"):
        return "error_ratio_spike"
    if r.startswith("multivariate"):
        return "multivariate_outlier"
    if r.startswith("template="):
        return r[len("template="):].split()[0] or "log_classification"
    if r.startswith("cusum") or "drift" in r:
        return "slow_exfiltration"
    return (r.split("=")[0].strip() or "anomalous")[:32]


class FusionEngine:
    def __init__(self, cfg: FusionConfig) -> None:
        self.cfg = cfg
        self.weights = {
            "argus": cfg.weight_argus,
            "sentinel": cfg.weight_sentinel,
            "cassandra": cfg.weight_cassandra,
        }
        # (entity_type, entity_id) -> model -> _Contribution
        self.entities: dict[tuple[str, str], dict[str, _Contribution]] = {}
        self.level = NORMAL
        self.level_since: float | None = None
        self.transitions: deque[dict] = deque(maxlen=cfg.transitions_kept)
        self.unknown_models: set[str] = set()
        self._window_start: float | None = None  # start of the current emit window
        self._last_emit_score = 0.0
        self.counters = {
            "scores_consumed": 0,
            "scores_self_skipped": 0,
            "scores_benign": 0,
            "scores_below_floor": 0,
            "scores_stale": 0,
            "scores_dropped": 0,
            "scores_folded": 0,
            "emits": 0,
            "alerts_emitted": 0,
            "emissions_dropped": 0,
        }

    # -- ingest ---------------------------------------------------------------

    def ingest(self, doc: dict, now: float) -> None:
        """Fold one document from guardian.scores into the threat state."""
        score = doc.get("score") if isinstance(doc, dict) else None
        if not isinstance(score, dict):
            self.counters["scores_dropped"] += 1
            return
        model = str(score.get("model") or "unknown")
        if model == "guardian":
            # Self-feedback guard: we publish to the topic we consume.
            self.counters["scores_self_skipped"] += 1
            return
        self.counters["scores_consumed"] += 1
        try:
            value = float(score.get("anomaly_score") or 0.0)
        except (TypeError, ValueError):
            value = 0.0
        if not score.get("is_anomalous") or value <= 0.0:
            self.counters["scores_benign"] += 1
            return
        ts = _parse_ts(doc.get("@timestamp"))
        if ts is not None and now - ts > self.cfg.stale_after_seconds:
            # Replayed backlog (restart, seed replay) must not re-poison "now".
            self.counters["scores_stale"] += 1
            return
        feats = score.get("features") if isinstance(score.get("features"), dict) else {}
        events = feats.get("event_count")
        if isinstance(events, (int, float)) and events < self.cfg.min_contrib_events:
            self.counters["scores_below_floor"] += 1
            return

        weight = self.weights.get(model)
        if weight is None:
            weight = self.cfg.weight_default
            if model not in self.unknown_models:
                self.unknown_models.add(model)
                log.warning(
                    "unknown score.model %r — folding in with default weight %.2f",
                    model, weight,
                )

        etype = str(score.get("entity_type") or "unknown")
        eid = str(score.get("entity_id") or "unknown")
        contribs = self.entities.setdefault((etype, eid), {})
        c = contribs.setdefault(model, _Contribution())
        # max(), not sum(): a sustained attack pegs the contribution at its
        # strongest hit (bounded by the weight) instead of growing without
        # limit off per-minute re-detections; decay starts once hits stop.
        c.value = max(c.decayed(now, self.cfg.half_life_seconds), weight * min(value, 1.0))
        c.ts = now
        c.weight = weight
        c.raw_score = min(value, 1.0)
        c.tag = _reason_tag(score.get("reasons"))
        c.hits += 1
        self.counters["scores_folded"] += 1

    # -- derived state ----------------------------------------------------------

    def _entity_state(self, contribs: dict[str, _Contribution], now: float) -> _EntityState:
        cfg = self.cfg
        base = 0.0
        decayed: dict[str, float] = {}
        for model, c in contribs.items():
            v = c.decayed(now, cfg.half_life_seconds)
            decayed[model] = v
            base += v
        active = sorted(
            (m for m, v in decayed.items() if v >= cfg.active_floor),
            key=lambda m: decayed[m], reverse=True,
        )
        score = base
        if len(active) >= 2:
            # Corroboration boost: independent models agreeing on one entity
            # is worth more than the plain weighted sum.
            score = base * (1.0 + cfg.corroboration_boost * (len(active) - 1))
        return _EntityState(
            score=min(1.0, score),
            active_models=active,
            unweighted={
                m: min(1.0, decayed[m] / contribs[m].weight)
                for m in active
                if contribs[m].weight > 0
            },
            tags={m: contribs[m].tag for m in active},
            last_update=max((c.ts for c in contribs.values()), default=0.0),
        )

    def _prune(self, now: float) -> None:
        hl = self.cfg.half_life_seconds
        dead = [
            key
            for key, contribs in self.entities.items()
            if all(c.decayed(now, hl) < _PRUNE_FLOOR for c in contribs.values())
        ]
        for key in dead:
            del self.entities[key]

    def _picture(self, now: float) -> dict:
        """The full decayed threat picture at `now` (read-only)."""
        cfg = self.cfg
        states: list[tuple[tuple[str, str], _EntityState]] = [
            (key, self._entity_state(contribs, now))
            for key, contribs in self.entities.items()
        ]
        lit = [(key, st) for key, st in states if st.score >= cfg.active_floor]
        peak = max((st.score for _, st in lit), default=0.0)
        # Breadth: many simultaneously lit entities push the global picture a
        # little above the single worst entity.
        breadth = cfg.breadth_weight * math.log1p(max(0, len(lit) - 1))
        global_score = min(1.0, peak + breadth) if lit else 0.0

        # Per-model contributors: each model's strongest decayed (unweighted)
        # claim across all entities, plus the reason tag it carried there.
        contributors: dict[str, float] = {}
        tags: dict[str, str] = {}
        for _, st in lit:
            for m in st.active_models:
                v = st.unweighted.get(m, 0.0)
                if v > contributors.get(m, 0.0):
                    contributors[m] = v
                    tags[m] = st.tags.get(m, "anomalous")
        corroboration = max((len(st.active_models) for _, st in lit), default=0)

        ranked = sorted(
            (item for item in lit if item[0] != ("global", "global")),
            key=lambda item: item[1].score, reverse=True,
        )
        reasons = [
            f"{m}:{tags[m]}"
            for m in sorted(contributors, key=contributors.get, reverse=True)
        ]
        if corroboration >= 2:
            reasons.append(f"corroborated:{corroboration} models")
        return {
            "global_score": round(global_score, 4),
            "contributors": {m: round(v, 4) for m, v in contributors.items()},
            "corroboration": corroboration,
            "reasons": reasons,
            "top": ranked[: cfg.top_entities],
            "lit_entities": len(lit),
        }

    def _next_level(self, score: float) -> str:
        cfg = self.cfg
        if score >= cfg.critical_up:
            return CRITICAL
        if self.level == CRITICAL:
            if score >= cfg.critical_down:
                return CRITICAL
            return ELEVATED if score >= cfg.elevated_down else NORMAL
        if score >= cfg.elevated_up:
            return ELEVATED
        if self.level == ELEVATED and score >= cfg.elevated_down:
            return ELEVATED
        return NORMAL

    # -- emission ----------------------------------------------------------------

    def tick(self, now: float) -> tuple[list[dict], list[dict]]:
        """Advance the machine to `now`; returns (score_docs, alert_docs) to
        publish. Call it every couple of seconds — it decides internally when
        the ~30s cadence / significant-change / transition rules warrant an
        emission."""
        cfg = self.cfg
        if self._window_start is None:  # first tick: open the emit window
            self._window_start = now
            self.level_since = now
            return [], []
        self._prune(now)
        pic = self._picture(now)
        g = pic["global_score"]

        docs: list[dict] = []
        alerts: list[dict] = []
        forced = False
        new_level = self._next_level(g)
        if new_level != self.level:
            transition = {
                "at": _iso(now), "from": self.level, "to": new_level, "score": g,
            }
            self.transitions.append(transition)
            alerts.append(self._alert_doc(now, self.level, new_level, g, pic))
            self.level = new_level
            self.level_since = now
            forced = True
            self.counters["alerts_emitted"] += 1
            log.info("threat level %s -> %s (score %.2f)",
                     transition["from"], new_level, g)

        due = now - self._window_start >= cfg.emit_interval_seconds
        moved = abs(g - self._last_emit_score) >= cfg.emit_delta
        if forced or due or moved:
            docs.append(self._score_doc(now, g, pic))
            self._window_start = now
            self._last_emit_score = g
            self.counters["emits"] += 1
        return docs, alerts

    def _score_doc(self, now: float, g: float, pic: dict) -> dict:
        start = self._window_start if self._window_start is not None else now
        return {
            "@timestamp": _iso(now),
            "score": {
                "model": "guardian",
                "entity_type": "global",
                "entity_id": "global",
                "anomaly_score": g,
                "threat_level": self.level,
                "is_anomalous": self.level != NORMAL,
                "reasons": pic["reasons"],
                "features": {
                    "contributors": pic["contributors"],
                    "corroboration": pic["corroboration"],
                    "top_entities": [key[1] for key, _ in pic["top"]],
                },
                "window": {
                    "start": _iso(start),
                    "end": _iso(now),
                    "duration_seconds": round(now - start),
                },
            },
        }

    def _alert_doc(self, now: float, old: str, new: str, g: float, pic: dict) -> dict:
        escalating = LEVELS.index(new) > LEVELS.index(old)
        if escalating and pic["top"]:
            (etype, eid), st = pic["top"][0]
            drivers = "+".join(st.active_models) or "scorers"
            extra = pic["lit_entities"] - 1
            cause = f"{drivers} on {etype} {eid}" + (
                f" (+{extra} more entit{'ies' if extra > 1 else 'y'})" if extra > 0 else ""
            )
        elif escalating:
            cause = "+".join(pic["contributors"]) or "scorer activity"
        else:
            cause = "contributions decayed"
        start = self._window_start if self._window_start is not None else now
        return {
            "@timestamp": _iso(now),
            "alert": {
                "id": str(uuid.uuid4()),
                "type": "threat_level_change",
                "severity": _SEVERITY[new],
                "entity_type": "global",
                "entity_id": "global",
                "score": g,
                "source": "guardian",
                "summary": (
                    f"Guardian threat level {'escalated' if escalating else 'recovered'} "
                    f"from {old} to {new} (score {g:.2f}): {cause}."
                ),
                "window": {"start": _iso(start), "end": _iso(now)},
                "details": {
                    "from": old,
                    "to": new,
                    "contributors": pic["contributors"],
                    "corroboration": pic["corroboration"],
                    "top_entities": [key[1] for key, _ in pic["top"]],
                },
            },
        }

    # -- read side (GET /threat) ---------------------------------------------------

    def snapshot(self, now: float) -> dict:
        """Current picture for the HUD. Read-only: the level shown is the one
        set by the last tick (at most tick-interval seconds stale)."""
        pic = self._picture(now)
        cfg = self.cfg
        return {
            "threat_level": self.level,
            "anomaly_score": pic["global_score"],
            "is_anomalous": self.level != NORMAL,
            "level_since": _iso(self.level_since) if self.level_since else None,
            "contributors": pic["contributors"],
            "corroboration": pic["corroboration"],
            "reasons": pic["reasons"],
            "top_entities": [
                {
                    "entity_type": key[0],
                    "entity_id": key[1],
                    "score": round(st.score, 4),
                    "models": {m: round(v, 4) for m, v in st.unweighted.items()},
                    "corroborated": len(st.active_models) >= 2,
                    "reasons": [f"{m}:{st.tags[m]}" for m in st.active_models],
                    "last_update": _iso(st.last_update),
                }
                for key, st in pic["top"]
            ],
            "recent_transitions": list(self.transitions),
            "entities_tracked": len(self.entities),
            "unknown_models": sorted(self.unknown_models),
            "counters": dict(self.counters),
            "config": {
                "weights": {**self.weights, "default": cfg.weight_default},
                "half_life_seconds": cfg.half_life_seconds,
                "corroboration_boost": cfg.corroboration_boost,
                "breadth_weight": cfg.breadth_weight,
                "min_contrib_events": cfg.min_contrib_events,
                "thresholds": {
                    "elevated_up": cfg.elevated_up,
                    "elevated_down": cfg.elevated_down,
                    "critical_up": cfg.critical_up,
                    "critical_down": cfg.critical_down,
                },
            },
        }
