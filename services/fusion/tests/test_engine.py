"""Offline validation for the fusion threat-state engine.

Drives the pure state machine (app/engine.py) with synthetic score documents
on a simulated clock — no Kafka, no wall clock, stdlib only, so it runs on
host Python 3.14 where aiokafka does not build:

    python services/fusion/tests/test_engine.py

Also pytest-compatible (plain assert functions).
"""
from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.engine import CRITICAL, ELEVATED, NORMAL, FusionConfig, FusionEngine  # noqa: E402

T0 = 1_780_000_000.0  # arbitrary epoch anchor for the simulated clock
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _iso(epoch: float) -> str:
    return (
        datetime.fromtimestamp(epoch, tz=timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def argus_doc(ts, eid="10.9.9.9", etype="client_ip", score=1.0, events=200,
              reasons=None):
    """Shape-accurate copy of a live ARGUS score doc (guardian-scores-*)."""
    return {
        "@timestamp": _iso(ts),
        "score": {
            "model": "argus",
            "entity_type": etype,
            "entity_id": eid,
            "anomaly_score": score,
            "is_anomalous": True,
            "warming_up": False,
            "reasons": reasons or ["cohort_rate_z=12.3>3"],
            "features": {
                "event_count": events, "mean_payload_bytes": 703.3,
                "error_ratio": 0.04, "malformed_count": 0,
                "mean_amount": 179527.92,
            },
            "baseline": {"rate_mean": 2.1, "rate_std": 15.8, "buckets_observed": 144023},
            "window": {"start": _iso(ts - 60), "end": _iso(ts), "duration_seconds": 60},
        },
    }


def sentinel_doc(ts, eid="10.9.9.9", etype="client_ip", score=0.88):
    """Per the pinned SENTINEL envelope in docs/architecture.md."""
    return {
        "@timestamp": _iso(ts),
        "score": {
            "model": "sentinel",
            "entity_type": etype,
            "entity_id": eid,
            "anomaly_score": score,
            "is_anomalous": True,
            "reasons": ["template=sqli_probe count=7", "auth_fail_ratio=0.6"],
            "features": {
                "template_counts": {"sqli_probe": 7, "scanner_probe": 3},
                "window_events": 24, "distinct_templates": 5,
            },
            "window": {"start": _iso(ts - 60), "end": _iso(ts), "duration_seconds": 60},
        },
    }


def drain(engine, start, end, step=10.0):
    """Tick the engine across [start, end]; returns (score_docs, alerts)."""
    docs, alerts = [], []
    t = start
    while t <= end:
        d, a = engine.tick(t)
        docs.extend(d)
        alerts.extend(a)
        t += step
    return docs, alerts


# ── 1. burst -> elevated -> decay -> normal ─────────────────────────────────

def test_burst_elevates_then_decays_to_normal():
    eng = FusionEngine(FusionConfig())
    eng.tick(T0 - 5)  # baseline tick (opens the emit window)

    # ARGUS flags two flood IPs for three consecutive minutes.
    for minute in (0, 60, 120):
        for ip in ("10.0.0.1", "10.0.0.2"):
            eng.ingest(argus_doc(T0 + minute, eid=ip), now=T0 + minute)

    docs, alerts = drain(eng, T0 + 2, T0 + 130, step=2.0)
    assert eng.level == ELEVATED, f"expected elevated during attack, got {eng.level}"
    ups = [a for a in alerts if a["alert"]["details"]["to"] == ELEVATED]
    assert len(ups) == 1, f"expected exactly one upward transition, got {len(ups)}"
    up = ups[0]["alert"]
    assert up["type"] == "threat_level_change" and up["source"] == "guardian"
    assert up["details"]["from"] == NORMAL and up["severity"] == "medium"
    # Transition happened on the first tick after the first anomalous score.
    assert ups[0]["@timestamp"] == _iso(T0 + 2)
    hot = [d for d in docs if d["score"]["threat_level"] == ELEVATED]
    assert hot and hot[0]["score"]["is_anomalous"] is True
    assert set(hot[0]["score"]["features"]["top_entities"]) == {"10.0.0.1", "10.0.0.2"}

    # Attack stops after T0+120 — the state must decay back on its own.
    docs2, alerts2 = drain(eng, T0 + 132, T0 + 1200, step=10.0)
    downs = [a for a in alerts2 if a["alert"]["details"]["to"] == NORMAL]
    assert eng.level == NORMAL, f"expected normal after decay, got {eng.level}"
    assert len(downs) == 1 and len(alerts2) == 1, "exactly one downward transition"
    down = downs[0]["alert"]
    assert down["details"]["from"] == ELEVATED and down["severity"] == "low"
    down_at = datetime.fromisoformat(down["window"]["end"].replace("Z", "+00:00")).timestamp()
    # 0.55 peak + breadth decays below elevated_down=0.25 ~162s after the
    # last contribution (half-life 120s): recovery lands within minutes.
    assert 120 <= down_at - (T0 + 120) <= 420, f"recovery took {down_at - (T0 + 120):.0f}s"
    assert eng.snapshot(T0 + 1200)["anomaly_score"] < 0.25


# ── 2. corroboration boost ───────────────────────────────────────────────────

def test_corroboration_boost_exceeds_single_models():
    cfg = FusionConfig()
    ip = "45.148.10.19"

    solo_argus = FusionEngine(cfg)
    solo_argus.ingest(argus_doc(T0, eid=ip, score=0.6), now=T0)
    argus_only = solo_argus.snapshot(T0)["top_entities"][0]["score"]

    solo_sentinel = FusionEngine(cfg)
    solo_sentinel.ingest(sentinel_doc(T0, eid=ip, score=0.5), now=T0)
    sentinel_only = solo_sentinel.snapshot(T0)["top_entities"][0]["score"]

    both = FusionEngine(cfg)
    both.tick(T0 - 5)
    both.ingest(argus_doc(T0, eid=ip, score=0.6), now=T0)
    both.ingest(sentinel_doc(T0, eid=ip, score=0.5), now=T0)
    entity = both.snapshot(T0)["top_entities"][0]

    plain_sum = argus_only + sentinel_only  # weighted sum without the boost
    expected = plain_sum * (1 + cfg.corroboration_boost)  # 2 models -> 1 extra
    assert abs(entity["score"] - round(expected, 4)) < 1e-3
    assert entity["score"] > plain_sum > max(argus_only, sentinel_only)
    assert entity["corroborated"] is True

    docs, _ = both.tick(T0 + 2)
    feats = docs[0]["score"]["features"]
    assert feats["corroboration"] == 2
    assert "corroborated:2 models" in docs[0]["score"]["reasons"]
    assert set(feats["contributors"]) == {"argus", "sentinel"}
    # Contributors are the models' decayed raw anomaly scores, not weighted.
    assert abs(feats["contributors"]["argus"] - 0.6) < 0.01
    assert abs(feats["contributors"]["sentinel"] - 0.5) < 0.01
    # Two corroborating models push past critical_up where either alone
    # would not even leave normal/elevated.
    assert both.level == CRITICAL


# ── 3. hysteresis ────────────────────────────────────────────────────────────

def test_hysteresis_boundary_hover_does_not_flap():
    cfg = FusionConfig()
    eng = FusionEngine(cfg)
    eng.tick(T0 - 5)
    # One entity at 0.55*0.78 = 0.429: just above elevated_up=0.40; between
    # re-feeds it decays into the 0.25..0.40 hysteresis band.
    t = T0
    for _ in range(4):
        eng.ingest(argus_doc(t, eid="10.7.7.7", score=0.78), now=t)
        drain(eng, t + 2, t + 60, step=2.0)
        t += 62
    assert eng.level == ELEVATED
    assert len(eng.transitions) == 1, (
        f"level flapped: {[tr['to'] for tr in eng.transitions]}"
    )
    # Full decay finally drops it below elevated_down -> exactly one more.
    drain(eng, t, t + 400, step=10.0)
    assert eng.level == NORMAL and len(eng.transitions) == 2


def test_hysteresis_critical_band():
    eng = FusionEngine(FusionConfig())
    eng.level = CRITICAL
    assert eng._next_level(0.80) == CRITICAL   # above critical_up
    assert eng._next_level(0.60) == CRITICAL   # in the 0.55..0.75 hold band
    assert eng._next_level(0.50) == ELEVATED   # below critical_down
    assert eng._next_level(0.20) == NORMAL     # straight down past both
    eng.level = ELEVATED
    assert eng._next_level(0.74) == ELEVATED   # does not re-enter critical
    assert eng._next_level(0.30) == ELEVATED   # 0.25..0.40 hold band
    assert eng._next_level(0.24) == NORMAL
    eng.level = NORMAL
    assert eng._next_level(0.39) == NORMAL     # below elevated_up
    assert eng._next_level(0.76) == CRITICAL   # can jump straight to critical


# ── 4. self-feedback guard ───────────────────────────────────────────────────

def test_guardian_docs_are_ignored():
    eng = FusionEngine(FusionConfig())
    eng.tick(T0 - 5)
    # Craft a hot guardian doc the way fusion itself would emit one.
    hot = FusionEngine(FusionConfig())
    hot.tick(T0 - 5)
    hot.ingest(argus_doc(T0), now=T0)
    hot.ingest(sentinel_doc(T0), now=T0)
    docs, _ = hot.tick(T0 + 2)
    assert docs and docs[0]["score"]["model"] == "guardian"

    eng.ingest(docs[0], now=T0 + 3)
    assert eng.counters["scores_self_skipped"] == 1
    assert eng.counters["scores_folded"] == 0 and not eng.entities
    eng.tick(T0 + 4)
    assert eng.level == NORMAL
    assert eng.snapshot(T0 + 4)["anomaly_score"] == 0.0


# ── 5. envelope contract ─────────────────────────────────────────────────────

def test_emitted_envelopes_match_contract():
    eng = FusionEngine(FusionConfig())
    eng.tick(T0 - 5)
    eng.ingest(argus_doc(T0, eid="45.148.10.19"), now=T0)
    eng.ingest(sentinel_doc(T0, eid="45.148.10.19"), now=T0)
    docs, alerts = eng.tick(T0 + 2)
    assert len(docs) == 1 and len(alerts) == 1

    doc = docs[0]
    assert set(doc) == {"@timestamp", "score"}
    assert ISO_RE.match(doc["@timestamp"])
    s = doc["score"]
    assert set(s) == {"model", "entity_type", "entity_id", "anomaly_score",
                      "threat_level", "is_anomalous", "reasons", "features",
                      "window"}
    assert s["model"] == "guardian"
    assert s["entity_type"] == "global" and s["entity_id"] == "global"
    assert isinstance(s["anomaly_score"], float) and 0.0 <= s["anomaly_score"] <= 1.0
    assert s["threat_level"] in (NORMAL, ELEVATED, CRITICAL)
    assert isinstance(s["is_anomalous"], bool)
    assert isinstance(s["reasons"], list) and all(isinstance(r, str) for r in s["reasons"])
    assert "argus:rate_spike" in s["reasons"] and "sentinel:sqli_probe" in s["reasons"]
    f = s["features"]
    assert set(f) == {"contributors", "corroboration", "top_entities"}
    assert all(isinstance(v, float) for v in f["contributors"].values())
    assert isinstance(f["corroboration"], int)
    assert f["top_entities"] == ["45.148.10.19"]
    w = s["window"]
    assert set(w) == {"start", "end", "duration_seconds"}
    assert ISO_RE.match(w["start"]) and ISO_RE.match(w["end"])
    assert isinstance(w["duration_seconds"], int)

    alert = alerts[0]
    assert set(alert) == {"@timestamp", "alert"}
    a = alert["alert"]
    assert set(a) == {"id", "type", "severity", "entity_type", "entity_id",
                      "score", "source", "summary", "window", "details"}
    assert a["type"] == "threat_level_change" and a["source"] == "guardian"
    assert a["severity"] in ("low", "medium", "high")
    assert a["entity_type"] == "global" and a["entity_id"] == "global"
    assert set(a["window"]) == {"start", "end"}
    assert a["details"]["from"] == NORMAL and a["details"]["to"] == eng.level


# ── 6. live-noise guard, unknown models, stale docs ──────────────────────────

def test_low_volume_argus_noise_cannot_move_the_level():
    """Live-measured: ARGUS emits ~13k/h is_anomalous=true payer docs with
    event_count 1..6 on benign steady state. They must not contribute."""
    eng = FusionEngine(FusionConfig())
    eng.tick(T0 - 5)
    t = T0
    for i in range(120):  # 2 "hours" of scattered benign payer anomalies
        eng.ingest(
            argus_doc(t, eid=f"wallet-user-{i:04d}", etype="payer", score=1.0,
                      events=1 + i % 6,
                      reasons=["multivariate=1.00 (iforest_df=-0.17, knn_ratio=0.2)"]),
            now=t,
        )
        eng.tick(t + 1)
        t += 60
    assert eng.counters["scores_below_floor"] == 120
    assert eng.counters["scores_folded"] == 0
    assert eng.level == NORMAL and not eng.entities


def test_unknown_model_folds_with_default_weight():
    cfg = FusionConfig()
    eng = FusionEngine(cfg)
    doc = sentinel_doc(T0, eid="payer-x", etype="payer", score=0.8)
    doc["score"]["model"] = "medusa"  # not a known scorer
    eng.ingest(doc, now=T0)
    ent = eng.snapshot(T0)["top_entities"][0]
    assert abs(ent["score"] - cfg.weight_default * 0.8) < 1e-6
    assert "medusa" in eng.snapshot(T0)["unknown_models"]


def test_stale_and_benign_docs_are_skipped():
    eng = FusionEngine(FusionConfig())
    eng.ingest(argus_doc(T0 - 3600), now=T0)  # old @timestamp: replayed backlog
    assert eng.counters["scores_stale"] == 1
    benign = argus_doc(T0)
    benign["score"]["is_anomalous"] = False
    benign["score"]["anomaly_score"] = 0.0
    eng.ingest(benign, now=T0)
    assert eng.counters["scores_benign"] == 1
    eng.ingest({"not": "a score"}, now=T0)
    assert eng.counters["scores_dropped"] == 1
    assert not eng.entities


# ── 7. emit cadence ──────────────────────────────────────────────────────────

def test_quiet_state_emits_on_30s_cadence():
    eng = FusionEngine(FusionConfig())
    docs, alerts = drain(eng, T0, T0 + 70, step=2.0)
    assert not alerts
    assert len(docs) == 2, f"expected 2 cadence emits in 70s, got {len(docs)}"
    for doc in docs:
        s = doc["score"]
        assert s["threat_level"] == NORMAL and s["is_anomalous"] is False
        assert s["anomaly_score"] == 0.0
        assert s["features"] == {"contributors": {}, "corroboration": 0,
                                 "top_entities": []}
        assert 28 <= s["window"]["duration_seconds"] <= 34


TESTS = [
    test_burst_elevates_then_decays_to_normal,
    test_corroboration_boost_exceeds_single_models,
    test_hysteresis_boundary_hover_does_not_flap,
    test_hysteresis_critical_band,
    test_guardian_docs_are_ignored,
    test_emitted_envelopes_match_contract,
    test_low_volume_argus_noise_cannot_move_the_level,
    test_unknown_model_folds_with_default_weight,
    test_stale_and_benign_docs_are_skipped,
    test_quiet_state_emits_on_30s_cadence,
]

if __name__ == "__main__":
    failed = 0
    for test in TESTS:
        try:
            test()
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {test.__name__}: {exc}")
        else:
            print(f"PASS  {test.__name__}")
    print(f"\n{len(TESTS) - failed}/{len(TESTS)} passed")
    sys.exit(1 if failed else 0)
