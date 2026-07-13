"""Offline validation for CASSANDRA — runs on host Python, no stack needed.

The detection core (app/detector.py, app/pipeline.py) is stdlib-pure, so the
whole detection path — bucket aggregation, watermark finalization, CUSUM
scoring, envelope construction — is exercised here exactly as it runs in the
container, minus aiokafka.

Scenarios (shipped defaults, i.e. exactly what compose runs):
  1. warm payer baseline, then a slow_exfil-shaped trickle (~+2 events/min at
     1.8x amounts, the generator's defaults) -> alarm on every one of 25
     seeds, median delay <=10 simulated minutes, all <=25 (a persistent
     shift with E[z] > k always accumulates; the tail is Poisson luck),
     correct score/alert envelopes.
  2. benign steady traffic (watermark-driven finalization across 3 simulated
     partitions, like the real consumer) -> no alarm.
  3. short benign bursts (1-2 hot minutes) and a single whale transaction
     -> no alarm.
  4. cold payer with no baseline under an immediate hot trickle -> no alarm
     (warm-up guard), score docs flagged warming_up.
  5. fleet false-alarm soak: 700 benign payers x 6 h at the detector level
     -> alarm episodes within the measured-ARL budget quoted in the README
     (a CUSUM's false-alarm rate is a quantified trade-off, not zero; the
     shipped tuning measured ~1 episode per ~1000 benign payer-hours).
  6. state snapshot round-trip preserves baselines and open excursions.

Run:  python services/cassandra/tests/offline_check.py
"""
from __future__ import annotations

import math
import random
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detector import Params, PayerDrift  # noqa: E402
from app.pipeline import Pipeline  # noqa: E402

P = Params()  # shipped defaults — the compose block sets no detector overrides

T0 = 1_800_000_000  # fixed epoch anchor (minute-aligned), keeps runs reproducible
EXFIL_PAYER = "wallet-user-0001"

FAILURES: list[str] = []


def check(cond: bool, label: str) -> None:
    print(("PASS  " if cond else "FAIL  ") + label)
    if not cond:
        FAILURES.append(label)


def iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def poisson(rng: random.Random, lam: float) -> int:
    if lam <= 0.0:
        return 0
    limit = math.exp(-lam)
    k, p = 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def benign_amount(rng: random.Random) -> float:
    # Same distribution as the generator / seed_baseline: lognormal(11.5, 1.0),
    # clamped to [1e3, 5e7] IDR.
    return round(min(max(rng.lognormvariate(11.5, 1.0), 1_000.0), 50_000_000.0), -2)


def make_doc(ts: float, payer: str, amount: float, attack: bool = False) -> dict:
    """A normalized doc in the exact flattened shape Vector produces."""
    return {
        "@timestamp": iso(ts),
        "event": {"id": str(uuid.uuid4()), "type": "transaction"},
        "network": {"client_ip": "10.0.0.1"},
        "transaction": {
            "payer_id": payer,
            "payee_id": "merchant-0042",
            "amount": amount,
            "currency": "IDR",
            "channel": "ecommerce",
            "status": "approved",
            "latency_ms": 12.0,
        },
        "security": {"is_attack": attack,
                     "attack_pattern": "slow_exfil" if attack else None,
                     "is_malformed": False},
        "error": False,
    }


class World:
    """A small benign economy: payers with fixed Poisson rates."""

    def __init__(self, rng: random.Random, n_payers: int = 40) -> None:
        self.rng = rng
        self.rates = {f"payer-{i:03d}": rng.uniform(0.4, 2.5) for i in range(n_payers)}
        self.rates[EXFIL_PAYER] = 1.3  # the designated payer's observed live rate

    def minute_events(self, minute_epoch: int, extra: list[tuple[str, float]] = ()) -> list[dict]:
        docs = []
        for payer, rate in self.rates.items():
            for _ in range(poisson(self.rng, rate)):
                docs.append(make_doc(minute_epoch + self.rng.uniform(0, 59.9),
                                     payer, benign_amount(self.rng)))
        for payer, amount in extra:
            docs.append(make_doc(minute_epoch + self.rng.uniform(0, 59.9),
                                 payer, amount, attack=True))
        return docs


def drive_minute(pipe: Pipeline, world: World, minute_idx: int,
                 extra: list[tuple[str, float]] = ()) -> tuple[list[dict], list[dict]]:
    """Feed one simulated minute, then finalize it directly (single-writer
    deterministic path; the watermark path is exercised in scenario 2)."""
    minute = T0 + minute_idx * 60
    for doc in world.minute_events(minute, extra):
        pipe.add_event(doc, partition=0)
    return pipe.finalize(minute)


def exfil_extra(rng: random.Random, per_minute: float = 2.0,
                multiplier: float = 1.8) -> list[tuple[str, float]]:
    """The generator's slow_exfil trickle: ~Poisson(2)/min extra events on the
    designated payer at 1.8x amounts."""
    return [(EXFIL_PAYER, round(min(benign_amount(rng) * multiplier, 50_000_000.0), -2))
            for _ in range(poisson(rng, per_minute))]


# ---------------------------------------------------------------------------
# Scenario 1 — slow_exfil trickle on a warm baseline
# ---------------------------------------------------------------------------

def run_exfil_once(seed: int, warm_minutes: int = 45, attack_minutes: int = 25):
    rng = random.Random(seed)
    world = World(rng)
    pipe = Pipeline(P)
    for m in range(warm_minutes):
        _, alerts = drive_minute(pipe, world, m)
        assert not alerts, f"seed {seed}: alert during benign warmup"
    first_alert = None
    first_delay = None
    all_scores = []
    for m in range(warm_minutes, warm_minutes + attack_minutes):
        docs, alerts = drive_minute(pipe, world, m, extra=exfil_extra(rng))
        all_scores.extend(docs)
        exfil_alerts = [a for a in alerts if a["alert"]["entity_id"] == EXFIL_PAYER]
        if exfil_alerts and first_alert is None:
            first_alert = exfil_alerts[0]
            first_delay = m - warm_minutes + 1  # minutes since onset
    return first_alert, first_delay, all_scores


def scenario_1() -> None:
    print("\n-- scenario 1: slow_exfil trickle (+~2/min @ 1.8x) on a warm baseline --")
    alert, delay, scores = run_exfil_once(seed=1001)
    check(alert is not None, "alert raised on the designated payer")
    if alert is None:
        return
    check(delay is not None and delay <= 10, f"alarm within <=10 min of onset (got {delay})")

    a = alert["alert"]
    check(a["type"] == "slow_exfiltration", "alert.type == slow_exfiltration")
    check(a["source"] == "cassandra", "alert.source == cassandra")
    check(a["entity_type"] == "payer", "alert.entity_type == payer")
    check(a["entity_id"] == EXFIL_PAYER, "alert.entity_id == designated payer")
    check(a["severity"] in ("low", "medium", "high"), "alert.severity valid")
    check(0.0 < a["score"] <= 1.0, "alert.score in (0, 1]")
    check(isinstance(a["id"], str) and len(a["id"]) == 36, "alert.id is a uuid")
    check(set(a["window"]) == {"start", "end"}, "alert.window has start/end")
    start = datetime.fromisoformat(a["window"]["start"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(a["window"]["end"].replace("Z", "+00:00"))
    span = (end - start).total_seconds()
    check(span >= P.min_drift_buckets * 60,
          f"alert window spans the accumulation period ({span:.0f}s >= {P.min_drift_buckets * 60}s)")

    anom = [d for d in scores
            if d["score"]["entity_id"] == EXFIL_PAYER and d["score"]["is_anomalous"]]
    check(bool(anom), "anomalous score docs emitted for the payer")
    if anom:
        s = anom[0]["score"]
        check(s["model"] == "cassandra", "score.model == cassandra")
        check(s["entity_type"] == "payer", "score.entity_type == payer")
        check(s["warming_up"] is False, "score.warming_up false post-warmup")
        check(bool(s["reasons"]), "score.reasons populated")
        check({"cusum_volume", "cusum_amount", "buckets_elevated",
               "cumulative_amount", "mean_amount_ratio"} <= set(s["features"]),
              "score.features carries the drift evidence")
        w = s["window"]
        dur = (datetime.fromisoformat(w["end"].replace("Z", "+00:00"))
               - datetime.fromisoformat(w["start"].replace("Z", "+00:00"))).total_seconds()
        check(w["duration_seconds"] == dur and dur >= P.min_drift_buckets * 60,
              "score.window spans the accumulation period, not one minute")

    delays = []
    misses = 0
    for seed in range(1002, 1026):
        alert_i, delay_i, _ = run_exfil_once(seed)
        if alert_i is None:
            misses += 1
        else:
            delays.append(delay_i)
    check(misses == 0, f"detection across 25 seeds (misses={misses})")
    if delays:
        delays.sort()
        median = delays[len(delays) // 2]
        check(median <= 10,
              f"median detection delay <=10 min (median={median}, max={delays[-1]})")
        check(delays[-1] <= 25,
              f"every seed detected <=25 min (max={delays[-1]}) — CUSUM's "
              f"eventual-detection guarantee, tail is Poisson luck")


# ---------------------------------------------------------------------------
# Scenario 2 — benign steady traffic through the watermark path
# ---------------------------------------------------------------------------

def scenario_2() -> None:
    print("\n-- scenario 2: benign steady traffic (3-partition watermark path) --")
    rng = random.Random(42)
    world = World(rng)
    pipe = Pipeline(P)
    pipe.register_partitions([0, 1, 2])
    total_alerts = 0
    part = 0
    minutes = 105  # 45 warmup + 60 observed
    for m in range(minutes):
        minute = T0 + m * 60
        for doc in world.minute_events(minute):
            ready = pipe.add_event(doc, partition=part)
            part = (part + 1) % 3
            for r in sorted(ready):
                _, alerts = pipe.finalize(r)
                total_alerts += len(alerts)
    for r in sorted(pipe._buckets):
        _, alerts = pipe.finalize(r)
        total_alerts += len(alerts)
    check(pipe.counters["buckets_finalized"] == minutes,
          f"all {minutes} buckets finalized whole (no fragmentation)")
    check(total_alerts == 0, f"no alerts on benign steady traffic (got {total_alerts})")


# ---------------------------------------------------------------------------
# Scenario 3 — short benign bursts and a whale transaction
# ---------------------------------------------------------------------------

def scenario_3() -> None:
    print("\n-- scenario 3: benign bursts (1-2 hot minutes) + whale amount --")
    rng = random.Random(7)
    world = World(rng)
    pipe = Pipeline(P)
    total_alerts = 0
    for m in range(45):
        _, alerts = drive_minute(pipe, world, m)
        total_alerts += len(alerts)
    # Two consecutive hot minutes on one payer: 10x its normal event count at
    # normal amounts (a burst is ARGUS's niche, must NOT trip CASSANDRA).
    burst_payer = "payer-005"
    for m in (45, 46):
        extra = [(burst_payer, benign_amount(rng)) for _ in range(10)]
        minute = T0 + m * 60
        for doc in world.minute_events(minute):
            pipe.add_event(doc, partition=0)
        for payer, amount in extra:
            pipe.add_event(make_doc(minute + rng.uniform(0, 59.9), payer, amount), 0)
        _, alerts = pipe.finalize(minute)
        total_alerts += len(alerts)
    # One benign whale: a single 5M IDR transaction on an ordinary payer.
    _, alerts = drive_minute(pipe, world, 47, extra=[])
    total_alerts += len(alerts)
    minute = T0 + 48 * 60
    for doc in world.minute_events(minute):
        pipe.add_event(doc, partition=0)
    pipe.add_event(make_doc(minute + 5.0, "payer-010", 5_000_000.0), 0)
    _, alerts = pipe.finalize(minute)
    total_alerts += len(alerts)
    # Cool-down: the excursions must drain without ever alarming.
    for m in range(49, 75):
        _, alerts = drive_minute(pipe, world, m)
        total_alerts += len(alerts)
    check(total_alerts == 0, f"no alerts from bursts or whales (got {total_alerts})")


# ---------------------------------------------------------------------------
# Scenario 4 — cold payer: warm-up guard
# ---------------------------------------------------------------------------

def scenario_4() -> None:
    print("\n-- scenario 4: cold payer under an immediate hot trickle --")
    rng = random.Random(11)
    world = World(rng)
    pipe = Pipeline(P)
    for m in range(45):
        drive_minute(pipe, world, m)
    cold = "payer-cold-0001"
    cold_alerts = 0
    cold_docs = []
    for m in range(45, 45 + 12):  # 12 min < warmup_buckets(30): must stay silent
        extra = [(cold, benign_amount(rng) * 2.0) for _ in range(poisson(rng, 3.0))]
        minute = T0 + m * 60
        for doc in world.minute_events(minute):
            pipe.add_event(doc, partition=0)
        for payer, amount in extra:
            pipe.add_event(make_doc(minute + rng.uniform(0, 59.9), payer, amount, True), 0)
        docs, alerts = pipe.finalize(minute)
        cold_alerts += sum(1 for a in alerts if a["alert"]["entity_id"] == cold)
        cold_docs += [d for d in docs if d["score"]["entity_id"] == cold]
    check(cold_alerts == 0, "no alert for a payer with no baseline (warm-up guard)")
    check(all(d["score"]["warming_up"] for d in cold_docs),
          f"cold payer's score docs flagged warming_up ({len(cold_docs)} docs)")
    check(all(not d["score"]["is_anomalous"] for d in cold_docs),
          "cold payer never marked anomalous")


# ---------------------------------------------------------------------------
# Scenario 5 — fleet false-alarm soak (detector level, for speed)
# ---------------------------------------------------------------------------

def scenario_5() -> None:
    print("\n-- scenario 5: fleet ARL soak — 700 benign payers x 6 h --")
    rng = random.Random(1234)
    started = time.monotonic()
    fleet = [(PayerDrift(P), rng.uniform(0.2, 3.0)) for _ in range(700)]
    alarm_payers = set()
    alarm_minutes = 0
    for m in range(360):
        minute = T0 + m * 60
        for i, (drift, rate) in enumerate(fleet):
            n = poisson(rng, rate)
            # Same per-event winsorization the pipeline applies before summing.
            amt = sum(min(benign_amount(rng), P.amount_event_cap) for _ in range(n))
            a = drift.update(n, amt, min(n, 1), minute, P)
            if a.is_anomalous:
                alarm_payers.add(i)
                alarm_minutes += 1
    payer_hours = 700 * 6
    budget = 8  # ~2x the measured rate of ~1 episode / ~1000 benign payer-hours
    print(f"      {payer_hours} benign payer-hours in {time.monotonic() - started:.1f}s: "
          f"{len(alarm_payers)} alarm episodes ({alarm_minutes} alarm-minutes)")
    check(len(alarm_payers) <= budget,
          f"false-alarm episodes within budget over {payer_hours} benign "
          f"payer-hours ({len(alarm_payers)} <= {budget}; README documents the "
          f"measured ARL — a CUSUM's false-alarm rate is quantified, not zero)")


# ---------------------------------------------------------------------------
# Scenario 6 — state snapshot round-trip
# ---------------------------------------------------------------------------

def scenario_6() -> None:
    print("\n-- scenario 6: state snapshot round-trip --")
    rng = random.Random(5)
    world = World(rng)
    pipe = Pipeline(P)
    for m in range(45):
        drive_minute(pipe, world, m)
    for m in range(45, 49):  # open a live excursion, below the alarm bar
        drive_minute(pipe, world, m, extra=exfil_extra(rng))
    import json
    state = json.loads(json.dumps(pipe.state_dict()))  # through-JSON, like /data
    restored = Pipeline(P)
    restored.load_state(state)
    src = pipe.payers[EXFIL_PAYER]
    dst = restored.payers[EXFIL_PAYER]
    check(len(restored.payers) == len(pipe.payers), "all payers restored")
    check(dst.buckets_observed == src.buckets_observed, "warm-up progress survives restart")
    check(abs(dst.volume.s - src.volume.s) < 1e-9
          and dst.volume.excursion_start == src.volume.excursion_start,
          "open CUSUM excursion survives restart")
    check(abs(dst.amount.baseline.mean - src.amount.baseline.mean) < 1e-6,
          "amount baseline survives restart")


def main() -> int:
    print(f"CASSANDRA offline validation — defaults: k={P.cusum_k}, h={P.cusum_h}, "
          f"h_single={P.cusum_h_single}, z_clip={P.z_clip}, "
          f"min_drift={P.min_drift_buckets}, warmup={P.warmup_buckets}")
    scenario_1()
    scenario_2()
    scenario_3()
    scenario_4()
    scenario_5()
    scenario_6()
    print(f"\n{'ALL CHECKS PASSED' if not FAILURES else f'{len(FAILURES)} FAILURE(S)'}")
    for f in FAILURES:
        print(f"  FAIL: {f}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
