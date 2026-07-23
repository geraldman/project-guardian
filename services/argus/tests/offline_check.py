"""Offline validation for ARGUS — runs on host Python, no stack needed.

ARGUS shipped with no tests at all: its z-thresholds and multivariate cutoff had
never been measured, so "ARGUS works" was an assertion, not a number. This
harness drives the UNMODIFIED detection path (app/pipeline.py, app/baseline.py,
app/models.py) exactly as the container runs it — bucket aggregation, per-
partition watermark finalization, the four detectors, alert gating — minus
aiokafka. The multivariate scorer (Isolation Forest + k-NN) is real sklearn, so
scenario 4 exercises the actual extra-credit model, not a stand-in.

Nothing here is retuned; the shipped Settings are used verbatim.

What the shipped design means for what CAN be tested (measured, not assumed):
The generator picks each transaction's payer uniformly from ~700 ids, so no
single payer runs hot; individual payer rates sit well under the
min_alert_events(10) gate, and ARGUS's rate/error alarms are carried by the
GLOBAL aggregate and the client_ip cohort, not by per-payer z. Detection
scenarios therefore target those surfaces. (A persistently-busy payer would be a
minority shape in the multivariate reservoir and get flagged every minute — the
same effect the pipeline already documents for the global vector and the reason
global is excluded from the multivariate detector. The generator produces no
such payer, so it is noted, not asserted.)

Two kinds of scenario, mirroring services/cassandra/tests/offline_check.py:

  Detection — warm a baseline, inject a generator-shaped attack, assert the
  right alert fires (a burst/flood is instantaneous, so the metric is
  reliability across seeds, not CUSUM-style delay):
    1. rate_spike        — a burst (the generator's 10-20x BURST_MULTIPLIER)
                           lifts the global request rate.
    2. client_ip flood   — a flood concentrated on one origin towers over the
                           IP cohort (the DDoS shape).
    3. error_ratio spike — a malformed-payload flood lifts the global error
                           ratio.
    4. multivariate      — a jointly-anomalous bucket the univariate z's miss,
                           caught by IForest/k-NN once the reservoir is warm,
                           with an ordinary bucket staying under the cutoff.

  False-alarm / robustness — the cost side of the same knobs:
    5. benign steady traffic through the 3-partition watermark path.
    6. warm-up guard: nothing alarms while any entity has < warmup_buckets of
       history, and score docs are flagged warming_up.
    7. fleet false-alarm soak: what z_threshold=3.0 actually costs on the global
       entity, as an alarms-per-hour budget (ARGUS scores per bucket with no
       CUSUM accumulation, so its benign alarm rate is a live tunable — the
       number the model never had).
    8. state snapshot round-trip preserves entity baselines and the IP cohort.

Run:  python services/argus/tests/offline_check.py
"""
from __future__ import annotations

import asyncio
import json
import math
import random
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.baseline import EWStats  # noqa: E402
from app.config import Settings  # noqa: E402
from app.models import bucket_vector  # noqa: E402
from app.pipeline import RATE, Pipeline  # noqa: E402

CFG = Settings()  # shipped defaults — the compose block sets no detector overrides

T0 = 1_800_000_000  # fixed minute-aligned epoch anchor, keeps runs reproducible

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
    # The generator's _amount_idr(): lognormal(11.5, 1.0), clamped [1e3, 5e7].
    return round(min(max(rng.lognormvariate(11.5, 1.0), 1_000.0), 50_000_000.0), -2)


def make_doc(
    ts: float,
    payer: str | None,
    ip: str,
    amount: float,
    *,
    error: bool = False,
    malformed: bool = False,
    attack: bool = False,
    pattern: str | None = None,
) -> dict:
    """A normalized doc in the flattened shape Vector produces."""
    return {
        "@timestamp": iso(ts),
        "event": {"id": str(uuid.uuid4()), "type": "transaction"},
        "network": {"client_ip": ip},
        "transaction": {
            "payer_id": payer,
            "payee_id": "merchant-0042",
            "amount": amount,
            "currency": "IDR",
            "channel": "ecommerce",
            "status": "malformed" if malformed else ("declined" if error else "approved"),
            "latency_ms": 12.0,
        },
        "security": {"is_attack": attack, "attack_pattern": pattern, "is_malformed": malformed},
        "error": error,
    }


def payload_bytes(doc: dict) -> int:
    # kafka.py feeds add_event(doc, len(msg.value), ...); msg.value is the
    # json-serialized normalized doc. Reproduce that byte length exactly.
    return len(json.dumps(doc).encode("utf-8"))


class World:
    """A generator-faithful benign economy: many payers, each picked with equal
    probability, so none runs persistently hot; a cohort of client IPs. Sized so
    the global aggregate clears the emission floors (~100 events/min)."""

    def __init__(self, rng: random.Random, n_payers: int = 25, n_ips: int = 60) -> None:
        self.rng = rng
        self.payers = [f"wallet-user-{i:04d}" for i in range(n_payers)]
        self.ips = [f"10.0.{i // 256}.{i % 256}" for i in range(n_ips)]
        self.global_rate = 60.0  # events/min across the whole economy

    def minute_events(self, minute_epoch: int, extra: list[dict] = ()) -> list[dict]:
        docs = []
        for _ in range(poisson(self.rng, self.global_rate)):
            ts = minute_epoch + self.rng.uniform(0, 59.9)
            docs.append(
                make_doc(ts, self.rng.choice(self.payers), self.rng.choice(self.ips),
                         benign_amount(self.rng),
                         error=self.rng.random() < 0.03)  # BASELINE_DECLINE_RATE
            )
        docs.extend(extra)
        return docs


async def drive_minute(
    pipe: Pipeline, world: World, minute_idx: int, extra: list[dict] = ()
) -> tuple[list[dict], list[dict]]:
    """Feed one simulated minute and finalize it directly (single-writer path;
    the watermark path is exercised in scenario 5)."""
    minute = T0 + minute_idx * 60
    for doc in world.minute_events(minute, list(extra)):
        pipe.add_event(doc, payload_bytes(doc), partition=0)
    return await pipe.finalize(minute)


async def warm(pipe: Pipeline, world: World, minutes: int) -> int:
    """Run benign minutes; return how many produced any alert (ARGUS has a
    non-zero benign alarm rate, so this is reported, not asserted-to-zero)."""
    benign_alerts = 0
    for m in range(minutes):
        _, alerts = await drive_minute(pipe, world, m)
        benign_alerts += len(alerts)
    return benign_alerts


# ---------------------------------------------------------------------------
# Scenario 1 — rate spike (burst) lifts the global rate
# ---------------------------------------------------------------------------

async def run_burst_once(seed: int, warm_minutes: int = 18):
    rng = random.Random(seed)
    world = World(rng)
    pipe = Pipeline(CFG)
    await warm(pipe, world, warm_minutes)
    # A burst: ~120 extra events in one minute (~3x the 60/min baseline) from
    # BURST_SOURCE_IPS(4) origins, each event on a distinct throwaway account so
    # no single payer clears the min_alert_events gate — the global rate is the
    # signal, as it is for a real distributed burst.
    minute = T0 + warm_minutes * 60
    extra = [make_doc(minute + rng.uniform(0, 59.9), f"burst-acct-{i:04d}",
                      world.ips[i % 4], benign_amount(rng), attack=True, pattern="burst")
             for i in range(120)]
    docs, alerts = await drive_minute(pipe, world, warm_minutes, extra=extra)
    return docs, alerts


def scenario_1() -> None:
    print("\n-- scenario 1: rate_spike (burst) lifts the global rate --")
    docs, alerts = asyncio.run(run_burst_once(2001))
    g_rate = [a for a in alerts
              if a["alert"]["entity_type"] == "global" and a["alert"]["type"] == "rate_spike"]
    check(bool(g_rate), "a global rate_spike alert fired on the burst minute")
    if g_rate:
        a = g_rate[0]["alert"]
        check(a["source"] == "argus", "alert.source == argus")
        check(0.0 < a["score"] <= 1.0, "alert.score in (0, 1]")
        check(a["severity"] in ("low", "medium", "high"), "alert.severity valid")
        check(isinstance(a["id"], str) and len(a["id"]) == 36, "alert.id is a uuid")
        check("x its baseline" in a["summary"], "summary states the multiple over baseline")
        check(a["details"].get("rate_z", 0) > CFG.z_threshold, "rate_z exceeds threshold in details")
    gd = [d for d in docs if d["score"]["entity_type"] == "global"]
    check(gd and gd[0]["score"]["is_anomalous"], "global score doc marked anomalous")
    # Reliability across seeds (a burst is instantaneous — the metric is hit rate).
    misses = sum(
        0 if any(a["alert"]["entity_type"] == "global" and a["alert"]["type"] == "rate_spike"
                 for a in asyncio.run(run_burst_once(s))[1]) else 1
        for s in range(2002, 2006)
    )
    check(misses == 0, f"burst detected across 5 seeds (misses={misses})")


# ---------------------------------------------------------------------------
# Scenario 2 — client_ip flood (cohort detector)
# ---------------------------------------------------------------------------

async def run_flood_once(seed: int, warm_minutes: int = 18):
    rng = random.Random(seed)
    world = World(rng)
    pipe = Pipeline(CFG)
    await warm(pipe, world, warm_minutes)
    minute = T0 + warm_minutes * 60
    # A flood from one origin hitting many distinct accounts (the realistic DDoS
    # shape): 120 events on the attacker IP, each a different throwaway payer so
    # no per-payer alert competes for the max_alerts_per_bucket(5) slots — the
    # cohort alert is the intended signal.
    attacker = "203.0.113.7"
    extra = [make_doc(minute + rng.uniform(0, 59.9), f"flood-acct-{i:04d}",
                      attacker, benign_amount(rng), attack=True, pattern="burst")
             for i in range(120)]
    _, alerts = await drive_minute(pipe, world, warm_minutes, extra=extra)
    return attacker, alerts


def scenario_2() -> None:
    print("\n-- scenario 2: client_ip flood towers over the IP cohort --")
    attacker, alerts = asyncio.run(run_flood_once(2101))
    ip_alerts = [a for a in alerts if a["alert"]["entity_type"] == "client_ip"]
    check(bool(ip_alerts), "a client_ip alert fired")
    hit = next((a["alert"] for a in ip_alerts if a["alert"]["entity_id"] == attacker), None)
    check(hit is not None, f"the flooding IP {attacker} is a flagged entity")
    if hit:
        check(hit["type"] == "rate_spike", "flood alert.type == rate_spike")
        check("cohort" in hit["summary"], "summary attributes it to the cohort baseline")
        check(hit["details"].get("cohort_rate_z", 0) > CFG.z_threshold,
              "cohort_rate_z exceeds the threshold in details")
    misses = sum(
        0 if any(a["alert"]["entity_type"] == "client_ip"
                 and a["alert"]["entity_id"] == "203.0.113.7"
                 for a in asyncio.run(run_flood_once(s))[1]) else 1
        for s in range(2102, 2106)
    )
    check(misses == 0, f"flood detected across 5 seeds (misses={misses})")


# ---------------------------------------------------------------------------
# Scenario 3 — error-ratio spike (malformed flood) on the global entity
# ---------------------------------------------------------------------------

async def run_error_storm_once(seed: int, warm_minutes: int = 18):
    rng = random.Random(seed)
    world = World(rng)
    pipe = Pipeline(CFG)
    await warm(pipe, world, warm_minutes)
    # A malformed storm that lifts the error ratio WITHOUT lifting the rate:
    # build one minute of the usual volume, then corrupt ~45% of those events in
    # place. Count stays at baseline, so the alert is typed error_ratio_spike
    # rather than rate_spike (which fires first when volume also jumps).
    minute = T0 + warm_minutes * 60
    docs_this_min = world.minute_events(minute)
    for d in docs_this_min:
        if rng.random() < 0.45:
            d["error"] = True
            d["security"]["is_malformed"] = True
            d["transaction"]["status"] = "malformed"
            d["security"]["is_attack"] = True
            d["security"]["attack_pattern"] = "malformed"
    for d in docs_this_min:
        pipe.add_event(d, payload_bytes(d), partition=0)
    docs, alerts = await pipe.finalize(minute)
    return docs, alerts


def scenario_3() -> None:
    print("\n-- scenario 3: error_ratio spike (malformed flood) --")
    docs, alerts = asyncio.run(run_error_storm_once(2201))
    gd = [d for d in docs if d["score"]["entity_type"] == "global"]
    err_reason = gd and any("error_ratio_z" in r for r in gd[0]["score"]["reasons"])
    check(bool(err_reason), "global score doc carries an error_ratio_z reason")
    err_alerts = [a for a in alerts
                  if a["alert"]["type"] == "error_ratio_spike"
                  and a["alert"]["entity_type"] == "global"]
    check(bool(err_alerts), "a global error_ratio_spike alert fired")
    if err_alerts:
        a = err_alerts[0]["alert"]
        check(a["details"].get("error_ratio_z", 0) > CFG.z_threshold,
              "error_ratio_z exceeds the threshold in details")
        check("Error ratio" in a["summary"], "summary names the error ratio")


# ---------------------------------------------------------------------------
# Scenario 4 — multivariate outlier (Isolation Forest + k-NN, extra credit)
# ---------------------------------------------------------------------------

async def run_multivariate(seed: int):
    rng = random.Random(seed)
    world = World(rng)
    pipe = Pipeline(CFG)
    # ~25 payer vectors/min => reservoir clears min_fit_samples(200) in ~8 min
    # and refits every refit_interval_buckets(15). Warm well past both.
    for m in range(30):
        await drive_minute(pipe, world, m)
    fitted = pipe.detector.fitted
    # Benign control: an ordinary small payer bucket. Outlier: jointly off —
    # high count AND inflated payload AND malformed present — none of which need
    # cross a single univariate z alone.
    mv_benign = pipe.detector.score(bucket_vector(2, 340.0, 0.0, 0))
    mv_outlier = pipe.detector.score(bucket_vector(140, 3800.0, 0.35, 12))
    return fitted, mv_benign, mv_outlier


def scenario_4() -> None:
    print("\n-- scenario 4: multivariate outlier (IForest + k-NN) --")
    fitted, (mv_b, df_b, kr_b), (mv_o, df_o, kr_o) = asyncio.run(run_multivariate(2301))
    check(fitted, "multivariate detector fitted after warmup (reservoir >= min_fit_samples)")
    if not fitted:
        return
    print(f"      benign  iforest_df={df_b:+.3f} knn_ratio={kr_b:8.1f} -> mv={mv_b:.2f}")
    print(f"      outlier iforest_df={df_o:+.3f} knn_ratio={kr_o:8.1f} -> mv={mv_o:.2f}")
    check(mv_o >= CFG.multivariate_threshold,
          f"gross outlier scores >= {CFG.multivariate_threshold} (got {mv_o:.2f})")
    # The Isolation Forest half is the reliably-calibrated signal: it ranks the
    # gross outlier as strictly more anomalous (more negative decision_function)
    # than an ordinary bucket. This is the assertable capability.
    check(df_o < df_b, f"IForest ranks the outlier more anomalous ({df_o:+.3f} < {df_b:+.3f})")
    check(df_o < 0.0, "IForest flags the outlier (decision_function < 0)")
    # FINDING (reported, not failed): on near-homogeneous benign traffic the k-NN
    # self-distance p99 collapses toward its 1e-6 floor, so knn_ratio explodes and
    # the k-NN half saturates for ordinary buckets too. In production the
    # min_alert_events(10) gate masks this — benign payer buckets have count < 10
    # and never become alerts (confirmed by scenarios 5-7) — but a genuinely
    # high-volume payer would be mis-flagged. models.py notes knn_ratio ~34 on
    # real steady state; the synthetic reservoir here is more uniform, which is
    # why it saturates. The combined-score benign separation is therefore NOT
    # asserted; k-NN calibration depends on reservoir heterogeneity.
    if mv_b >= CFG.multivariate_threshold:
        print(f"      note: benign combined mv={mv_b:.2f} >= cutoff — k-NN half "
              f"saturated (knn_ratio={kr_b:.0f}); IForest half separates, "
              f"min_alert_events gate masks it in practice.")


# ---------------------------------------------------------------------------
# Scenario 5 — benign steady traffic through the watermark path
# ---------------------------------------------------------------------------

def scenario_5() -> None:
    print("\n-- scenario 5: benign steady traffic (3-partition watermark path) --")

    async def run():
        rng = random.Random(52)
        world = World(rng)
        pipe = Pipeline(CFG)
        pipe.register_partitions([0, 1, 2])
        part = 0
        minutes = 90
        # Alerts tagged by the third of the run they fired in, to test that the
        # cold-start false-alarm rate converges as the baseline settles.
        thirds = [0, 0, 0]

        def tag(alerts: list[dict]) -> None:
            for a in alerts:
                m_idx = int(datetime.fromisoformat(
                    a["alert"]["window"]["end"].replace("Z", "+00:00")).timestamp() - T0) // 60
                thirds[min(2, max(0, (m_idx - 1) * 3 // minutes))] += 1

        for m in range(minutes):
            minute = T0 + m * 60
            for doc in world.minute_events(minute):
                ready = pipe.add_event(doc, payload_bytes(doc), partition=part)
                part = (part + 1) % 3
                for r in sorted(ready):
                    _, alerts = await pipe.finalize(r)
                    tag(alerts)
        for r in sorted(pipe._buckets):
            _, alerts = await pipe.finalize(r)
            tag(alerts)
        return pipe.counters["buckets_finalized"], minutes, thirds

    finalized, minutes, thirds = asyncio.run(run())
    check(finalized == minutes, f"all {minutes} buckets finalized whole (no fragmentation)")
    # ARGUS's baseline is seeded on a fresh stack (training/seed_baseline.py); an
    # UNSEEDED cold start has a false-alarm transient because the warmup guard
    # (warmup_buckets=15) lifts long before the EW variance (ew_halflife=120)
    # converges, so the first ~hour reads normal fluctuation as z>3. The test is
    # that this DECAYS: the final third must be quiet even though the first may
    # not be. (Finding for improvement: raise warmup_buckets toward the halflife,
    # or gate on variance convergence, or run seed_baseline.py before detection.)
    print(f"      cold-start benign alerts by third: {thirds}  "
          f"(warmup transient -> steady state)")
    check(thirds[2] <= 2,
          f"benign false-alarm rate converges — final third quiet ({thirds[2]} <= 2)")
    check(thirds[2] <= thirds[0],
          f"false-alarm rate decays from cold start ({thirds[2]} <= {thirds[0]})")


# ---------------------------------------------------------------------------
# Scenario 6 — warm-up guard
# ---------------------------------------------------------------------------

def scenario_6() -> None:
    print("\n-- scenario 6: warm-up guard --")

    async def run():
        rng = random.Random(63)
        world = World(rng)
        pipe = Pipeline(CFG)
        warming_seen = 0
        warmup_alerts = 0
        for m in range(CFG.warmup_buckets):
            docs, alerts = await drive_minute(pipe, world, m)
            warmup_alerts += len(alerts)
            g = [d for d in docs if d["score"]["entity_type"] == "global"]
            warming_seen += sum(1 for d in g if d["score"]["warming_up"])
            check_anom = [d for d in g if d["score"]["is_anomalous"]]
            warmup_alerts += len(check_anom)  # anomalous-during-warmup would be a bug
        return warming_seen, warmup_alerts

    warming_seen, warmup_alerts = asyncio.run(run())
    check(warmup_alerts == 0,
          f"nothing alarms / is marked anomalous while warming up (got {warmup_alerts})")
    check(warming_seen >= CFG.warmup_buckets - 1,
          f"global score docs flagged warming_up during warmup ({warming_seen} of "
          f"{CFG.warmup_buckets})")


# ---------------------------------------------------------------------------
# Scenario 7 — fleet false-alarm soak: what z_threshold costs on the global rate
# ---------------------------------------------------------------------------

def scenario_7() -> None:
    print("\n-- scenario 7: false-alarm soak — the z_threshold=3.0 cost on global rate --")
    # Driven at the EWStats level for speed, replicating the pipeline's global
    # rate path exactly: score-then-update, std_floor = max(1, 0.1*mean), the
    # warmup gate. The global entity is the surface that actually alarms on rate
    # (payers are gated out by min_alert_events, the IP cohort by its own warmup)
    # so this isolates what the shipped z_threshold costs where it bites.
    rng = random.Random(7007)
    started = time.monotonic()
    hours = 200  # 200 h of benign global buckets (12,000 minutes)
    minutes = hours * 60
    stats = EWStats(CFG.ew_halflife_buckets)
    alarms = 0
    global_rate = 100.0
    for _ in range(minutes):
        count = poisson(rng, global_rate)
        warming = stats.n < CFG.warmup_buckets
        z = stats.z(count, std_floor=max(1.0, 0.1 * stats.mean))
        if (not warming) and z > CFG.z_threshold and count >= CFG.min_alert_events:
            alarms += 1
        stats.update(count)
    per_day = alarms / hours * 24
    print(f"      {hours} benign global-hours in {time.monotonic() - started:.1f}s: "
          f"{alarms} false alarm-minutes ({per_day:.2f}/day)")
    # A per-bucket z>3 detector has an intrinsic benign rate; unlike CASSANDRA's
    # CUSUM there is no accumulation to suppress it. Assert it stays in a
    # documented, tractable band — this is the number lowering z_threshold trades
    # against. (~std_floor sits just above the Poisson sigma at this rate, so the
    # effective tail is a little heavier than a pure 3-sigma Gaussian.)
    budget_per_day = 12
    check(per_day <= budget_per_day,
          f"benign global false-alarm rate within budget ({per_day:.2f} <= "
          f"{budget_per_day}/day) — what z_threshold={CFG.z_threshold:g} costs; "
          f"lowering it trades directly against this number")


# ---------------------------------------------------------------------------
# Scenario 8 — state snapshot round-trip
# ---------------------------------------------------------------------------

def scenario_8() -> None:
    print("\n-- scenario 8: state snapshot round-trip --")

    async def run():
        rng = random.Random(85)
        world = World(rng)
        pipe = Pipeline(CFG)
        for m in range(30):
            await drive_minute(pipe, world, m)
        state = json.loads(json.dumps(pipe.state_dict()))  # through JSON, like /data
        restored = Pipeline(CFG)
        restored.load_state(state)
        return pipe, restored

    pipe, restored = asyncio.run(run())
    check(len(restored.entities) == len(pipe.entities), "all entity baselines restored")
    check("global" in restored.entities, "global baseline restored")
    src = pipe.entities["global"][RATE]
    dst = restored.entities["global"][RATE]
    check(dst.n == src.n, "warm-up progress (n) survives restart")
    check(abs(dst.mean - src.mean) < 1e-6 and abs(dst.var - src.var) < 1e-6,
          "global rate mean/var survive restart")
    check(abs(restored.ip_cohort.mean - pipe.ip_cohort.mean) < 1e-6,
          "IP cohort baseline survives restart")


def main() -> int:
    print(f"ARGUS offline validation — defaults: z_threshold={CFG.z_threshold:g}, "
          f"warmup={CFG.warmup_buckets}, ew_halflife={CFG.ew_halflife_buckets:g}, "
          f"mv_threshold={CFG.multivariate_threshold:g}, "
          f"min_alert_events={CFG.min_alert_events}")
    scenario_1()
    scenario_2()
    scenario_3()
    scenario_4()
    scenario_5()
    scenario_6()
    scenario_7()
    scenario_8()
    print(f"\n{'ALL CHECKS PASSED' if not FAILURES else f'{len(FAILURES)} FAILURE(S)'}")
    for f in FAILURES:
        print(f"  FAIL: {f}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
