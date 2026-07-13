"""Cumulative per-payer drift detection — the pure math core of CASSANDRA.

Low-and-slow exfiltration is locally normal and only abnormal cumulatively,
so the unit of analysis is the aggregated per-payer 1-minute bucket series
(event count + total amount moved), never the single event. The backbone is
a pair of one-sided upper CUSUM control charts per payer:

    z_t = clip((x_t - mu) / sigma, +-z_clip)     mu/sigma from the payer's OWN
    S_t = min(max(0, S_{t-1} + z_t - k), s_cap)  clean exponentially-weighted
                                                 baseline (per-entity calibration)

CUSUM has closed-form average-run-length properties (Siegmund: for
standardized Gaussian input ARL0 ~ (e^{2k(h+1.166)} - 2k(h+1.166) - 1)/2k^2),
so the false-alarm rate per payer-series is quantifiable; the exact numbers
for the shipped defaults are in the README, together with the measured
fleet-wide rate from the offline simulation.

Alarm policy — sustained multi-bucket drift only, never a single hot bucket,
and the volume chart must always be involved (amounts corroborate, never
accuse alone: per-minute amount sums are zero-inflated and lognormal-heavy-
tailed, so their standardized z is asymmetric — a run of benign whale minutes
charges the chart at up to +(z_clip - k) per bucket while zero minutes can
only drain it at a fraction of that, and such a walk crosses any single-series
bar eventually. Poisson event counts have no such asymmetry, and every
exfiltration variant that adds events lifts amount sums with it):
  * joint path:  BOTH the volume (count) and amount CUSUMs qualify at h —
    the slow-exfil signature moves both together;
  * single path: the volume CUSUM alone qualifies at the much higher h_single
    (an amount-only drift — same event count, larger amounts — surfaces in
    score docs and /drift/top but does not page);
  * a series "qualifies" only when its excursion has lasted
    >= min_drift_buckets AND its short-halflife EWMA of z (the complementary
    smoother) confirms the *recent* buckets are still elevated — so a couple
    of clipped benign spikes cannot alarm on their own;
  * cold-start guard: while a payer has fewer than warmup_buckets of observed
    history its charts stay pinned at S=0 — every bucket calibrates the
    baseline and none accumulates evidence, so a cold payer cannot alarm and
    a noisy early baseline cannot pre-charge an excursion.

The baseline freezes while a series is in a material excursion
(S >= baseline_freeze_s), so a persisting attack cannot teach itself into
the baseline; benign buckets keep adapting it.

No aiokafka / pydantic / numpy imports: this module must run under host
Python (3.14) for the offline validation suite in tests/offline_check.py.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

VOLUME, AMOUNT = "volume", "amount"


@dataclass(frozen=True)
class Params:
    """All tuning knobs, decoupled from pydantic so the detection core and
    tests run on host Python. app/config.py maps env vars onto this."""
    bucket_seconds: int = 60
    warmup_buckets: int = 30           # per-payer minutes of history before alarms
    cusum_k: float = 0.75              # allowance (sigma units): tuned for ~1.5sigma+ shifts,
                                       # with margin for the post-warmup calibration error
                                       # (sample-mean over warmup_buckets: sigma/sqrt(30) ~ 0.2sigma)
    cusum_h: float = 6.0               # joint-path threshold (both series)
    cusum_h_single: float = 10.0       # volume-only threshold: an exfil trickle whose
                                       # amounts ride under the winsorization cap can
                                       # present as volume-only drift (measured S peaks
                                       # ~10.4 on such runs; 11 missed them, benign
                                       # traffic stays well below either value)
    s_cap: float = 12.0                # cap on S: bounds post-attack recovery time
    z_clip: float = 3.0                # winsorize z: one benign whale can't buy an alarm
    min_drift_buckets: int = 6         # excursion must span at least this many buckets
    ewma_halflife_buckets: float = 5.0
    ewma_alarm_floor: float = 0.9      # recent z must still be elevated at alarm time      # recent z must still be elevated at alarm time
    baseline_halflife_buckets: float = 240.0
    # Stop baseline updates while S >= this. Set AT the joint threshold h, not
    # below it: a baseline whose warmup sample landed low keeps a small
    # positive E[z] afterwards, and if the freeze bites below the alarm bar
    # the baseline can never learn its way back up while the chart stays
    # charged — a deadlock that ends in a guaranteed benign alarm. At h, the
    # miscalibrated-but-benign regime keeps self-correcting, while a real
    # attack races past h within a few buckets and freezes as intended.
    baseline_freeze_s: float = 5.0
    # Sigma floors encode the granularity of the observable itself: a payer's
    # minute-count is never treated as more predictable than +-1 event, nor
    # its minute-amount than +-1 typical event's value (~200k IDR). Without
    # the floors, low-rate payers get sub-event "precision" and a single
    # ordinary 2-event minute standardizes to z > 2 — pure discreteness
    # noise that a cumulative chart then happily accumulates into an alarm.
    count_sigma_floor: float = 1.0
    amount_sigma_floor: float = 200_000.0  # IDR; ~1.2x the economy's per-event mean
    amount_sigma_rel: float = 0.35         # relative floor: 0.35 * baseline mean
    # Winsorize each event's amount before it enters the bucket sum. Amounts
    # are lognormal-heavy-tailed, so an un-capped sigma estimated from a
    # warmup-sized sample is dominated by whether it happened to contain a
    # whale — unusably noisy at n~30. The cap (~p97 of the traffic economy's
    # per-event amounts) bounds a whale's influence on both the baseline and
    # the chart; a slow-exfil trickle keeps paying mostly under the cap, and
    # its extra *events* lift the capped sum regardless.
    amount_event_cap: float = 1_000_000.0
    score_emit_floor: float = 2.0      # emit score docs once max(S) reaches this
    max_alerts_per_bucket: int = 5
    max_tracked_payers: int = 10_000
    flush_after_seconds: float = 75.0
    flush_idle_seconds: float = 15.0


class EWStats:
    """Exponentially-weighted running mean/variance with a two-phase rate:
    plain sample statistics (alpha_t = 1/n) while the series is younger than
    calibration_n buckets, then a hard switch to the fixed exponential rate.

    The two phases separate the two timescales a cumulative detector must
    keep apart. During calibration the estimate has to converge fast and
    unbiased (a long-halflife EW seeded on its first value would stay pinned
    near that one bucket for hundreds of minutes). After calibration the rate
    must be SMALL: baseline error is persistent and can correct over hours,
    but an attack lasts minutes — at alpha ~ 1/n the first buckets of a drift
    excursion would be absorbed into the baseline faster than the CUSUM can
    accumulate them (observed as missed detections), while at the fixed
    240-bucket halflife a 10-minute excursion moves the mean by well under
    0.1 sigma. Constant memory; serializes to three floats."""

    __slots__ = ("alpha", "calibration_n", "n", "mean", "var")

    def __init__(self, halflife: float, calibration_n: int = 0) -> None:
        self.alpha = 1.0 - 0.5 ** (1.0 / max(halflife, 1.0))
        self.calibration_n = calibration_n
        self.n = 0
        self.mean = 0.0
        self.var = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        if self.n == 1:
            self.mean = x
            self.var = 0.0
            return
        a = 1.0 / self.n if self.n <= self.calibration_n else self.alpha
        delta = x - self.mean
        self.mean += a * delta
        self.var = (1.0 - a) * (self.var + a * delta * delta)

    def std(self) -> float:
        return math.sqrt(max(self.var, 0.0))

    def to_dict(self) -> dict:
        return {"n": self.n, "mean": self.mean, "var": self.var}

    @classmethod
    def from_dict(cls, halflife: float, d: dict, calibration_n: int = 0) -> "EWStats":
        s = cls(halflife, calibration_n)
        s.n = int(d.get("n", 0))
        s.mean = float(d.get("mean", 0.0))
        s.var = float(d.get("var", 0.0))
        return s


class CusumSeries:
    """One one-sided upper CUSUM chart with its own EW baseline and a
    short-halflife EWMA of the standardized values (recency smoother)."""

    __slots__ = ("baseline", "s", "run", "ewma_z", "excursion_start", "_ewma_alpha")

    def __init__(self, p: Params) -> None:
        self.baseline = EWStats(p.baseline_halflife_buckets, p.warmup_buckets)
        self._ewma_alpha = 1.0 - 0.5 ** (1.0 / max(p.ewma_halflife_buckets, 1.0))
        self.s = 0.0
        self.run = 0                          # buckets since S was last 0
        self.ewma_z = 0.0
        self.excursion_start: int | None = None  # epoch s of the bucket that lifted S off 0

    def update(self, x: float, minute_start: int, sigma_floor: float,
               warming: bool, p: Params) -> float:
        b = self.baseline
        if b.n >= 2:
            sigma = max(b.std(), sigma_floor)
            z = (x - b.mean) / sigma
        else:
            z = 0.0
        zc = max(-p.z_clip, min(p.z_clip, z))
        self.ewma_z += self._ewma_alpha * (zc - self.ewma_z)
        if warming:
            # The chart only runs on a calibrated baseline: while the payer
            # warms up, S stays pinned at 0 (an excursion accumulated against
            # a half-baked mu/sigma would be meaningless) and every bucket
            # feeds the baseline.
            self.s = 0.0
            self.run = 0
            self.excursion_start = None
            b.update(x)
            return zc
        self.s = min(max(0.0, self.s + zc - p.cusum_k), p.s_cap)
        if self.s > 0.0:
            if self.excursion_start is None:
                self.excursion_start = minute_start
            self.run += 1
        else:
            self.excursion_start = None
            self.run = 0
        # Score-then-update, with an attack-absorption guard: the baseline
        # only learns from buckets observed while the chart is quiescent.
        if self.s < p.baseline_freeze_s:
            b.update(x)
        return zc

    def qualifies(self, threshold: float, p: Params) -> bool:
        """Sustained-drift gate: level, excursion length, and recency."""
        return (
            self.s >= threshold
            and self.run >= p.min_drift_buckets
            and self.ewma_z >= p.ewma_alarm_floor
        )

    def to_dict(self) -> dict:
        return {
            "baseline": self.baseline.to_dict(),
            "s": self.s,
            "run": self.run,
            "ewma_z": self.ewma_z,
            "excursion_start": self.excursion_start,
        }

    @classmethod
    def from_dict(cls, p: Params, d: dict) -> "CusumSeries":
        c = cls(p)
        c.baseline = EWStats.from_dict(p.baseline_halflife_buckets,
                                       d.get("baseline") or {}, p.warmup_buckets)
        c.s = float(d.get("s", 0.0))
        c.run = int(d.get("run", 0))
        c.ewma_z = float(d.get("ewma_z", 0.0))
        start = d.get("excursion_start")
        c.excursion_start = int(start) if start is not None else None
        return c


@dataclass
class Assessment:
    """One payer-bucket verdict, ready to be wrapped into the score envelope."""
    warming: bool
    anomaly_score: float
    is_anomalous: bool
    reasons: list[str]
    features: dict
    baseline: dict
    window_start: int  # epoch seconds — start of the accumulation window
    summary: str = ""
    details: dict = field(default_factory=dict)


class PayerDrift:
    """Per-payer drift state: volume + amount CUSUM charts and the cumulative
    tally of the current excursion."""

    __slots__ = ("volume", "amount", "buckets_observed", "exc_events", "exc_amount")

    def __init__(self, p: Params) -> None:
        self.volume = CusumSeries(p)
        self.amount = CusumSeries(p)
        self.buckets_observed = 0
        self.exc_events = 0          # events accumulated over the active excursion
        self.exc_amount = 0.0        # amount accumulated over the active excursion

    @property
    def s_max(self) -> float:
        return max(self.volume.s, self.amount.s)

    def update(self, count: int, amount_sum: float, distinct_payees: int,
               minute_start: int, p: Params) -> Assessment:
        self.buckets_observed += 1
        warming = self.buckets_observed < p.warmup_buckets
        vol_floor = max(p.count_sigma_floor,
                        math.sqrt(max(self.volume.baseline.mean, 0.25)))
        amt_floor = max(p.amount_sigma_floor,
                        p.amount_sigma_rel * self.amount.baseline.mean)
        self.volume.update(float(count), minute_start, vol_floor, warming, p)
        self.amount.update(amount_sum, minute_start, amt_floor, warming, p)

        starts = [s.excursion_start for s in (self.volume, self.amount)
                  if s.excursion_start is not None]
        if not starts:
            self.exc_events = 0
            self.exc_amount = 0.0
            window_start = minute_start
        else:
            window_start = min(starts)
            if window_start == minute_start:  # this bucket opened the excursion
                self.exc_events = count
                self.exc_amount = amount_sum
            else:
                self.exc_events += count
                self.exc_amount += amount_sum

        vol_ok = self.volume.qualifies(p.cusum_h, p)
        amt_ok = self.amount.qualifies(p.cusum_h, p)
        joint = vol_ok and amt_ok
        # Volume-only backstop; there is deliberately no amount-only path
        # (see the alarm-policy note in the module docstring).
        single = self.volume.qualifies(p.cusum_h_single, p)
        anomalous = (not warming) and (joint or single)

        sc, sa = self.volume.s, self.amount.s
        score = round(min(1.0, self.s_max / (2.0 * p.cusum_h)), 4)
        run = max(self.volume.run, self.amount.run)
        ratio = self._mean_amount_ratio()

        reasons: list[str] = []
        if sc >= p.score_emit_floor or anomalous:
            mark = f">{p.cusum_h:g}" if sc >= p.cusum_h else ""
            reasons.append(f"cusum_volume={sc:.1f}{mark}")
        if sa >= p.score_emit_floor or anomalous:
            mark = f">{p.cusum_h:g}" if sa >= p.cusum_h else ""
            reasons.append(f"cusum_amount={sa:.1f}{mark}")
        if anomalous:
            if ratio > 1.0:
                reasons.append(f"cumulative_amount_drift=+{(ratio - 1.0) * 100:.0f}%")
            reasons.append(f"sustained={run}m")

        features = {
            "cusum_volume": round(sc, 2),
            "cusum_amount": round(sa, 2),
            "buckets_elevated": run,
            "bucket_events": count,
            "bucket_amount": round(amount_sum, 2),
            "cumulative_events": self.exc_events,
            "cumulative_amount": round(self.exc_amount, 2),
            "mean_amount_ratio": round(ratio, 2),
            "distinct_payees": distinct_payees,
            "ewma_volume_z": round(self.volume.ewma_z, 2),
            "ewma_amount_z": round(self.amount.ewma_z, 2),
        }
        baseline = {
            "rate_mean": round(self.volume.baseline.mean, 3),
            "rate_std": round(self.volume.baseline.std(), 3),
            "amount_mean": round(self.amount.baseline.mean, 1),
            "amount_std": round(self.amount.baseline.std(), 1),
            "buckets_observed": self.buckets_observed,
        }
        assessment = Assessment(
            warming=warming,
            anomaly_score=score,
            is_anomalous=anomalous,
            reasons=reasons,
            features=features,
            baseline=baseline,
            window_start=window_start,
        )
        if anomalous:
            duration_min = max(1, (minute_start + p.bucket_seconds - window_start) // 60)
            assessment.summary = (
                f"{self.exc_events} events moving {self.exc_amount:,.0f} IDR accumulated "
                f"over {duration_min} min vs baseline {self.volume.baseline.mean:.1f} ev/min "
                f"at {self.amount.baseline.mean:,.0f} IDR/min "
                f"(mean amount ratio {ratio:.1f}x; cusum volume={sc:.1f}, amount={sa:.1f})."
            )
            assessment.details = {
                "cusum_volume": round(sc, 1),
                "cusum_amount": round(sa, 1),
                "buckets_elevated": run,
                "mean_amount_ratio": round(ratio, 2),
                "cumulative_events": self.exc_events,
                "cumulative_amount": round(self.exc_amount, 2),
            }
        return assessment

    def _mean_amount_ratio(self) -> float:
        """Per-event amount over the excursion vs the baseline per-event amount."""
        if self.exc_events <= 0:
            return 0.0
        base_rate = self.volume.baseline.mean
        base_amount = self.amount.baseline.mean
        if base_rate <= 0.0 or base_amount <= 0.0:
            return 0.0
        return (self.exc_amount / self.exc_events) / (base_amount / base_rate)

    def to_dict(self) -> dict:
        return {
            "volume": self.volume.to_dict(),
            "amount": self.amount.to_dict(),
            "buckets_observed": self.buckets_observed,
            "exc_events": self.exc_events,
            "exc_amount": self.exc_amount,
        }

    @classmethod
    def from_dict(cls, p: Params, d: dict) -> "PayerDrift":
        drift = cls(p)
        drift.volume = CusumSeries.from_dict(p, d.get("volume") or {})
        drift.amount = CusumSeries.from_dict(p, d.get("amount") or {})
        drift.buckets_observed = int(d.get("buckets_observed", 0))
        drift.exc_events = int(d.get("exc_events", 0))
        drift.exc_amount = float(d.get("exc_amount", 0.0))
        return drift
