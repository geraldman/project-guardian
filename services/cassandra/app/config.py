from pydantic_settings import BaseSettings

from .detector import Params


class Settings(BaseSettings):
    redpanda_brokers: str = "redpanda:9092"
    input_topic: str = "guardian.telemetry.normalized"
    scores_topic: str = "guardian.scores"
    alerts_topic: str = "guardian.alerts"

    # Aggregation / warmup. Production design is days of per-payer history;
    # the demo compresses it to ~30 minutes, fast-forwarded by the earliest-
    # offset replay and/or training/seed_history.py (see README).
    bucket_seconds: int = 60
    warmup_buckets: int = 30

    # CUSUM drift detection (docs/architecture.md#cassandra ...; README has
    # the ARL trade-off table for these).
    cusum_k: float = 0.75
    cusum_h: float = 6.0
    cusum_h_single: float = 10.0
    s_cap: float = 12.0
    z_clip: float = 3.0
    min_drift_buckets: int = 6
    ewma_halflife_buckets: float = 5.0
    ewma_alarm_floor: float = 0.9

    # Per-payer baseline calibration (freeze pinned at h — see detector.py
    # on the calibration-deadlock hazard of freezing below the alarm bar).
    baseline_freeze_s: float = 5.0
    baseline_halflife_buckets: float = 240.0
    count_sigma_floor: float = 1.0
    amount_sigma_floor: float = 200_000.0
    amount_sigma_rel: float = 0.35
    amount_event_cap: float = 1_000_000.0

    # Emission / guards.
    score_emit_floor: float = 2.0
    max_alerts_per_bucket: int = 5
    max_tracked_payers: int = 10_000

    # Bucket finalization safety net for a stalled stream (same rationale as
    # ARGUS: flush long-over, idle buckets on the wall clock).
    flush_after_seconds: float = 75.0
    flush_idle_seconds: float = 15.0

    state_path: str = "/data/cassandra_state.json"
    snapshot_interval_seconds: float = 60.0

    def to_params(self) -> Params:
        """The detection core is pydantic-free (host-Python testable); hand it
        a plain Params built from the env-backed settings."""
        return Params(
            bucket_seconds=self.bucket_seconds,
            warmup_buckets=self.warmup_buckets,
            cusum_k=self.cusum_k,
            cusum_h=self.cusum_h,
            cusum_h_single=self.cusum_h_single,
            s_cap=self.s_cap,
            z_clip=self.z_clip,
            min_drift_buckets=self.min_drift_buckets,
            ewma_halflife_buckets=self.ewma_halflife_buckets,
            ewma_alarm_floor=self.ewma_alarm_floor,
            baseline_halflife_buckets=self.baseline_halflife_buckets,
            baseline_freeze_s=self.baseline_freeze_s,
            count_sigma_floor=self.count_sigma_floor,
            amount_sigma_floor=self.amount_sigma_floor,
            amount_sigma_rel=self.amount_sigma_rel,
            amount_event_cap=self.amount_event_cap,
            score_emit_floor=self.score_emit_floor,
            max_alerts_per_bucket=self.max_alerts_per_bucket,
            max_tracked_payers=self.max_tracked_payers,
            flush_after_seconds=self.flush_after_seconds,
            flush_idle_seconds=self.flush_idle_seconds,
        )


settings = Settings()
