from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    redpanda_brokers: str = "redpanda:9092"
    input_topic: str = "guardian.telemetry.normalized"
    scores_topic: str = "guardian.scores"
    alerts_topic: str = "guardian.alerts"

    # Aggregation / baseline. Production design is a 7-day window; the demo
    # compresses warmup + halflife so a fresh stack detects within ~15 minutes
    # (docs/architecture.md#detection-layer).
    bucket_seconds: int = 60
    warmup_buckets: int = 15
    z_threshold: float = 3.0
    ew_halflife_buckets: float = 120.0

    # Emission floors: entity score docs need >=min_bucket_events (or an
    # anomaly) to be indexed; entity alerts additionally need
    # >=min_alert_events so Poisson noise on quiet payers can't page anyone.
    min_bucket_events: int = 3
    min_alert_events: int = 10
    max_alerts_per_bucket: int = 5

    # Multivariate detector (Isolation Forest + k-NN on recent bucket vectors).
    multivariate_threshold: float = 0.7
    reservoir_size: int = 4000
    min_fit_samples: int = 200
    refit_interval_buckets: int = 15

    # Bucket finalization safety net for a stalled stream: flush buckets whose
    # window ended >flush_after_seconds ago (wall clock) and that have been
    # idle >flush_idle_seconds (protects fast backdated seed replays).
    flush_after_seconds: float = 75.0
    flush_idle_seconds: float = 15.0

    state_path: str = "/data/argus_state.json"
    snapshot_interval_seconds: float = 60.0


settings = Settings()
