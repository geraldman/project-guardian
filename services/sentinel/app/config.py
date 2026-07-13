from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    redpanda_brokers: str = "redpanda:9092"
    input_topic: str = "guardian.telemetry.normalized"
    scores_topic: str = "guardian.scores"
    alerts_topic: str = "guardian.alerts"

    # Windowing: 1-minute tumbling windows per client_ip, finalized with the
    # same per-partition watermark + wall-clock flush scheme as ARGUS
    # (services/argus/app/pipeline.py explains why a global watermark breaks).
    window_seconds: int = 60
    flush_after_seconds: float = 75.0
    flush_idle_seconds: float = 15.0

    # Decision thresholds. model_score = P(malicious) + 0.5 * P(suspicious);
    # >= anomaly_threshold is anomalous, [suspicious_threshold, anomaly_threshold)
    # is the "suspicious" middle band (score doc, no alert). Level-0 rule hits
    # (unambiguous signatures) bypass the model floor entirely.
    anomaly_threshold: float = 0.70
    suspicious_threshold: float = 0.40

    # >= this many auth failures from one IP in one window is a credential-
    # stuffing storm (unambiguous); below it a lone 401 is just suspicious.
    auth_fail_storm: int = 3

    # Emission floors: model-only anomalies need >=min_window_events so a
    # single ambiguous line can't page anyone (level-0 signature hits are
    # exempt: one SQLi line IS the evidence). Score docs are emitted for
    # anomalous/suspicious windows or >=min_score_events (mirrors ARGUS's
    # volume floor so ~1-event benign windows don't flood guardian-scores-*).
    min_window_events: int = 3
    min_score_events: int = 3
    max_alerts_per_window: int = 5

    # Committed XGBoost artifact (trained by training/train_sentinel.py);
    # relative to the container WORKDIR /app.
    model_path: str = "model/sentinel_xgb.json"


settings = Settings()
