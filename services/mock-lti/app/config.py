from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Throttled for laptop dev; LTI's production figure is 5M+ tx/day (~58/s avg).
    events_per_second: float = 10.0
    attack_mode: str = "mixed"  # off | burst | malformed | mixed | slow_exfil | log_attack
    capture_ingest_url: str = "http://capture-agent:8001/ingest"
    emit_timeout_seconds: float = 2.0

    # slow_exfil tunables (see generator.py / docs/architecture.md#attack-modes).
    exfil_payer_id: str = "wallet-user-0001"
    exfil_events_per_minute: float = 2.0
    exfil_amount_multiplier: float = 1.8
    # log_attack: share of non-burst events carrying malicious log content.
    log_attack_probability: float = 0.08


settings = Settings()
