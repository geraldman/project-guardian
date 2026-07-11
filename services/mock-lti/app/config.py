from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Throttled for laptop dev; LTI's production figure is 5M+ tx/day (~58/s avg).
    events_per_second: float = 10.0
    attack_mode: str = "mixed"  # off | burst | malformed | mixed
    capture_ingest_url: str = "http://capture-agent:8001/ingest"
    emit_timeout_seconds: float = 2.0


settings = Settings()
