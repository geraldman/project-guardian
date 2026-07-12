from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    redpanda_brokers: str = "redpanda:9092"
    alerts_topic: str = "guardian.alerts"

    # The brief's extra-credit requirement: a 5-minute dedup window.
    dedup_seconds: float = 300.0

    # Leave both empty for log-only mode (alerts go to the container log —
    # the default for local dev so no secret is ever needed to demo).
    slack_webhook_url: str = ""
    discord_webhook_url: str = ""
    webhook_timeout_seconds: float = 10.0


settings = Settings()
