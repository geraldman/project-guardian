from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    redpanda_brokers: str = "redpanda:9092"
    telemetry_topic: str = "guardian.telemetry.raw"


settings = Settings()
