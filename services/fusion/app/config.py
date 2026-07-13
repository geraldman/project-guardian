from dataclasses import fields

from pydantic_settings import BaseSettings

from .engine import FusionConfig


class Settings(BaseSettings):
    redpanda_brokers: str = "redpanda:9092"
    input_topic: str = "guardian.scores"
    scores_topic: str = "guardian.scores"
    alerts_topic: str = "guardian.alerts"

    # How often the ticker advances the engine (decay, level checks). The
    # engine itself decides when the ~30s cadence / significant-change /
    # transition rules warrant an actual emission.
    tick_seconds: float = 2.0

    # Engine tunables — defaults live on FusionConfig (single source of
    # truth); every field is env-overridable (e.g. WEIGHT_ARGUS=0.7,
    # HALF_LIFE_SECONDS=60). See engine.py for what each knob does.
    weight_argus: float = FusionConfig.weight_argus
    weight_sentinel: float = FusionConfig.weight_sentinel
    weight_cassandra: float = FusionConfig.weight_cassandra
    weight_default: float = FusionConfig.weight_default
    half_life_seconds: float = FusionConfig.half_life_seconds
    corroboration_boost: float = FusionConfig.corroboration_boost
    active_floor: float = FusionConfig.active_floor
    breadth_weight: float = FusionConfig.breadth_weight
    min_contrib_events: int = FusionConfig.min_contrib_events
    stale_after_seconds: float = FusionConfig.stale_after_seconds
    elevated_up: float = FusionConfig.elevated_up
    elevated_down: float = FusionConfig.elevated_down
    critical_up: float = FusionConfig.critical_up
    critical_down: float = FusionConfig.critical_down
    emit_interval_seconds: float = FusionConfig.emit_interval_seconds
    emit_delta: float = FusionConfig.emit_delta
    top_entities: int = FusionConfig.top_entities
    transitions_kept: int = FusionConfig.transitions_kept

    def fusion_config(self) -> FusionConfig:
        return FusionConfig(
            **{f.name: getattr(self, f.name) for f in fields(FusionConfig)}
        )


settings = Settings()
