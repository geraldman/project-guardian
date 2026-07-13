"""fusion — unified Guardian threat state.

Consumes guardian.scores (ARGUS / SENTINEL / CASSANDRA output; its own
score.model="guardian" documents are filtered out), maintains a decayed
per-entity and global threat state with a corroboration boost and level
hysteresis, and emits guardian score documents (~30s cadence and on any
significant change) plus threat_level_change alerts on level transitions.
Pure Kafka-in/Kafka-out — Vector carries both topics into OpenSearch.
GET /threat serves the current picture for the Guardian Pulse HUD.

Threat state is deliberately NOT persisted across restarts: its half-life is
minutes, so a restart loses nothing that the live stream doesn't rebuild
within a couple of minutes (unlike ARGUS baselines, which take much longer
to learn and are snapshotted).
"""
import asyncio
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .config import settings
from .engine import FusionEngine
from .kafka import FusionKafka

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("fusion.main")


async def _ticker(kafka: FusionKafka, engine: FusionEngine) -> None:
    """Advances the engine (decay + level checks) and publishes whatever it
    decides to emit. Consume loop and ticker share the event loop and the
    engine methods never await, so no locking is needed."""
    while True:
        await asyncio.sleep(settings.tick_seconds)
        docs, alerts = engine.tick(time.time())
        if docs or alerts:
            await kafka.publish(docs, alerts)


@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = FusionEngine(settings.fusion_config())
    kafka = FusionKafka(
        settings.redpanda_brokers, settings.input_topic,
        settings.scores_topic, settings.alerts_topic, engine,
    )
    kafka.start()
    ticker = asyncio.create_task(_ticker(kafka, engine))
    app.state.engine = engine
    app.state.kafka = kafka
    yield
    ticker.cancel()
    try:
        await ticker
    except asyncio.CancelledError:
        pass
    await kafka.stop()


app = FastAPI(title="GUARDIAN fusion", version="0.1.0", lifespan=lifespan)


@app.get("/health")
def health():
    engine: FusionEngine = app.state.engine
    kafka: FusionKafka = app.state.kafka
    return {
        "status": "ok" if kafka.connected else "degraded",
        "service": "fusion",
        "consumer_connected": kafka.connected,
        "threat_level": engine.level,
        "entities_tracked": len(engine.entities),
        "scores_folded": engine.counters["scores_folded"],
        "emits": engine.counters["emits"],
        "topics": {
            "in": settings.input_topic,
            "scores": settings.scores_topic,
            "alerts": settings.alerts_topic,
        },
    }


@app.get("/threat")
def threat():
    """The current unified threat picture (Guardian Pulse HUD feed):
    global level + decayed score, per-model contributors, top entities with
    their per-entity states, recent transitions, counters, config."""
    engine: FusionEngine = app.state.engine
    return engine.snapshot(time.time())
