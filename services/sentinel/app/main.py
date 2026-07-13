"""SENTINEL — log-line classification scorer.

Consumes guardian.telemetry.normalized, template-parses each event's gateway
log line (Drain3), aggregates 1-minute windows per client_ip, and classifies
them with a rule pre-filter + XGBoost cascade. Anomalous windows emit score
documents (guardian.scores) and log_classification alerts (guardian.alerts);
Vector carries both into OpenSearch, the alerting service pages.
"""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .config import settings
from .kafka import SentinelKafka
from .model import SentinelModel
from .pipeline import Pipeline

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("sentinel.main")

FLUSH_CHECK_SECONDS = 10.0


async def _flusher(kafka: SentinelKafka, pipeline: Pipeline) -> None:
    while True:
        await asyncio.sleep(FLUSH_CHECK_SECONDS)
        for minute in sorted(pipeline.stale_minutes()):
            await kafka.finalize_and_emit(minute)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail fast if the committed artifact is missing/drifted: a scorer that
    # can't score should never report healthy.
    model = SentinelModel.load(settings.model_path)
    log.info("model loaded from %s (%d boosted rounds)", settings.model_path, model.num_trees)
    pipeline = Pipeline(settings, model)
    kafka = SentinelKafka(
        settings.redpanda_brokers, settings.input_topic, settings.scores_topic,
        settings.alerts_topic, pipeline, asyncio.Lock(),
    )
    kafka.start()
    flusher = asyncio.create_task(_flusher(kafka, pipeline))
    app.state.pipeline = pipeline
    app.state.kafka = kafka
    app.state.model = model
    yield
    flusher.cancel()
    await kafka.stop()


app = FastAPI(title="GUARDIAN SENTINEL", version="0.1.0", lifespan=lifespan)


@app.get("/health")
def health():
    pipeline: Pipeline = app.state.pipeline
    kafka: SentinelKafka = app.state.kafka
    return {
        "status": "ok" if kafka.connected else "degraded",
        "service": "sentinel",
        "consumer_connected": kafka.connected,
        "model_loaded": True,  # lifespan fails before serving otherwise
        "model_trees": app.state.model.num_trees,
        "windows_scored": pipeline.counters["windows_scored"],
        "topics": {
            "in": settings.input_topic,
            "scores": settings.scores_topic,
            "alerts": settings.alerts_topic,
        },
    }


@app.get("/stats")
def stats():
    pipeline: Pipeline = app.state.pipeline
    return {
        **pipeline.counters,
        "templates_mined": len(pipeline.miner.drain.clusters),
        "config": {
            "window_seconds": settings.window_seconds,
            "anomaly_threshold": settings.anomaly_threshold,
            "suspicious_threshold": settings.suspicious_threshold,
            "auth_fail_storm": settings.auth_fail_storm,
            "min_window_events": settings.min_window_events,
            "max_alerts_per_window": settings.max_alerts_per_window,
        },
    }


@app.get("/templates")
def templates():
    """The Drain3 template set mined so far — the live view of what the log
    stream's families look like."""
    pipeline: Pipeline = app.state.pipeline
    clusters = sorted(
        pipeline.miner.drain.clusters, key=lambda c: c.size, reverse=True
    )
    return {
        "count": len(clusters),
        "templates": [
            {"cluster_id": c.cluster_id, "size": c.size, "template": c.get_template()}
            for c in clusters[:100]
        ],
    }
