"""ARGUS — transaction-rate / payload-size anomaly scorer.

Consumes guardian.telemetry.normalized, aggregates 1-minute buckets per
entity, scores them against exponentially-weighted baselines plus an
Isolation Forest / k-NN detector, and emits score documents
(guardian.scores) and alerts (guardian.alerts). Vector carries both into
OpenSearch; the alerting service turns alerts into Slack/Discord messages.
"""
import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from .config import settings
from .kafka import ArgusKafka
from .pipeline import Pipeline

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("argus.main")

FLUSH_CHECK_SECONDS = 10.0


def _load_state(pipeline: Pipeline) -> None:
    try:
        with open(settings.state_path, encoding="utf-8") as f:
            pipeline.load_state(json.load(f))
    except FileNotFoundError:
        log.info("no baseline state at %s — starting cold", settings.state_path)
    except (json.JSONDecodeError, OSError):
        log.exception("baseline state unreadable — starting cold")


def _snapshot_state(pipeline: Pipeline) -> None:
    tmp = settings.state_path + ".tmp"
    os.makedirs(os.path.dirname(settings.state_path), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(pipeline.state_dict(), f)
    os.replace(tmp, settings.state_path)  # atomic: never a half-written state


async def _flusher(kafka: ArgusKafka, pipeline: Pipeline) -> None:
    while True:
        await asyncio.sleep(FLUSH_CHECK_SECONDS)
        for minute in sorted(pipeline.stale_minutes()):
            await kafka.finalize_and_emit(minute)


async def _snapshotter(pipeline: Pipeline) -> None:
    while True:
        await asyncio.sleep(settings.snapshot_interval_seconds)
        try:
            _snapshot_state(pipeline)
        except OSError:
            log.exception("baseline snapshot failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    pipeline = Pipeline(settings)
    _load_state(pipeline)
    kafka = ArgusKafka(
        settings.redpanda_brokers, settings.input_topic, settings.scores_topic,
        settings.alerts_topic, pipeline, asyncio.Lock(),
    )
    kafka.start()
    tasks = [
        asyncio.create_task(_flusher(kafka, pipeline)),
        asyncio.create_task(_snapshotter(pipeline)),
    ]
    app.state.pipeline = pipeline
    app.state.kafka = kafka
    yield
    for task in tasks:
        task.cancel()
    await kafka.stop()
    try:
        _snapshot_state(pipeline)
    except OSError:
        log.exception("final baseline snapshot failed")


app = FastAPI(title="GUARDIAN ARGUS", version="0.1.0", lifespan=lifespan)


@app.get("/health")
def health():
    pipeline: Pipeline = app.state.pipeline
    kafka: ArgusKafka = app.state.kafka
    global_stats = pipeline.entities.get("global")
    buckets_observed = global_stats["rate"].n if global_stats else 0
    return {
        "status": "ok" if kafka.connected else "degraded",
        "service": "argus",
        "consumer_connected": kafka.connected,
        "warming_up": buckets_observed < settings.warmup_buckets,
        "buckets_observed": buckets_observed,
        "warmup_buckets": settings.warmup_buckets,
        "model_fitted": pipeline.detector.fitted,
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
        "entities_tracked": len(pipeline.entities),
        "ip_cohort": pipeline.ip_cohort.to_dict(),
        "model": {
            "fitted": pipeline.detector.fitted,
            "fit_count": pipeline.detector.fit_count,
            "reservoir_size": len(pipeline.detector.reservoir),
        },
        "config": {
            "bucket_seconds": settings.bucket_seconds,
            "warmup_buckets": settings.warmup_buckets,
            "z_threshold": settings.z_threshold,
            "ew_halflife_buckets": settings.ew_halflife_buckets,
        },
    }


@app.get("/baseline/global")
def baseline_global():
    return _baseline("global")


@app.get("/baseline/payer/{payer_id}")
def baseline_payer(payer_id: str):
    return _baseline(f"payer:{payer_id}")


@app.get("/baseline/client_ip")
def baseline_ip_cohort():
    """client_ip baselines are cohort-wide (see docs/architecture.md)."""
    pipeline: Pipeline = app.state.pipeline
    return {"entity_type": "client_ip", "cohort": pipeline.ip_cohort.to_dict()}


def _baseline(key: str):
    pipeline: Pipeline = app.state.pipeline
    stats = pipeline.entities.get(key)
    if stats is None:
        raise HTTPException(status_code=404, detail=f"no baseline yet for {key}")
    etype, _, eid = key.partition(":")
    return {
        "entity_type": etype if eid else "global",
        "entity_id": eid or "global",
        "warming_up": stats["rate"].n < settings.warmup_buckets,
        "features": {name: s.to_dict() for name, s in stats.items()},
    }
