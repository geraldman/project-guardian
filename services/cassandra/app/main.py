"""CASSANDRA — cumulative per-payer drift detector (slow exfiltration).

Consumes guardian.telemetry.normalized, aggregates 1-minute per-payer
buckets, runs paired CUSUM control charts (event volume + amount moved) with
per-payer calibrated baselines, and emits score documents (guardian.scores)
and slow_exfiltration alerts (guardian.alerts). Vector carries both into
OpenSearch; the alerting service turns alerts into Slack/Discord messages.
"""
import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from .config import settings
from .kafka import CassandraKafka
from .pipeline import Pipeline

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("cassandra.main")

FLUSH_CHECK_SECONDS = 10.0


def _load_state(pipeline: Pipeline) -> None:
    try:
        with open(settings.state_path, encoding="utf-8") as f:
            pipeline.load_state(json.load(f))
    except FileNotFoundError:
        log.info("no drift state at %s — starting cold", settings.state_path)
    except (json.JSONDecodeError, OSError):
        log.exception("drift state unreadable — starting cold")


def _snapshot_state(pipeline: Pipeline) -> None:
    tmp = settings.state_path + ".tmp"
    os.makedirs(os.path.dirname(settings.state_path), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(pipeline.state_dict(), f)
    os.replace(tmp, settings.state_path)  # atomic: never a half-written state


async def _flusher(kafka: CassandraKafka, pipeline: Pipeline) -> None:
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
            log.exception("drift state snapshot failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    pipeline = Pipeline(settings.to_params())
    _load_state(pipeline)
    kafka = CassandraKafka(
        settings.redpanda_brokers, settings.input_topic, settings.scores_topic,
        settings.alerts_topic, pipeline,
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
        log.exception("final drift state snapshot failed")


app = FastAPI(title="GUARDIAN CASSANDRA", version="0.1.0", lifespan=lifespan)


def _warm_count(pipeline: Pipeline) -> int:
    return sum(
        1 for d in pipeline.payers.values()
        if d.buckets_observed >= settings.warmup_buckets
    )


@app.get("/health")
def health():
    pipeline: Pipeline = app.state.pipeline
    kafka: CassandraKafka = app.state.kafka
    warm = _warm_count(pipeline)
    return {
        "status": "ok" if kafka.connected else "degraded",
        "service": "cassandra",
        "consumer_connected": kafka.connected,
        # Warm-up requirement: a payer may alarm only after warmup_buckets
        # minutes of its own observed history; the service is "warming up"
        # until at least one payer crossed that bar (README#warm-up).
        "warming_up": warm == 0,
        "payers_tracked": len(pipeline.payers),
        "payers_warm": warm,
        "warmup_buckets": settings.warmup_buckets,
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
        "payers_tracked": len(pipeline.payers),
        "payers_warm": _warm_count(pipeline),
        "config": {
            "bucket_seconds": settings.bucket_seconds,
            "warmup_buckets": settings.warmup_buckets,
            "cusum_k": settings.cusum_k,
            "cusum_h": settings.cusum_h,
            "cusum_h_single": settings.cusum_h_single,
            "min_drift_buckets": settings.min_drift_buckets,
            "ewma_alarm_floor": settings.ewma_alarm_floor,
        },
    }


@app.get("/drift/top")
def drift_top(n: int = 10):
    """The payers closest to (or over) the alarm bar right now — the live
    threat picture for debugging and the future HUD."""
    pipeline: Pipeline = app.state.pipeline
    ranked = sorted(pipeline.payers.items(), key=lambda kv: kv[1].s_max, reverse=True)
    return {
        "top": [
            {
                "payer_id": pid,
                "cusum_volume": round(d.volume.s, 2),
                "cusum_amount": round(d.amount.s, 2),
                "buckets_elevated": max(d.volume.run, d.amount.run),
                "warming_up": d.buckets_observed < settings.warmup_buckets,
                "buckets_observed": d.buckets_observed,
            }
            for pid, d in ranked[: max(1, min(n, 100))]
        ]
    }


@app.get("/baseline/payer/{payer_id}")
def baseline_payer(payer_id: str):
    pipeline: Pipeline = app.state.pipeline
    drift = pipeline.payers.get(payer_id)
    if drift is None:
        raise HTTPException(status_code=404, detail=f"no baseline yet for payer {payer_id}")
    return {
        "entity_type": "payer",
        "entity_id": payer_id,
        "warming_up": drift.buckets_observed < settings.warmup_buckets,
        "buckets_observed": drift.buckets_observed,
        "volume": drift.volume.to_dict(),
        "amount": drift.amount.to_dict(),
    }
