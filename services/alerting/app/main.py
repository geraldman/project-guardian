"""alerting — dedup + webhook alerter (the brief's extra-credit item).

Two inlets, one dedup window: ARGUS alerts arrive via the guardian.alerts
topic; OpenSearch Alerting monitors POST /notify through the
guardian-alerting-webhook notification channel. Either way, at most one
message per (entity, alert type) per DEDUP_SECONDS reaches Slack/Discord —
or the container log when no webhook is configured.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status

from .config import settings
from .dedup import Deduper
from .kafka import AlertConsumer
from .notifier import Notifier

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("alerting.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    deduper = Deduper(settings.dedup_seconds)
    notifier = Notifier(settings, deduper)
    consumer = AlertConsumer(settings.redpanda_brokers, settings.alerts_topic, notifier)
    consumer.start()
    app.state.deduper = deduper
    app.state.notifier = notifier
    app.state.consumer = consumer
    log.info("alerting up — mode=%s dedup=%.0fs", notifier.mode, settings.dedup_seconds)
    yield
    await consumer.stop()
    await notifier.aclose()


app = FastAPI(title="GUARDIAN alerting", version="0.1.0", lifespan=lifespan)


@app.get("/health")
def health():
    consumer: AlertConsumer = app.state.consumer
    notifier: Notifier = app.state.notifier
    return {
        "status": "ok" if consumer.connected else "degraded",
        "service": "alerting",
        "consumer_connected": consumer.connected,
        "mode": notifier.mode,
        "dedup_seconds": settings.dedup_seconds,
        "topic": consumer.topic,
    }


@app.get("/stats")
def stats():
    consumer: AlertConsumer = app.state.consumer
    notifier: Notifier = app.state.notifier
    deduper: Deduper = app.state.deduper
    return {
        **deduper.stats(),
        "delivered": notifier.delivered,
        "delivery_failures": notifier.delivery_failures,
        "malformed_messages": consumer.malformed,
        "mode": notifier.mode,
    }


@app.post("/notify", status_code=status.HTTP_202_ACCEPTED)
async def notify(body: dict):
    """Inlet for OpenSearch Alerting monitors (and manual tests). Accepts the
    topic contract shape {"alert": {...}} or a bare alert object."""
    alert = body.get("alert", body)
    if not isinstance(alert, dict) or not alert.get("type"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail='expected {"alert": {"type": ..., "summary": ...}}',
        )
    notifier: Notifier = app.state.notifier
    sent = await notifier.process(alert)
    return {"accepted": True, "sent": sent, "deduped": not sent}
