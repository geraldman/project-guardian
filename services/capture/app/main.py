"""capture-agent — ingestion boundary between telemetry sources and Redpanda.

MVP stand-in for a real eBPF/AF_PACKET mirror agent (see README + docs/architecture.md
for the rationale and the planned Tetragon swap-in on the Linux VPS deployment).

Receives telemetry over POST /ingest and produces it to the Redpanda topic
(guardian.telemetry.raw). The producer connects in the background with backoff;
until it is up, /ingest answers 503 and /health reports degraded.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status

from .config import settings
from .producer import TelemetryProducer
from .schemas import TelemetryEvent

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("capture.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    producer = TelemetryProducer(settings.redpanda_brokers, settings.telemetry_topic)
    producer.start()
    app.state.producer = producer
    yield
    await producer.stop()


app = FastAPI(title="GUARDIAN capture-agent", version="0.2.0", lifespan=lifespan)


@app.get("/health")
def health():
    producer: TelemetryProducer = app.state.producer
    return {
        "status": "ok" if producer.connected else "degraded",
        "service": "capture-agent",
        "producer_connected": producer.connected,
        "topic": producer.topic,
    }


@app.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest(events: TelemetryEvent | list[TelemetryEvent]):
    producer: TelemetryProducer = app.state.producer
    batch = events if isinstance(events, list) else [events]
    if not producer.connected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="telemetry producer not connected to Redpanda yet; retry shortly",
        )
    queued = 0
    for event in batch:
        try:
            await producer.send(event.model_dump(mode="json"))
            queued += 1
        except Exception:
            log.exception("failed to produce event %s", event.event_id)
    if batch and queued == 0:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Redpanda rejected the whole batch; broker may be down",
        )
    return {"accepted": len(batch), "queued": queued, "topic": producer.topic}
