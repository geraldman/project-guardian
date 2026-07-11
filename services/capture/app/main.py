"""capture-agent — ingestion boundary between telemetry sources and Redpanda.

MVP stand-in for a real eBPF/AF_PACKET mirror agent (see README + docs/architecture.md
for the rationale and the planned Tetragon swap-in on the Linux VPS deployment).

Phase 0 scaffold: /health + a validating /ingest stub that does NOT yet produce
to Redpanda. The aiokafka producer lands on feat/capture-agent.
"""
from fastapi import FastAPI, status

from .config import settings
from .schemas import TelemetryEvent

app = FastAPI(title="GUARDIAN capture-agent", version="0.1.0")


@app.get("/health")
def health():
    return {"status": "ok", "service": "capture-agent"}


@app.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
def ingest(events: TelemetryEvent | list[TelemetryEvent]):
    batch = events if isinstance(events, list) else [events]
    return {
        "accepted": len(batch),
        "queued": 0,
        "note": "validated only — Redpanda producer lands via feat/capture-agent",
        "topic": settings.telemetry_topic,
    }
