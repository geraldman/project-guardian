"""Mock LTI API — synthetic FinTech transaction router + traffic/attack generator.

Phase 0 scaffold: /health and read-only status only. The generator loop,
attack injection, telemetry emitter, and /transactions/route land on
feat/mock-lti (see docs/architecture.md).
"""
from fastapi import FastAPI

from .config import settings

app = FastAPI(title="Mock LTI API", version="0.1.0")


@app.get("/health")
def health():
    return {"status": "ok", "service": "mock-lti"}


@app.get("/admin/generator/status")
def generator_status():
    return {
        "implemented": False,
        "note": "generator loop lands via feat/mock-lti",
        "config": {
            "events_per_second": settings.events_per_second,
            "attack_mode": settings.attack_mode,
            "capture_ingest_url": settings.capture_ingest_url,
        },
    }
