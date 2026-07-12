"""Mock LTI API — synthetic FinTech transaction router + traffic/attack generator.

Endpoints:
  GET  /health                   liveness
  POST /transactions/route       demo-curlable routing endpoint; telemetry is
                                 emitted via BackgroundTasks AFTER the response
                                 is sent (async/non-blocking ingestion proof point)
  GET  /admin/generator/status   config + counters + uptime
  POST /admin/generator/config   runtime update of rate / attack mode
"""
import random
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Literal

from fastapi import BackgroundTasks, FastAPI, Request
from pydantic import BaseModel, Field

from .config import settings
from .generator import (
    ATTACK_MODES,
    BASELINE_DECLINE_RATE,
    TrafficGenerator,
    random_client_ip,
    random_latency_ms,
)
from .schemas import TelemetryEvent
from .telemetry import TelemetryEmitter


@asynccontextmanager
async def lifespan(app: FastAPI):
    emitter = TelemetryEmitter(settings.capture_ingest_url, settings.emit_timeout_seconds)
    generator = TrafficGenerator(emitter, settings.events_per_second, settings.attack_mode)
    app.state.emitter = emitter
    app.state.generator = generator
    generator.start()
    yield
    await generator.stop()
    await emitter.aclose()


app = FastAPI(title="Mock LTI API", version="0.2.0", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok", "service": "mock-lti"}


class RouteRequest(BaseModel):
    payer_id: str
    payee_id: str
    channel: Literal["ecommerce", "wallet", "bank"] = "ecommerce"
    amount: float = Field(gt=0)
    currency: str = "IDR"


class RouteResponse(BaseModel):
    transaction_id: str
    status: str  # approved | declined
    latency_ms: float
    timestamp: datetime


@app.post("/transactions/route", response_model=RouteResponse)
def route_transaction(
    payload: RouteRequest, background_tasks: BackgroundTasks, request: Request
):
    """Route one transaction; respond immediately, emit telemetry out-of-band."""
    status = "declined" if random.random() < BASELINE_DECLINE_RATE else "approved"
    now = datetime.now(timezone.utc)
    event = TelemetryEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now,
        event_type="transaction",
        payer_id=payload.payer_id,
        payee_id=payload.payee_id,
        channel=payload.channel,
        amount=payload.amount,
        currency=payload.currency,
        status=status,
        latency_ms=random_latency_ms(),
        client_ip=random_client_ip(),
    )
    # Runs after the response is sent -- telemetry adds zero response latency.
    background_tasks.add_task(request.app.state.emitter.send, event)
    return RouteResponse(
        transaction_id=event.event_id,
        status=status,
        latency_ms=event.latency_ms,
        timestamp=now,
    )


class GeneratorConfigUpdate(BaseModel):
    events_per_second: float | None = Field(default=None, gt=0, le=1000)
    attack_mode: Literal[*ATTACK_MODES] | None = None


@app.post("/admin/generator/config")
def update_generator_config(payload: GeneratorConfigUpdate, request: Request):
    generator: TrafficGenerator = request.app.state.generator
    generator.configure(payload.events_per_second, payload.attack_mode)
    return {
        "events_per_second": generator.events_per_second,
        "attack_mode": generator.attack_mode,
    }


@app.get("/admin/generator/status")
def generator_status(request: Request):
    generator: TrafficGenerator = request.app.state.generator
    emitter: TelemetryEmitter = request.app.state.emitter
    status = generator.status()
    return {
        "implemented": True,
        "config": {
            "events_per_second": status["events_per_second"],
            "attack_mode": status["attack_mode"],
            "capture_ingest_url": settings.capture_ingest_url,
        },
        "counters": {
            "events_emitted": status["events_emitted"],
            "attacks_injected": status["attacks_injected"],
            "telemetry": {"sent": emitter.sent, "failed": emitter.failed},
        },
        "uptime_seconds": status["uptime_seconds"],
    }
