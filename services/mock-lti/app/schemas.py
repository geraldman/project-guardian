"""Canonical telemetry event envelope — THE cross-service contract.

Human-readable spec lives in docs/architecture.md#event-schema.
services/capture/app/schemas.py keeps an identical copy (separate build
contexts); if you change one, change the other and the doc.

The envelope itself is ALWAYS schema-valid, even for attack traffic:
malformation is expressed in the field *values* (negative amount, junk
currency, missing payer) plus raw_payload_valid=False — never by breaking
the JSON, so the pipeline keeps flowing while still surfacing bad data.
"""
from datetime import datetime
from pydantic import BaseModel


class TelemetryEvent(BaseModel):
    event_id: str                      # uuid4
    timestamp: datetime                # ISO8601 UTC
    source: str = "mock-lti"
    event_type: str                    # transaction | burst_spike | malformed_payload
    payer_id: str | None = None
    payee_id: str | None = None
    channel: str | None = None         # ecommerce | wallet | bank
    amount: float | None = None
    currency: str | None = None        # ISO 4217 when well-formed
    status: str                        # approved | declined | error | malformed
    latency_ms: float | None = None
    is_attack: bool = False
    attack_pattern: str | None = None  # burst | malformed | None
    client_ip: str | None = None       # synthetic
    raw_payload_valid: bool = True
