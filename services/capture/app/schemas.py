"""Telemetry event envelope — identical copy of the canonical contract.

Canonical spec: docs/architecture.md#event-schema (source copy in
services/mock-lti/app/schemas.py). If you change one, change the other
and the doc.
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
