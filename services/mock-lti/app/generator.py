"""Background synthetic-traffic loop with attack injection.

Baseline traffic mimics LTI-style B2B micro-transaction routing.
Attack modes (runtime-switchable via /admin/generator/config):

  burst     -- every 60-120s the event rate spikes 10-20x for 5-10s,
               sourced from a handful of attacker IPs
               (event_type=burst_spike, is_attack=True, attack_pattern=burst)
  malformed -- a fraction of events carry intentionally bad *values*
               (negative amount, junk currency, or missing payer_id) with
               raw_payload_valid=False. The JSON envelope itself always
               stays schema-valid -- pipeline invariant, see
               docs/architecture.md#event-schema.
  mixed     -- both of the above
  off       -- clean baseline only
"""
import asyncio
import random
import time
import uuid
from datetime import datetime, timezone

from .schemas import TelemetryEvent
from .telemetry import TelemetryEmitter

ATTACK_MODES = ("off", "burst", "malformed", "mixed")

# Entity pools -- sized so ids repeat enough to aggregate on in dashboards.
MERCHANTS = [f"merchant-{i:04d}" for i in range(1, 201)]
BANKS = [f"bank-{i:03d}" for i in range(1, 21)]
WALLET_USERS = [f"wallet-user-{i:04d}" for i in range(1, 501)]
CHANNELS = ("ecommerce", "wallet", "bank")

BASELINE_DECLINE_RATE = 0.03
MALFORMED_PROBABILITY = 0.08
JUNK_CURRENCIES = ("RUPIAH", "ID R", "???", "XXX!!", "")

BURST_EVERY_SECONDS = (60.0, 120.0)
BURST_DURATION_SECONDS = (5.0, 10.0)
BURST_MULTIPLIER = (10.0, 20.0)
BURST_SOURCE_IPS = 4  # a flood comes from few origins


def random_client_ip() -> str:
    return f"10.{random.randint(0, 3)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _amount_idr() -> float:
    # Log-normal micro-transaction amounts: median ~100k IDR, long tail
    # into the millions, rounded to hundreds like real IDR pricing.
    amount = random.lognormvariate(11.5, 1.0)
    return round(min(max(amount, 1_000.0), 50_000_000.0), -2)


def random_latency_ms() -> float:
    # Median ~12ms routing latency with a plausible slow tail.
    return round(random.lognormvariate(2.5, 0.5), 1)


def _parties(channel: str) -> tuple[str, str]:
    if channel == "ecommerce":
        return random.choice(WALLET_USERS), random.choice(MERCHANTS)
    if channel == "wallet":
        return random.choice(WALLET_USERS), random.choice(WALLET_USERS + MERCHANTS)
    return random.choice(MERCHANTS), random.choice(BANKS)  # bank settlement


def make_transaction() -> TelemetryEvent:
    channel = random.choice(CHANNELS)
    payer_id, payee_id = _parties(channel)
    return TelemetryEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        event_type="transaction",
        payer_id=payer_id,
        payee_id=payee_id,
        channel=channel,
        amount=_amount_idr(),
        currency="IDR",
        status="declined" if random.random() < BASELINE_DECLINE_RATE else "approved",
        latency_ms=random_latency_ms(),
        client_ip=random_client_ip(),
    )


def make_burst_event(client_ip: str) -> TelemetryEvent:
    event = make_transaction()
    event.event_type = "burst_spike"
    event.is_attack = True
    event.attack_pattern = "burst"
    event.client_ip = client_ip
    return event


def make_malformed_event() -> TelemetryEvent:
    """Bad VALUES only -- the envelope stays schema-valid JSON."""
    event = make_transaction()
    corruption = random.choice(("negative_amount", "junk_currency", "missing_payer"))
    if corruption == "negative_amount":
        event.amount = -abs(event.amount or 100_000.0)
    elif corruption == "junk_currency":
        event.currency = random.choice(JUNK_CURRENCIES)
    else:
        event.payer_id = None
    event.event_type = "malformed_payload"
    event.status = "malformed"
    event.is_attack = True
    event.attack_pattern = "malformed"
    event.raw_payload_valid = False
    return event


class TrafficGenerator:
    """Paced asyncio loop; owned by the FastAPI lifespan."""

    def __init__(
        self, emitter: TelemetryEmitter, events_per_second: float, attack_mode: str
    ) -> None:
        self.emitter = emitter
        self.events_per_second = events_per_second
        self.attack_mode = attack_mode
        self.started_at = time.time()
        self.counters = {"transaction": 0, "burst_spike": 0, "malformed_payload": 0}
        self._task: asyncio.Task | None = None
        # Burst state (loop-clock timestamps).
        self._burst_until = 0.0
        self._next_burst_at = 0.0
        self._burst_multiplier = 1.0
        self._burst_ips: list[str] = []

    # -- lifecycle -----------------------------------------------------

    def start(self) -> None:
        self.started_at = time.time()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # -- runtime config / status ---------------------------------------

    def configure(
        self, events_per_second: float | None = None, attack_mode: str | None = None
    ) -> None:
        if events_per_second is not None:
            self.events_per_second = events_per_second
        if attack_mode is not None:
            self.attack_mode = attack_mode

    def status(self) -> dict:
        return {
            "events_per_second": self.events_per_second,
            "attack_mode": self.attack_mode,
            "uptime_seconds": round(time.time() - self.started_at, 1),
            "events_emitted": {
                "total": sum(self.counters.values()),
                **self.counters,
            },
            "attacks_injected": {
                "burst": self.counters["burst_spike"],
                "malformed": self.counters["malformed_payload"],
            },
        }

    # -- generation loop -------------------------------------------------

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        next_at = loop.time()
        while True:
            now = loop.time()
            in_burst = self._update_burst(now)
            event = self._next_event(in_burst)
            self.counters[event.event_type] += 1
            self.emitter.emit_nowait(event)

            rate = self.events_per_second * (self._burst_multiplier if in_burst else 1.0)
            # Absolute scheduling keeps the average rate honest even with
            # coarse timer resolution; the clamp caps catch-up backlog to 1s.
            next_at = max(next_at + 1.0 / max(rate, 0.01), now - 1.0)
            await asyncio.sleep(max(0.0, next_at - loop.time()))

    def _update_burst(self, now: float) -> bool:
        if self.attack_mode not in ("burst", "mixed"):
            self._burst_until = 0.0
            self._next_burst_at = 0.0  # reschedule if the mode comes back
            return False
        if self._next_burst_at == 0.0:  # just (re)entered a burst-capable mode
            self._next_burst_at = now + random.uniform(*BURST_EVERY_SECONDS)
        if now < self._burst_until:
            return True
        if now >= self._next_burst_at:
            self._burst_until = now + random.uniform(*BURST_DURATION_SECONDS)
            self._burst_multiplier = random.uniform(*BURST_MULTIPLIER)
            self._burst_ips = [random_client_ip() for _ in range(BURST_SOURCE_IPS)]
            self._next_burst_at = now + random.uniform(*BURST_EVERY_SECONDS)
            return True
        return False

    def _next_event(self, in_burst: bool) -> TelemetryEvent:
        if in_burst:
            return make_burst_event(random.choice(self._burst_ips))
        if (
            self.attack_mode in ("malformed", "mixed")
            and random.random() < MALFORMED_PROBABILITY
        ):
            return make_malformed_event()
        return make_transaction()
