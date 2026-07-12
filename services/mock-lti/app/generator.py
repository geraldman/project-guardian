"""Background synthetic-traffic loop with attack injection.

Baseline traffic mimics LTI-style B2B micro-transaction routing. Every event
also carries a rendered API-gateway log line (``log_message``) in a consistent,
parseable-but-realistic format so a downstream template miner (Drain3) has a
stable set of families to learn — benign traffic varies the *values*, not the
line structure, while attack traffic smuggles its signature into the log
content.

Attack modes (runtime-switchable via /admin/generator/config):

  burst      -- every 60-120s the event rate spikes 10-20x for 5-10s, sourced
                from a handful of attacker IPs (event_type=burst_spike,
                is_attack=True, attack_pattern=burst). Log lines stay benign;
                the attack is the *rate*.
  malformed  -- a fraction of events carry intentionally bad *values* (negative
                amount, junk currency, or missing payer_id) with
                raw_payload_valid=False. The JSON envelope itself always stays
                schema-valid -- pipeline invariant, see
                docs/architecture.md#event-schema.
  slow_exfil -- one designated payer receives a small, persistent stream of
                extra transactions (default ~3/min) with modestly elevated
                amounts. Each is a normal, schema-valid transaction with a
                benign log line (is_attack=True, attack_pattern=slow_exfil for
                ground truth). Tuned to stay under ARGUS's per-minute 3σ / min
                alert-volume floor (invisible locally) yet obvious in cumulative
                per-payer volume over many minutes -- CASSANDRA's CUSUM niche.
  log_attack -- malicious log *content* at normal traffic rates from a modest
                pool of attacker IPs: SQL-injection strings, path traversal,
                credential-stuffing auth failures, scanner probes. Events stay
                schema-valid with a normal status distribution (is_attack=True,
                attack_pattern=log_attack), so neither ARGUS's rate detectors
                nor the error-rate monitor move -- detectable only from the log
                line. SENTINEL's niche.
  mixed      -- all four of the above.
  off        -- clean baseline only.
"""
import asyncio
import random
import time
import uuid
from datetime import datetime, timezone

from .schemas import TelemetryEvent
from .telemetry import TelemetryEmitter

ATTACK_MODES = ("off", "burst", "malformed", "mixed", "slow_exfil", "log_attack")

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

# -- slow_exfil defaults (env-tunable via app.config) ----------------------
# A wallet-user is a payer in the ecommerce/wallet channels, so the default
# id already accrues ARGUS payer-baseline history in ordinary traffic.
DEFAULT_EXFIL_PAYER_ID = "wallet-user-0001"
DEFAULT_EXFIL_EVENTS_PER_MINUTE = 2.0   # << ARGUS min_alert_events (10): never pages
DEFAULT_EXFIL_AMOUNT_MULTIPLIER = 1.8   # covert channel: amount is not an ARGUS scoring feature

# -- log_attack defaults ---------------------------------------------------
DEFAULT_LOG_ATTACK_PROBABILITY = 0.08   # share of non-burst events carrying attack log content
# A distinct, external-looking pool. 20 IPs keeps per-IP rate (~2-3/min at the
# default probability) well under ARGUS's cohort alert floor, so a credential-
# stuffing / scanning campaign hides from rate detection and shows only in logs.
LOG_ATTACK_SOURCE_IPS = [f"45.148.10.{i}" for i in range(11, 31)]


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


# -- log-line rendering ----------------------------------------------------
# Combined access/app format, one line, ~90-160 chars:
#   <ip> - <payer> [<ts>] "<METHOD> <path> HTTP/1.1" <code> <bytes> <lat>ms "<msg>"
# Benign traffic draws from a handful of endpoint families (structure fixed per
# family, values vary) so a template miner converges on a small template set;
# attack traffic keeps the same envelope but carries the signature in the path
# or message. If you change these, tell the SENTINEL owner: its rule pre-filter
# and training data are built against these exact families.

_DECLINE_REASONS = ("insufficient_funds", "risk_hold", "limit_exceeded", "issuer_declined")
_SQLI_PAYLOADS = (
    "1' OR '1'='1",
    "1;DROP TABLE transactions;--",
    "' UNION SELECT card_number,cvv FROM cards--",
    "admin'--",
)
_TRAVERSAL_PATHS = (
    "/api/v1/reports/../../../../etc/passwd",
    "/api/v1/exports/..%2f..%2f..%2f..%2fetc%2fshadow",
    "/static/../../config/database.yml",
)
_SCANNER_PATHS = (
    "/.env",
    "/.git/config",
    "/wp-login.php",
    "/admin.php",
    "/phpmyadmin/index.php",
    "/actuator/env",
)


def _log_ts(ts: datetime) -> str:
    return ts.strftime("%d/%b/%Y:%H:%M:%S +0000")


def _log_line(ip: str, payer: str | None, ts: datetime, method: str, path: str,
              code: int, latency_ms: float | None, msg: str) -> str:
    lat = f"{latency_ms:.0f}ms" if latency_ms else "0ms"
    nbytes = random.randint(180, 900)
    return (f'{ip} - {payer or "-"} [{_log_ts(ts)}] "{method} {path} HTTP/1.1" '
            f'{code} {nbytes} {lat} "{msg}"')


def benign_log_line(ev: TelemetryEvent) -> str:
    """Realistic gateway line for a well-formed transaction event."""
    ip, payer, ts, lat = ev.client_ip or "-", ev.payer_id, ev.timestamp, ev.latency_ms
    if ev.status == "declined":
        reason = random.choice(_DECLINE_REASONS)
        return _log_line(ip, payer, ts, "POST", "/api/v1/transactions/route", 402, lat,
                         f"payment declined: {reason}")
    # Approved: rotate through a small set of benign endpoint families.
    family = random.choice(("route", "route", "balance", "status", "settlement"))
    if family == "route":
        return _log_line(ip, payer, ts, "POST", "/api/v1/transactions/route", 200, lat,
                         f"routed {ev.channel} payment {payer}->{ev.payee_id}")
    if family == "balance":
        return _log_line(ip, payer, ts, "GET", f"/api/v1/accounts/{payer}/balance", 200, lat,
                         "balance inquiry ok")
    if family == "status":
        return _log_line(ip, payer, ts, "GET", f"/api/v1/transactions/{ev.event_id[:8]}/status", 200,
                         lat, "status poll approved")
    return _log_line(ip, payer, ts, "POST", f"/api/v1/settlements/{ev.channel}", 201, lat,
                     "settlement batch accepted")


def malformed_log_line(ev: TelemetryEvent) -> str:
    """A bad-request line mirroring the malformed-value envelope."""
    return _log_line(ev.client_ip or "-", ev.payer_id, ev.timestamp, "POST",
                     "/api/v1/transactions/route", 400, ev.latency_ms,
                     "rejected: schema validation failed")


def attack_log_line(ev: TelemetryEvent) -> str:
    """Malicious content in the request path/message (log_attack family)."""
    ip, payer, ts, lat = ev.client_ip or "-", ev.payer_id, ev.timestamp, ev.latency_ms
    technique = random.choice(("sqli", "path_traversal", "cred_stuffing", "scanner"))
    if technique == "sqli":
        payload = random.choice(_SQLI_PAYLOADS)
        return _log_line(ip, payer, ts, "GET", f"/api/v1/accounts?id={payload}", 200, lat,
                         "account lookup executed")
    if technique == "path_traversal":
        return _log_line(ip, payer, ts, "GET", random.choice(_TRAVERSAL_PATHS), 404, lat,
                         "route not found")
    if technique == "cred_stuffing":
        attempt = random.randint(2, 40)
        return _log_line(ip, payer, ts, "POST", "/api/v1/auth/login", 401, lat,
                         f"authentication failed for {payer} (attempt {attempt})")
    return _log_line(ip, payer, ts, "GET", random.choice(_SCANNER_PATHS), 404, lat,
                     "unmatched route probe")


# -- event factories -------------------------------------------------------


def make_transaction() -> TelemetryEvent:
    channel = random.choice(CHANNELS)
    payer_id, payee_id = _parties(channel)
    event = TelemetryEvent(
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
    event.log_message = benign_log_line(event)
    return event


def make_burst_event(client_ip: str) -> TelemetryEvent:
    event = make_transaction()
    event.event_type = "burst_spike"
    event.is_attack = True
    event.attack_pattern = "burst"
    event.client_ip = client_ip
    event.log_message = benign_log_line(event)  # benign content; the attack is the rate
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
    event.log_message = malformed_log_line(event)
    return event


def make_exfil_event(payer_id: str, amount_multiplier: float) -> TelemetryEvent:
    """Slow-exfil: a normal-looking transaction from the designated payer with a
    modestly elevated amount. Schema-valid, benign log line, ground-truth
    labelled (attack_pattern=slow_exfil)."""
    channel = random.choice(("ecommerce", "wallet"))  # channels where a wallet-user is the payer
    payee_id = random.choice(MERCHANTS) if channel == "ecommerce" else random.choice(WALLET_USERS)
    base = _amount_idr()
    event = TelemetryEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        event_type="transaction",
        payer_id=payer_id,
        payee_id=payee_id,
        channel=channel,
        amount=round(min(base * amount_multiplier, 50_000_000.0), -2),
        currency="IDR",
        status="declined" if random.random() < BASELINE_DECLINE_RATE else "approved",
        latency_ms=random_latency_ms(),
        client_ip=random_client_ip(),
        is_attack=True,
        attack_pattern="slow_exfil",
    )
    event.log_message = benign_log_line(event)
    return event


def make_log_attack_event() -> TelemetryEvent:
    """Schema-valid transaction from an attacker IP with malicious log content;
    normal status distribution so ARGUS rate/error detectors stay quiet."""
    event = make_transaction()
    event.client_ip = random.choice(LOG_ATTACK_SOURCE_IPS)
    event.is_attack = True
    event.attack_pattern = "log_attack"
    event.log_message = attack_log_line(event)
    return event


class TrafficGenerator:
    """Paced asyncio loop; owned by the FastAPI lifespan."""

    def __init__(
        self,
        emitter: TelemetryEmitter,
        events_per_second: float,
        attack_mode: str,
        exfil_payer_id: str = DEFAULT_EXFIL_PAYER_ID,
        exfil_events_per_minute: float = DEFAULT_EXFIL_EVENTS_PER_MINUTE,
        exfil_amount_multiplier: float = DEFAULT_EXFIL_AMOUNT_MULTIPLIER,
        log_attack_probability: float = DEFAULT_LOG_ATTACK_PROBABILITY,
    ) -> None:
        self.emitter = emitter
        self.events_per_second = events_per_second
        self.attack_mode = attack_mode
        self.exfil_payer_id = exfil_payer_id
        self.exfil_events_per_minute = exfil_events_per_minute
        self.exfil_amount_multiplier = exfil_amount_multiplier
        self.log_attack_probability = log_attack_probability
        self.started_at = time.time()
        self.counters = {"transaction": 0, "burst_spike": 0, "malformed_payload": 0}
        self.attacks = {"burst": 0, "malformed": 0, "slow_exfil": 0, "log_attack": 0}
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
            "attacks_injected": dict(self.attacks),
        }

    # -- generation loop -------------------------------------------------

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        next_at = loop.time()
        while True:
            now = loop.time()
            in_burst = self._update_burst(now)
            event = self._next_event(in_burst)
            self._emit(event)
            self._maybe_emit_exfil()

            rate = self.events_per_second * (self._burst_multiplier if in_burst else 1.0)
            # Absolute scheduling keeps the average rate honest even with
            # coarse timer resolution; the clamp caps catch-up backlog to 1s.
            next_at = max(next_at + 1.0 / max(rate, 0.01), now - 1.0)
            await asyncio.sleep(max(0.0, next_at - loop.time()))

    def _emit(self, event: TelemetryEvent) -> None:
        self.counters[event.event_type] += 1
        if event.is_attack and event.attack_pattern in self.attacks:
            self.attacks[event.attack_pattern] += 1
        self.emitter.emit_nowait(event)

    def _maybe_emit_exfil(self) -> None:
        """Slow-exfil rides *on top of* baseline traffic as a steady trickle on
        one payer — kept to ~exfil_events_per_minute regardless of the base rate
        so it never shows up as a global rate change."""
        if self.attack_mode not in ("slow_exfil", "mixed"):
            return
        prob = self.exfil_events_per_minute / max(self.events_per_second * 60.0, 1.0)
        if random.random() < prob:
            self._emit(make_exfil_event(self.exfil_payer_id, self.exfil_amount_multiplier))

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
        if (
            self.attack_mode in ("log_attack", "mixed")
            and random.random() < self.log_attack_probability
        ):
            return make_log_attack_event()
        return make_transaction()
