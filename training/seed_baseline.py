"""Fast-forward ARGUS's baseline warmup on a fresh stack.

Replays backdated *benign* traffic through capture-agent's /ingest, i.e.
through the real pipeline (raw topic -> Vector -> normalized topic -> ARGUS),
so ARGUS builds historical 1-minute buckets exactly as if it had been running
for the last N minutes. After ~WARMUP_BUCKETS minutes' worth (default 15),
detection is live immediately instead of after 15 real minutes.

Benign only, on purpose: seeding attack traffic would teach the baseline that
attacks are normal. Event shapes mirror services/mock-lti's generator (same
entity pools and distributions) but are intentionally decoupled from its code
— this script must run on the host with stdlib Python only (no aiokafka:
host Python 3.14 can't build its wheels, and none is needed for HTTP).

Usage (stack up, from the repo root):
    python training/seed_baseline.py [--minutes 20] [--events-per-minute 600]
                                     [--url http://localhost:8001/ingest]
"""
import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

MERCHANTS = [f"merchant-{i:04d}" for i in range(1, 201)]
BANKS = [f"bank-{i:03d}" for i in range(1, 21)]
WALLET_USERS = [f"wallet-user-{i:04d}" for i in range(1, 501)]
CHANNELS = ("ecommerce", "wallet", "bank")
BASELINE_DECLINE_RATE = 0.03
BATCH_SIZE = 200
_DECLINE_REASONS = ("insufficient_funds", "risk_hold", "limit_exceeded", "issuer_declined")


def benign_log_line(ip, payer, payee, channel, event_id, status, ts, latency_ms):
    """Render a benign gateway log line.

    NOTE: deliberately duplicates the benign families in
    services/mock-lti/app/generator.py (benign_log_line). This script must run
    on the host with stdlib Python only, so it can't import the container app;
    keep the two in sync when either changes.
    """
    lat = f"{latency_ms:.0f}ms" if latency_ms else "0ms"
    nbytes = random.randint(180, 900)
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")

    def line(method, path, code, msg):
        return f'{ip} - {payer or "-"} [{stamp}] "{method} {path} HTTP/1.1" {code} {nbytes} {lat} "{msg}"'

    if status == "declined":
        return line("POST", "/api/v1/transactions/route", 402,
                    f"payment declined: {random.choice(_DECLINE_REASONS)}")
    family = random.choice(("route", "route", "balance", "status", "settlement"))
    if family == "route":
        return line("POST", "/api/v1/transactions/route", 200,
                    f"routed {channel} payment {payer}->{payee}")
    if family == "balance":
        return line("GET", f"/api/v1/accounts/{payer}/balance", 200, "balance inquiry ok")
    if family == "status":
        return line("GET", f"/api/v1/transactions/{event_id[:8]}/status", 200, "status poll approved")
    return line("POST", f"/api/v1/settlements/{channel}", 201, "settlement batch accepted")


def benign_event(ts: datetime) -> dict:
    channel = random.choice(CHANNELS)
    if channel == "ecommerce":
        payer, payee = random.choice(WALLET_USERS), random.choice(MERCHANTS)
    elif channel == "wallet":
        payer, payee = random.choice(WALLET_USERS), random.choice(WALLET_USERS + MERCHANTS)
    else:
        payer, payee = random.choice(MERCHANTS), random.choice(BANKS)
    amount = round(min(max(random.lognormvariate(11.5, 1.0), 1_000.0), 50_000_000.0), -2)
    event_id = str(uuid.uuid4())
    status = "declined" if random.random() < BASELINE_DECLINE_RATE else "approved"
    latency_ms = round(random.lognormvariate(2.5, 0.5), 1)
    client_ip = f"10.{random.randint(0, 3)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    return {
        "event_id": event_id,
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "source": "mock-lti",
        "event_type": "transaction",
        "payer_id": payer,
        "payee_id": payee,
        "channel": channel,
        "amount": amount,
        "currency": "IDR",
        "status": status,
        "latency_ms": latency_ms,
        "is_attack": False,
        "attack_pattern": None,
        "client_ip": client_ip,
        "raw_payload_valid": True,
        "log_message": benign_log_line(client_ip, payer, payee, channel, event_id,
                                       status, ts, latency_ms),
    }


def post_batch(url: str, events: list[dict]) -> None:
    req = urllib.request.Request(
        url,
        data=json.dumps(events).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=10):
                return
        except urllib.error.HTTPError as exc:
            if exc.code == 503 and attempt < 4:  # capture-agent's producer still connecting
                time.sleep(2.0)
                continue
            raise
    raise RuntimeError("capture-agent kept answering 503")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--minutes", type=int, default=20,
                        help="how many backdated minutes to replay (default 20)")
    parser.add_argument("--events-per-minute", type=int, default=600,
                        help="benign events per minute (default 600 = the 10 ev/s dev rate)")
    parser.add_argument("--url", default="http://localhost:8001/ingest",
                        help="capture-agent ingest endpoint")
    args = parser.parse_args()

    start = datetime.now(timezone.utc) - timedelta(minutes=args.minutes)
    total = 0
    for minute in range(args.minutes):
        base = start + timedelta(minutes=minute)
        offsets = sorted(random.uniform(0, 59.999) for _ in range(args.events_per_minute))
        events = [benign_event(base + timedelta(seconds=o)) for o in offsets]
        for i in range(0, len(events), BATCH_SIZE):
            post_batch(args.url, events[i:i + BATCH_SIZE])
        total += len(events)
        print(f"\rseeded minute {minute + 1}/{args.minutes} ({total} events)", end="", flush=True)
    print(f"\ndone: {total} benign events over {args.minutes} backdated minutes.")
    print("ARGUS finalizes a minute once a newer one arrives; with the live "
          "generator running, warmup completes within ~2 minutes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
