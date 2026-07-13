"""Fast-forward CASSANDRA's per-payer baselines on a fresh stack.

Replays backdated *benign* traffic through capture-agent's /ingest — the real
pipeline (raw topic -> Vector -> normalized topic -> CASSANDRA) — so every
payer that appears accumulates the warmup_buckets (default 30) minutes of
observed history CASSANDRA requires before it may alarm, with per-payer
mean/sigma baselines calibrated from that same history. ARGUS warms off the
identical replay as a side effect (its 15-bucket warmup is a subset of this
one), so on a fresh stack this script alone readies both detectors.

The event shapes are seed_baseline.py's — imported, not duplicated, so the
two seeders cannot drift apart. Like it, this is benign-only on purpose:
seeding attack traffic would teach the baselines that attacks are normal.

Usage (stack up, from the repo root):
    python training/seed_history.py [--minutes 40] [--events-per-minute 600]
                                    [--url http://localhost:8001/ingest]

Then confirm readiness with:  curl http://localhost:8005/health
(`payers_warm` > 0 and `warming_up: false` once buckets finalize — with the
live generator running that takes ~2 minutes after the replay lands.)
"""
import argparse
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from seed_baseline import BATCH_SIZE, benign_event, post_batch  # noqa: E402

# CASSANDRA's warmup_buckets default is 30; seed a margin past it so the
# earliest (least-calibrated) minutes are not the whole baseline.
DEFAULT_MINUTES = 40


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--minutes", type=int, default=DEFAULT_MINUTES,
                        help=f"backdated minutes to replay (default {DEFAULT_MINUTES}; "
                             "CASSANDRA needs >= its warmup_buckets, default 30)")
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
    print("CASSANDRA finalizes a minute once every partition has seen a newer "
          "one; with the live generator running, payers reach warm (30 buckets "
          "observed) within ~2 minutes. Check :8005/health -> payers_warm.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
