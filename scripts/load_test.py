"""GUARDIAN load-test harness (Week 4).

Drives the mock-lti generator through rate steps and samples the whole
pipeline over HTTP, writing a CSV of raw counters plus a per-step summary
(printed and appended to a markdown fragment for docs/load_test.md).

Stdlib only, host Python 3.10+ — same constraint as training/seed_baseline.py
(host 3.14 cannot build aiokafka wheels; this must run with zero pip installs).
Everything is measured over the published localhost ports; the only numbers
this harness cannot see are per-container RAM/CPU, which the operator samples
with `docker stats --no-stream` at the marked points.

Usage:
  python scripts/load_test.py --profile ceiling                 # 10,58,120,250,500,1000 ev/s
  python scripts/load_test.py --profile sustain --rate 58 --minutes 30
  python scripts/load_test.py --profile sustain --rate 10 --minutes 2   # dry run

Rates are computed from counter deltas, never from sleep timing, so sampling
jitter cannot skew them. Lag proxies are baselined at run start:
  vector lag  = d(telemetry.sent) - d(indexed traffic docs)
  scorer lag  = d(telemetry.sent) - d(events_consumed)
A lag that grows monotonically at a fixed rate step means that stage is
saturated — that step is the ceiling.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SAMPLE_SECONDS = 15
CEILING_STEPS = (10, 58, 120, 250, 500, 1000)
DRAIN_RATE = 10
DRAIN_MAX_MINUTES = 10

GEN = "http://localhost:8000"
ARGUS = "http://localhost:8002"
ALERTING = "http://localhost:8003"
SENTINEL = "http://localhost:8004"
CASSANDRA = "http://localhost:8005"
FUSION = "http://localhost:8006"
OPENSEARCH = "https://localhost:9200"
OS_USER = "admin"
OS_PASSWORD = "Guardian!Lti2026"  # default; override with --os-password

_SSL_CTX = ssl._create_unverified_context()  # self-signed demo cert

FIELDS = [
    "ts", "target_rate", "emitted", "sent", "failed",
    "argus_consumed", "sentinel_consumed", "cassandra_consumed",
    "fusion_consumed", "fusion_folded", "threat_level",
    "alerts_sent", "alerts_suppressed", "delivery_failures",
    "traffic_count", "scores_count", "sample_errors",
]


def http_json(url: str, payload: dict | None = None, auth: str | None = None,
              timeout: float = 6.0):
    req = urllib.request.Request(url)
    if auth is not None:
        token = base64.b64encode(auth.encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    if payload is not None:
        req.data = json.dumps(payload).encode()
        req.add_header("Content-Type", "application/json")
    ctx = _SSL_CTX if url.startswith("https") else None
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as res:
        return json.loads(res.read())


def set_rate(rate: float, attack_mode: str = "off") -> None:
    http_json(f"{GEN}/admin/generator/config",
              payload={"events_per_second": rate, "attack_mode": attack_mode})


def sample(auth: str) -> dict:
    """One flat row of raw counters; unreachable sources leave gaps."""
    row: dict = {"ts": datetime.now(timezone.utc).isoformat(), "sample_errors": 0}

    def grab(fn):
        try:
            return fn()
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
            row["sample_errors"] += 1
            return None

    gen = grab(lambda: http_json(f"{GEN}/admin/generator/status"))
    if gen:
        row["emitted"] = gen["counters"]["events_emitted"]["total"]
        row["sent"] = gen["counters"]["telemetry"]["sent"]
        row["failed"] = gen["counters"]["telemetry"]["failed"]
    for key, url in (("argus", ARGUS), ("sentinel", SENTINEL), ("cassandra", CASSANDRA)):
        stats = grab(lambda u=url: http_json(f"{u}/stats"))
        if stats:
            row[f"{key}_consumed"] = stats.get("events_consumed")
    threat = grab(lambda: http_json(f"{FUSION}/threat"))
    if threat:
        row["fusion_consumed"] = threat["counters"].get("scores_consumed")
        row["fusion_folded"] = threat["counters"].get("scores_folded")
        row["threat_level"] = threat.get("threat_level")
    alerts = grab(lambda: http_json(f"{ALERTING}/stats"))
    if alerts:
        row["alerts_sent"] = alerts.get("sent")
        row["alerts_suppressed"] = alerts.get("suppressed")
        row["delivery_failures"] = alerts.get("delivery_failures")
    for key, index in (("traffic_count", "guardian-traffic-*"),
                       ("scores_count", "guardian-scores-*")):
        count = grab(lambda i=index: http_json(f"{OPENSEARCH}/{i}/_count", auth=auth))
        if count:
            row[key] = count["count"]
    return row


def delta(rows: list[dict], key: str) -> float | None:
    vals = [r[key] for r in rows if r.get(key) is not None]
    return (vals[-1] - vals[0]) if len(vals) >= 2 else None


def span_seconds(rows: list[dict]) -> float:
    t0 = datetime.fromisoformat(rows[0]["ts"])
    t1 = datetime.fromisoformat(rows[-1]["ts"])
    return max((t1 - t0).total_seconds(), 1.0)


def lag(rows: list[dict], consumed_key: str) -> float | None:
    d_sent = delta(rows, "sent")
    d_consumed = delta(rows, consumed_key)
    if d_sent is None or d_consumed is None:
        return None
    return d_sent - d_consumed


def fmt(v: float | None, digits: int = 1) -> str:
    return "-" if v is None else f"{v:.{digits}f}"


def summarize(rate: float, rows: list[dict]) -> dict:
    secs = span_seconds(rows)
    return {
        "rate": rate,
        "emit_rate": (delta(rows, "emitted") or 0) / secs,
        "failed": delta(rows, "failed"),
        "index_rate": (delta(rows, "traffic_count") or 0) / secs,
        "vector_lag": lag(rows, "traffic_count"),
        "argus_lag": lag(rows, "argus_consumed"),
        "sentinel_lag": lag(rows, "sentinel_consumed"),
        "cassandra_lag": lag(rows, "cassandra_consumed"),
        "threat": rows[-1].get("threat_level", "-"),
        "seconds": secs,
    }


SUMMARY_HEADER = ("| target ev/s | achieved emit/s | lost | indexed/s | vector lag "
                  "| argus lag | sentinel lag | cassandra lag | threat at end |")
SUMMARY_DIVIDER = "|---|---|---|---|---|---|---|---|---|"


def summary_row(s: dict) -> str:
    return (f"| {s['rate']:g} | {fmt(s['emit_rate'])} | {fmt(s['failed'], 0)} "
            f"| {fmt(s['index_rate'])} | {fmt(s['vector_lag'], 0)} "
            f"| {fmt(s['argus_lag'], 0)} | {fmt(s['sentinel_lag'], 0)} "
            f"| {fmt(s['cassandra_lag'], 0)} | {s['threat']} |")


class Guards:
    """Abort escalation when the pipeline is demonstrably saturated."""

    def __init__(self) -> None:
        self.failed_streak = 0
        self.lag_growth_streak = 0
        self.prev_failed: float | None = None
        self.prev_lag: float | None = None

    def check(self, base: dict, row: dict) -> str | None:
        failed = row.get("failed")
        if failed is not None:
            if self.prev_failed is not None and failed > self.prev_failed:
                self.failed_streak += 1
            else:
                self.failed_streak = 0
            self.prev_failed = failed
            if self.failed_streak >= 2:
                return "telemetry.failed climbing (emitter dropping events)"
        if row.get("sent") is not None and row.get("traffic_count") is not None \
                and base.get("sent") is not None and base.get("traffic_count") is not None:
            cur_lag = (row["sent"] - base["sent"]) - (row["traffic_count"] - base["traffic_count"])
            if self.prev_lag is not None and cur_lag > self.prev_lag + 5:
                self.lag_growth_streak += 1
            else:
                self.lag_growth_streak = 0
            self.prev_lag = cur_lag
            if self.lag_growth_streak >= 12:  # ~3 min of monotonic growth
                return f"vector/OpenSearch lag growing monotonically (now {cur_lag:.0f})"
        if row["sample_errors"] >= 4:
            return "multiple pipeline endpoints unreachable"
        return None


def run_step(rate: float, minutes: float, writer, csvfile, auth: str,
             base: dict, guards: Guards | None) -> tuple[list[dict], str | None]:
    set_rate(rate)
    end = time.monotonic() + minutes * 60
    half = time.monotonic() + minutes * 30
    half_announced = False
    rows: list[dict] = []
    end_clock = datetime.now().strftime("%H:%M:%S")
    print(f"\n=== STEP {rate:g} ev/s for {minutes:g} min "
          f"(until ~{datetime.now().astimezone().strftime('%H:%M')}+{minutes:g}m, started {end_clock}) ===",
          flush=True)
    while time.monotonic() < end:
        row = sample(auth)
        row["target_rate"] = rate
        rows.append(row)
        writer.writerow(row)
        csvfile.flush()
        if len(rows) >= 2:
            secs = span_seconds(rows[-2:])
            emit = (delta(rows[-2:], "emitted") or 0) / secs
            idx = (delta(rows[-2:], "traffic_count") or 0) / secs
            print(f"  {row['ts'][11:19]}  emit {emit:6.1f}/s  indexed {idx:6.1f}/s  "
                  f"failed {row.get('failed', '-')}  threat {row.get('threat_level', '-')}  "
                  f"errors {row['sample_errors']}", flush=True)
        if not half_announced and time.monotonic() >= half:
            print(f"  >>> USER SAMPLE POINT ({rate:g} ev/s plateau): "
                  f"run `docker stats --no-stream` now <<<", flush=True)
            half_announced = True
        if guards is not None:
            reason = guards.check(base, row)
            if reason is not None:
                print(f"  !! ABORT GUARD at {rate:g} ev/s: {reason}", flush=True)
                return rows, reason
        time.sleep(SAMPLE_SECONDS)
    return rows, None


def drain(writer, csvfile, auth: str, base: dict) -> None:
    print(f"\n=== DRAIN: back to {DRAIN_RATE} ev/s, waiting for lag to flatten ===", flush=True)
    set_rate(DRAIN_RATE)
    end = time.monotonic() + DRAIN_MAX_MINUTES * 60
    flat = 0
    prev_lag: float | None = None
    while time.monotonic() < end:
        row = sample(auth)
        row["target_rate"] = DRAIN_RATE
        writer.writerow(row)
        csvfile.flush()
        cur_lag = None
        if row.get("sent") is not None and row.get("traffic_count") is not None:
            cur_lag = (row["sent"] - base["sent"]) - (row["traffic_count"] - base["traffic_count"])
            print(f"  {row['ts'][11:19]}  vector lag {cur_lag:.0f}", flush=True)
            if prev_lag is not None and abs(cur_lag - prev_lag) < 10:
                flat += 1
            else:
                flat = 0
            prev_lag = cur_lag
            if flat >= 4 or cur_lag <= 100:
                print("  drain complete: lag flat/near-zero", flush=True)
                return
        time.sleep(SAMPLE_SECONDS)
    print(f"  drain window ({DRAIN_MAX_MINUTES} min) elapsed; lag still {prev_lag}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", choices=("ceiling", "sustain"), required=True)
    ap.add_argument("--rate", type=float, default=58, help="sustain profile rate (ev/s)")
    ap.add_argument("--minutes", type=float, default=30, help="sustain profile duration")
    ap.add_argument("--step-minutes", type=float, default=8, help="ceiling step duration")
    ap.add_argument("--os-password", default=OS_PASSWORD)
    args = ap.parse_args()
    auth = f"{OS_USER}:{args.os_password}"

    out_dir = Path(__file__).parent / "out"
    out_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    csv_path = out_dir / f"loadtest-{args.profile}-{stamp}.csv"
    md_path = out_dir / f"loadtest-{args.profile}-{stamp}-summary.md"

    base = sample(auth)
    if base.get("sent") is None:
        print("FATAL: mock-lti generator unreachable — is the stack up?", file=sys.stderr)
        return 1
    if base["sample_errors"] > 0:
        print(f"WARNING: {base['sample_errors']} source(s) unreachable at baseline; "
              "their columns will be gaps", file=sys.stderr)

    steps = (CEILING_STEPS if args.profile == "ceiling" else (args.rate,))
    minutes = (args.step_minutes if args.profile == "ceiling" else args.minutes)
    summaries: list[dict] = []
    abort_reason: str | None = None

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        base["target_rate"] = "baseline"
        writer.writerow(base)
        guards = Guards() if args.profile == "ceiling" else None
        try:
            for rate in steps:
                rows, abort_reason = run_step(rate, minutes, writer, csvfile, auth, base, guards)
                if len(rows) >= 2:
                    s = summarize(rate, rows[1:] if len(rows) > 2 else rows)
                    summaries.append(s)
                    print(f"  step summary: {summary_row(s)}", flush=True)
                if abort_reason is not None:
                    break
        finally:
            try:
                drain(writer, csvfile, auth, base)
            except (urllib.error.URLError, OSError) as exc:
                print(f"  drain skipped: {exc}", flush=True)

    lines = [f"# Load test `{args.profile}` — {stamp}", ""]
    if abort_reason is not None:
        lines += [f"**Escalation stopped at guard:** {abort_reason}", ""]
    lines += [SUMMARY_HEADER, SUMMARY_DIVIDER]
    lines += [summary_row(s) for s in summaries]
    lines += ["", f"Raw samples: `{csv_path.name}` (every {SAMPLE_SECONDS}s). "
              "Lags are events behind over the whole step (baselined at step start); "
              "'lost' is the telemetry.failed delta."]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nSummary written to {md_path}")
    print("\n".join(lines[2:]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
