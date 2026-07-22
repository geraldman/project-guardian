"""External validation: CASSANDRA vs the CERT Insider Threat Dataset r4.2.

Why this exists
---------------
CASSANDRA's paired-CUSUM drift detector is tuned and measured only on the
synthetic LTI economy (services/cassandra/tests/offline_check.py). This harness
runs the UNMODIFIED detector against an independently generated public dataset
with real ground truth — CERT r4.2, 1000 users over 17 months, 70 of them
malicious, including a removable-media data-exfiltration scenario — to show the
slow-exfil signal transfers to data it was never tuned on.

The production detector is NOT retuned. This is evidence only.

Method
------
CASSANDRA watches per-entity *volume drift*: a sustained rise in a payer's
per-bucket event count (amount corroborates, never accuses alone). CERT has no
money, but the same signal exists as a user's daily count of data-movement
events — file copies to removable media (file.csv / device.csv). Per user we
bucket that count per DAY, use file-content length as a winsorized size proxy
for the amount chart, and drive the shipped PayerDrift.update() exactly as
offline_check's fleet soak does. CUSUM on standardized per-bucket z is
bucket-duration-agnostic, so the shipped Params (warmup 30 buckets, k=0.75,
h=6/10) apply at day-granularity unchanged — this validates the shipped
detector, not a re-tuned one.

A malicious user is a "hit" if the detector alarms on/after their exfil-window
start (answers/insiders.csv); benign false alarms are counted across normal
users as an ARL budget, mirroring offline_check scenario 5.

Run (host Python 3.14, stdlib only):
    python training/validate_cassandra_cert.py --dataset training/datasets/cert-r4.2
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "services" / "cassandra"))

from app.detector import Params, PayerDrift  # noqa: E402

_DAY = 86400
# CERT timestamps: "01/04/2010 07:31:14" (m/d/Y H:M:S).
_CERT_TS = "%m/%d/%Y %H:%M:%S"


def parse_day(ts: str) -> int | None:
    try:
        dt = datetime.strptime(ts.strip(), _CERT_TS)
    except ValueError:
        return None
    return int(dt.timestamp() // _DAY)


def read_insiders(dataset: Path) -> dict[str, int]:
    """user -> first malicious day, from answers/insiders.csv (columns include
    dataset,scenario,details,user,start,end). Only r4.2 rows are kept."""
    path = next((p for p in dataset.rglob("insiders.csv")), None)
    if path is None:
        return {}
    out: dict[str, int] = {}
    with path.open(encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            ds = (row.get("dataset") or "").strip()
            if ds and "4.2" not in ds:
                continue
            user = (row.get("user") or "").strip()
            start = (row.get("start") or "").strip()
            if not user or not start:
                continue
            day = parse_day(start) or parse_day(start + " 00:00:00")
            if day is not None:
                out[user] = day
    return out


def load_activity(dataset: Path) -> dict[str, dict[int, tuple[int, float]]]:
    """user -> {day -> (event_count, size_proxy_sum)} from data-movement logs.

    file.csv rows are per-file copies (columns: id,date,user,pc,filename,content);
    each is one data-movement event, with len(content) as a byte-size proxy.
    device.csv Connect rows count as movement-enabling events too.
    """
    activity: dict[str, dict[int, tuple[int, float]]] = defaultdict(dict)

    def bump(user: str, day: int, size: float) -> None:
        c, s = activity[user].get(day, (0, 0.0))
        activity[user][day] = (c + 1, s + size)

    file_csv = next((p for p in dataset.rglob("file.csv")), None)
    if file_csv is not None:
        with file_csv.open(encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                day = parse_day(row.get("date", ""))
                user = (row.get("user") or "").strip()
                if day is None or not user:
                    continue
                bump(user, day, float(len(row.get("content") or "")))

    device_csv = next((p for p in dataset.rglob("device.csv")), None)
    if device_csv is not None:
        with device_csv.open(encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                act = (row.get("activity") or "").strip().lower()
                if "connect" not in act or "disconnect" in act:
                    continue
                day = parse_day(row.get("date", ""))
                user = (row.get("user") or "").strip()
                if day is None or not user:
                    continue
                bump(user, day, 0.0)
    return activity


def run_user(days: dict[int, tuple[int, float]], p: Params) -> int | None:
    """Drive one user's daily sequence through PayerDrift; return the first
    day index (0-based within the user's active span) an alarm fires, else None.
    Absent days between first and last activity are folded as zero-observation
    buckets, exactly as the pipeline does for quiet payers."""
    if not days:
        return None
    lo, hi = min(days), max(days)
    drift = PayerDrift(p)
    for i, day in enumerate(range(lo, hi + 1)):
        count, size = days.get(day, (0, 0.0))
        amount = min(size, p.amount_event_cap) if count else 0.0
        a = drift.update(count, amount, min(count, 1), day * _DAY, p)
        if a.is_anomalous:
            return day  # absolute day index; caller compares to exfil start
    return None


def evaluate(dataset: Path) -> dict:
    insiders = read_insiders(dataset)
    activity = load_activity(dataset)
    if not activity:
        return {}
    p = Params()

    # One pass: which users CASSANDRA flags for removable-media volume drift.
    flagged: dict[str, int] = {}  # user -> first alarm day
    for user, days in activity.items():
        alarm_day = run_user(days, p)
        if alarm_day is not None:
            flagged[user] = alarm_day

    results: dict[str, object] = {
        "total_users": len(activity),
        "flagged_users": len(flagged),
        "has_labels": bool(insiders),
    }
    if not insiders:
        # No ground-truth answers file present (CERT ships it separately). Report
        # the flagged set unsupervised — still shows the detector yields a small,
        # tractable candidate set on real independent data.
        top = sorted(flagged.items(), key=lambda kv: kv[1])
        results["flagged_sample"] = top[:25]
        return results

    hits = 0
    delays: list[int] = []
    missed: list[str] = []
    for user, start_day in insiders.items():
        alarm_day = flagged.get(user)
        if alarm_day is not None and alarm_day >= start_day - 1:
            hits += 1
            delays.append(alarm_day - start_day)
        else:
            missed.append(user)
    benign_flagged = sum(1 for u in flagged if u not in insiders)
    benign_total = len(activity) - len(insiders)
    results.update({
        "malicious_users": len(insiders),
        "detected": hits,
        "missed": missed,
        "median_delay_days": sorted(delays)[len(delays) // 2] if delays else None,
        "max_delay_days": max(delays) if delays else None,
        "benign_users": benign_total,
        "benign_alarms": benign_flagged,
    })
    return results


def _self_test() -> None:
    """Bucketing + detector wiring sanity without the real dataset: a flat
    benign user stays silent; a user with a sustained volume ramp alarms."""
    p = Params()
    flat = {d: (2, 4000.0) for d in range(60)}
    assert run_user(flat, p) is None, "flat benign user should not alarm"
    ramp = {d: (2, 4000.0) for d in range(40)}
    ramp.update({d: (20, 40000.0) for d in range(40, 60)})  # 10x sustained ramp
    assert run_user(ramp, p) is not None, "sustained 10x volume ramp should alarm"
    print("[self-test] daily bucketing + PayerDrift wiring OK")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", type=Path, help="unpacked CERT r4.2 root")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    _self_test()
    if args.self_test:
        return 0
    if not args.dataset or not args.dataset.exists():
        print("ERROR: --dataset path required (unpacked CERT r4.2 root: the dir "
              "holding device.csv, file.csv, http.csv and answers/)", file=sys.stderr)
        return 1

    r = evaluate(args.dataset)
    if not r:
        print("ERROR: no activity parsed — check the dataset layout", file=sys.stderr)
        return 1
    print("\n## CASSANDRA vs CERT r4.2 — removable-media exfil drift")
    print(f"users with removable-media activity: {r['total_users']}")
    print(f"flagged by CASSANDRA drift: {r['flagged_users']}")
    if not r["has_labels"]:
        print("\nNo ground-truth answers file found (CERT ships answers.tar.bz2 "
              "separately). Reporting the flagged set unsupervised — add answers/"
              "insiders.csv under the dataset root for precision/recall.")
        print("first-flagged users (user, day-index):")
        for user, day in r["flagged_sample"]:
            print(f"  {user}  day {day}")
        return 0
    print(f"malicious users with a start day: {r['malicious_users']}")
    print(f"detected: {r['detected']} / {r['malicious_users']}  "
          f"(median delay {r['median_delay_days']}d, max {r['max_delay_days']}d)")
    if r["missed"]:
        print(f"missed users: {', '.join(r['missed'][:20])}"
              + (" ..." if len(r["missed"]) > 20 else ""))
    fp_rate = r["benign_alarms"] / r["benign_users"] if r["benign_users"] else 0.0
    print(f"benign users: {r['benign_users']}  false-alarm users: {r['benign_alarms']}  "
          f"({fp_rate:.3%})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
