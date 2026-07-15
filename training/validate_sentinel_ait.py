"""External validation: SENTINEL vs the AIT Log Data Set v1.1.

Why this exists
---------------
SENTINEL's shipped model is trained on synthetic LTI gateway logs, and its
training labels come from the very rule engine (app.rules.window_rule_level)
that also gates inference — so its reported holdout accuracy is measured
against self-consistent labels. This harness breaks that circularity: it feeds
an *independently generated* public dataset (AIT-LDS v1.1, four mail-server
testbeds with real multi-stage attacks and per-line ground truth) through the
UNMODIFIED SENTINEL detection code and measures how well the detector
generalizes to attacks it has never seen.

The production model is NOT retrained. This is evidence only.

Method
------
AIT ships Apache *combined* access logs plus a parallel labels/ tree; each
label line annotates the log line at the same position (non-empty => attack).
SENTINEL expects the LTI gateway envelope
(services/sentinel/app/logparse.py:_LOG_RE), so each Apache line is reshaped
into that envelope — the request PATH (which carries the traversal / scanner /
SQLi signatures SENTINEL's rules key on) is preserved verbatim. Events are fed
through the real Pipeline(Settings(), SentinelModel.load(...)); SENTINEL scores
(client_ip, 1-minute) windows, so per-line ground truth is aggregated to the
window: a window is attack-GT if it contains >=1 attack line, and predicted
attack if the pipeline emits a log_classification alert.

Run (needs numpy/xgboost/drain3 — use the 3.13 venv, see training/README.md):
    .venv-val/Scripts/python.exe training/validate_sentinel_ait.py \
        --dataset training/datasets/AIT-LDS-v1_1
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "services" / "sentinel"))

from app.config import Settings  # noqa: E402
from app.model import SentinelModel  # noqa: E402
from app.pipeline import Pipeline  # noqa: E402

# Apache combined:  %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
_APACHE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<req>.*?)" (?P<code>\d{3}) (?P<bytes>\S+)'
    r'(?: "(?P<ref>.*?)" "(?P<ua>.*?)")?\s*$'
)
_REQ_RE = re.compile(r'^(?P<method>[A-Z]+) (?P<path>.*) (?P<proto>HTTP/\d\.\d)$')
_APACHE_TS = "%d/%b/%Y:%H:%M:%S %z"


def parse_apache(line: str) -> dict | None:
    """Lift the fields we need from one Apache combined access line."""
    m = _APACHE_RE.match(line.rstrip("\n"))
    if m is None:
        return None
    req = _REQ_RE.match(m["req"] or "")
    if req is None:
        return None  # malformed request line (SExtHTTP junk etc.) — skip
    try:
        ts = datetime.strptime(m["ts"], _APACHE_TS)
    except ValueError:
        return None
    nbytes = m["bytes"]
    return {
        "ip": m["ip"],
        "ts": ts.astimezone(timezone.utc),
        "method": req["method"],
        "path": req["path"],
        "code": int(m["code"]),
        "bytes": int(nbytes) if nbytes.isdigit() else 0,
        "ua": (m["ua"] or "-")[:180],
    }


def to_envelope(rec: dict) -> dict:
    """Reshape an Apache record into SENTINEL's normalized event envelope.

    The gateway line SENTINEL's parser expects is
        <ip> - <payer> [<ts>] "<METHOD> <path> HTTP/1.1" <code> <bytes> <lat>ms "<msg>"
    We set payer '-' (AIT logs carry no LTI payer) and latency 0ms (absent in
    Apache logs — SENTINEL's rules/features never use latency). The message is
    the user-agent, trimmed; the attack-carrying PATH is preserved verbatim.
    """
    iso = rec["ts"].isoformat().replace("+00:00", "Z")
    msg = rec["ua"].replace('"', "'")
    gateway = (
        f'{rec["ip"]} - - [{rec["ts"].strftime("%d/%b/%Y:%H:%M:%S %z")}] '
        f'"{rec["method"]} {rec["path"]} HTTP/1.1" {rec["code"]} {rec["bytes"]} 0ms "{msg}"'
    )
    return {
        "@timestamp": iso,
        "log": {"message": gateway},
        "network": {"client_ip": rec["ip"]},
    }


def label_is_attack(label_line: str) -> bool:
    """A parallel label line marks its log line as attack when it names any
    label other than the normal/empty sentinels. v1.1 puts one or two
    comma-separated tags per line; benign lines are empty or '0'."""
    s = label_line.strip()
    if not s:
        return False
    tags = {t.strip().lower() for t in s.split(",") if t.strip()}
    return bool(tags - {"0", "normal", "-", "none"})


def find_pairs(root: Path) -> list[tuple[Path, Path]]:
    """Locate (apache access log, matching label file) pairs.

    AIT mirrors the log tree under a labels/ root: a log at
    <root>/<testbed>/gather/<host>/logs/apache2/<name> has its labels at
    <root>/<testbed>/labels/gather/<host>/logs/apache2/<name>. We glob for
    access logs and derive the label path by inserting 'labels/' after the
    testbed dir; if that misses we search by basename under any labels/ tree.
    """
    pairs: list[tuple[Path, Path]] = []
    access_logs = [
        p for p in root.rglob("*access*.log")
        if "labels" not in p.parts and "apache" in str(p).lower()
    ]
    label_files = {p.name: p for p in root.rglob("*access*.log") if "labels" in p.parts}
    for log_path in access_logs:
        rel = log_path.relative_to(root)
        parts = list(rel.parts)
        cand = root.joinpath(parts[0], "labels", *parts[1:])
        if cand.exists():
            pairs.append((log_path, cand))
        elif log_path.name in label_files:
            pairs.append((log_path, label_files[log_path.name]))
    return pairs


def evaluate(pairs: list[tuple[Path, Path]], settings: Settings, model: SentinelModel) -> dict:
    """Feed every (log, label) pair through a fresh Pipeline per testbed-host
    and tally window-level detection against aggregated ground truth."""
    counts = defaultdict(int)  # tp/fp/fn/tn windows, and line-level tallies
    for log_path, label_path in pairs:
        pipe = Pipeline(settings, model)
        pipe.register_partitions([0])
        win_gt: dict[tuple[str, int], bool] = {}       # (ip, minute) -> any attack line
        win_pred: dict[tuple[str, int], bool] = {}     # (ip, minute) -> alerted
        wsec = settings.window_seconds

        with log_path.open(encoding="utf-8", errors="replace") as lf, \
                label_path.open(encoding="utf-8", errors="replace") as gf:
            for raw, lab in zip(lf, gf):
                rec = parse_apache(raw)
                if rec is None:
                    continue
                attack = label_is_attack(lab)
                minute = int(rec["ts"].timestamp() // wsec) * wsec
                key = (rec["ip"], minute)
                win_gt[key] = win_gt.get(key, False) or attack
                if attack:
                    counts["attack_lines"] += 1
                # Feed the event; finalize any minutes the watermark releases.
                for ready in pipe.add_event(to_envelope(rec), 0):
                    for a in pipe.finalize(ready)[1]:
                        win_pred[(a["alert"]["entity_id"], ready)] = True

        # Finalize whatever remains at stream end (single deterministic pass).
        for minute in sorted(pipe._buckets.keys()):
            for a in pipe.finalize(minute)[1]:
                win_pred[(a["alert"]["entity_id"], minute)] = True

        for key, is_attack in win_gt.items():
            alerted = win_pred.get(key, False)
            if is_attack and alerted:
                counts["tp"] += 1
            elif is_attack and not alerted:
                counts["fn"] += 1
            elif not is_attack and alerted:
                counts["fp"] += 1
            else:
                counts["tn"] += 1
    return counts


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def _self_test() -> None:
    """Adapter sanity — reshaped attack lines must trip the expected family and
    a benign FinTech-shaped line must not (plan verification step 1)."""
    from app.logparse import parse_log_line
    from app.rules import classify

    def fam(path: str, code: int = 200) -> str:
        rec = {"ip": "1.2.3.4", "ts": datetime(2020, 3, 4, tzinfo=timezone.utc),
               "method": "GET", "path": path, "code": code, "bytes": 12, "ua": "nikto"}
        parsed = parse_log_line(to_envelope(rec)["log"]["message"])
        assert parsed is not None, f"reshaped line failed to parse: {path}"
        return classify(parsed)[0]

    assert fam("/api/v1/reports/../../../../etc/passwd") == "path_traversal"
    assert fam("/index.php?id=1' OR '1'='1", 200) == "sqli_probe"
    assert fam("/wp-login.php", 404) == "scanner_probe"
    assert fam("/.git/config", 404) == "scanner_probe"
    # a normal WordPress GET is not a level-2 signature (falls to 'other')
    assert fam("/wordpress/index.html", 200) == "other"
    print("[self-test] adapter reshaping + rule signatures OK")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", type=Path, help="unpacked AIT-LDS v1.1 root")
    ap.add_argument("--self-test", action="store_true", help="adapter sanity only")
    args = ap.parse_args()

    _self_test()
    if args.self_test:
        return 0
    if not args.dataset or not args.dataset.exists():
        print("ERROR: --dataset path required (unpacked AIT-LDS v1.1 root)", file=sys.stderr)
        return 1

    settings = Settings()
    model = SentinelModel.load(str(_REPO / "services" / "sentinel" / "model" / "sentinel_xgb.json"))
    pairs = find_pairs(args.dataset)
    if not pairs:
        print("ERROR: no (apache access log, label) pairs found under dataset root",
              file=sys.stderr)
        return 1
    print(f"found {len(pairs)} apache-access/label file pairs")

    c = evaluate(pairs, settings, model)
    p, r, f = prf(c["tp"], c["fp"], c["fn"])
    total_win = c["tp"] + c["fp"] + c["fn"] + c["tn"]
    print("\n## SENTINEL vs AIT-LDS v1.1 — window-level detection")
    print(f"attack lines in ground truth: {c['attack_lines']}")
    print(f"windows: {total_win}  (tp {c['tp']}  fp {c['fp']}  fn {c['fn']}  tn {c['tn']})")
    print(f"precision {p:.3f}  recall {r:.3f}  f1 {f:.3f}")
    fp_rate = c["fp"] / (c["fp"] + c["tn"]) if (c["fp"] + c["tn"]) else 0.0
    print(f"benign-window false-positive rate: {fp_rate:.4f}  "
          "(domain-mismatch caveat: AIT benign traffic is WordPress/webmail, not /api/v1)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
