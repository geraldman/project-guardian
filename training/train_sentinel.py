"""Train SENTINEL's window classifier and commit the artifact.

Generates synthetic labeled (client_ip, 1-minute) windows from the pinned
gateway log-line families (docs/architecture.md#attack-modes) — benign:
route / balance / status / settlement / declined; attack: sqli /
path_traversal / cred_stuffing / scanner — plus benign BURSTS (rate spikes
are ARGUS's niche and must not trip SENTINEL) and ambiguous middles (lone
auth failures, unknown 4xx templates). Every line runs through the real
SENTINEL parsing/templating/feature code (imported from services/sentinel),
and labels come from the rule engine's confidence bands
(app.rules.window_rule_level), so the benign/suspicious/malicious classes
are reproducible from code — no manual labeling.

Deterministic by construction (fixed RNG seed, single-threaded hist
training): rerunning produces a byte-identical artifact, so the small
XGBoost JSON is committed and the Docker build needs no network, datasets,
or training step.

Usage (host Python; needs xgboost + drain3, see services/sentinel/requirements.txt):
    python training/train_sentinel.py [--windows 9000] [--seed 1337]
                                      [--out services/sentinel/model]
"""
import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import xgboost as xgb

# Reuse the service's own parsing/templating/feature/rule code so the model
# can never drift from what runs in the container.
_SENTINEL_DIR = Path(__file__).resolve().parents[1] / "services" / "sentinel"
sys.path.insert(0, str(_SENTINEL_DIR))

from app.features import FEATURE_NAMES, analyze_line, window_features  # noqa: E402
from app.logparse import build_miner, parse_log_line  # noqa: E402
from app.model import CLASSES  # noqa: E402
from app.rules import window_rule_level  # noqa: E402

AUTH_FAIL_STORM = 3  # keep in sync with app.config.Settings.auth_fail_storm

# ── log-line rendering ──────────────────────────────────────────────────────
# NOTE: deliberately duplicates the families in
# services/mock-lti/app/generator.py (benign_log_line / attack_log_line):
# this script runs on the host and can't import the container app. Keep the
# two in sync when either changes (generator.py carries the same warning).

MERCHANTS = [f"merchant-{i:04d}" for i in range(1, 201)]
WALLET_USERS = [f"wallet-user-{i:04d}" for i in range(1, 501)]
CHANNELS = ("ecommerce", "wallet", "bank")
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
# Plausible endpoints the ruleset does NOT know — exercises the "other"
# family so unknown-template windows have training coverage.
_UNKNOWN_2XX = (
    ("GET", "/api/v2/quotes/latest", 200, "fx quote served"),
    ("GET", "/healthz", 200, "ok"),
    ("POST", "/api/v1/notifications/subscribe", 201, "subscription created"),
)
_UNKNOWN_4XX = (
    ("GET", "/api/v1/invoices/1042", 404, "route not found"),
    ("POST", "/api/v1/webhooks/retry", 405, "method not allowed"),
    ("GET", "/api/v3/beta/limits", 404, "route not found"),
)


def _line(rng: random.Random, ip: str, payer: str | None, method: str, path: str,
          code: int, msg: str) -> str:
    nbytes = rng.randint(180, 900)
    lat = rng.randint(2, 60)
    return (f'{ip} - {payer or "-"} [13/Jul/2026:08:{rng.randint(0, 59):02d}:'
            f'{rng.randint(0, 59):02d} +0000] "{method} {path} HTTP/1.1" '
            f'{code} {nbytes} {lat}ms "{msg}"')


def _payer(rng: random.Random) -> str:
    return rng.choice(WALLET_USERS if rng.random() < 0.7 else MERCHANTS)


def benign_line(rng: random.Random, ip: str, declined_rate: float = 0.03) -> str:
    payer = _payer(rng)
    if rng.random() < declined_rate:
        return _line(rng, ip, payer, "POST", "/api/v1/transactions/route", 402,
                     f"payment declined: {rng.choice(_DECLINE_REASONS)}")
    family = rng.choice(("route", "route", "balance", "status", "settlement"))
    if family == "route":
        return _line(rng, ip, payer, "POST", "/api/v1/transactions/route", 200,
                     f"routed {rng.choice(CHANNELS)} payment {payer}->{_payer(rng)}")
    if family == "balance":
        return _line(rng, ip, payer, "GET", f"/api/v1/accounts/{payer}/balance", 200,
                     "balance inquiry ok")
    if family == "status":
        return _line(rng, ip, payer, "GET",
                     f"/api/v1/transactions/{rng.randbytes(4).hex()}/status", 200,
                     "status poll approved")
    return _line(rng, ip, payer, "POST", f"/api/v1/settlements/{rng.choice(CHANNELS)}",
                 201, "settlement batch accepted")


def schema_reject_line(rng: random.Random, ip: str) -> str:
    return _line(rng, ip, _payer(rng), "POST", "/api/v1/transactions/route", 400,
                 "rejected: schema validation failed")


def sqli_line(rng: random.Random, ip: str) -> str:
    return _line(rng, ip, _payer(rng), "GET",
                 f"/api/v1/accounts?id={rng.choice(_SQLI_PAYLOADS)}", 200,
                 "account lookup executed")


def traversal_line(rng: random.Random, ip: str) -> str:
    return _line(rng, ip, _payer(rng), "GET", rng.choice(_TRAVERSAL_PATHS), 404,
                 "route not found")


def auth_fail_line(rng: random.Random, ip: str, attempt: int) -> str:
    payer = _payer(rng)
    return _line(rng, ip, payer, "POST", "/api/v1/auth/login", 401,
                 f"authentication failed for {payer} (attempt {attempt})")


def scanner_line(rng: random.Random, ip: str) -> str:
    return _line(rng, ip, _payer(rng), "GET", rng.choice(_SCANNER_PATHS), 404,
                 "unmatched route probe")


def unknown_line(rng: random.Random, ip: str, table: tuple) -> str:
    method, path, code, msg = rng.choice(table)
    return _line(rng, ip, _payer(rng), method, path, code, msg)


# ── window recipes ──────────────────────────────────────────────────────────
# (name, weight, renderer(rng, ip) -> list[str]). Mix mirrors what the live
# generator produces per client_ip per minute, plus the ambiguous middles.


def _recipes(rng: random.Random) -> list[tuple[str, float]]:
    def benign_quiet(ip):
        return [benign_line(rng, ip) for _ in range(rng.randint(1, 3))]

    def benign_active(ip):
        return [benign_line(rng, ip) for _ in range(rng.randint(4, 30))]

    def benign_burst(ip):  # ARGUS's niche; must stay quiet here
        return [benign_line(rng, ip) for _ in range(rng.randint(80, 600))]

    def benign_declines(ip):  # a payer having a bad day, still benign
        return [benign_line(rng, ip, declined_rate=0.4) for _ in range(rng.randint(3, 20))]

    def schema_rejects(ip):  # malformed-mode traffic: ARGUS's niche
        return ([benign_line(rng, ip) for _ in range(rng.randint(2, 12))]
                + [schema_reject_line(rng, ip) for _ in range(rng.randint(1, 5))])

    def unknown_benign(ip):  # new 2xx endpoint the ruleset doesn't know
        return ([benign_line(rng, ip) for _ in range(rng.randint(1, 8))]
                + [unknown_line(rng, ip, _UNKNOWN_2XX) for _ in range(rng.randint(1, 3))])

    def auth_trickle(ip):  # 1-2 failures: typo or stuffing? suspicious band
        return ([benign_line(rng, ip) for _ in range(rng.randint(0, 6))]
                + [auth_fail_line(rng, ip, rng.randint(1, 2))
                   for _ in range(rng.randint(1, AUTH_FAIL_STORM - 1))])

    def unknown_4xx(ip):  # unknown templates answering 4xx: probing-ish
        return ([benign_line(rng, ip) for _ in range(rng.randint(0, 5))]
                + [unknown_line(rng, ip, _UNKNOWN_4XX) for _ in range(rng.randint(1, 3))])

    def attack_sqli(ip):
        return ([sqli_line(rng, ip) for _ in range(rng.randint(1, 8))]
                + [benign_line(rng, ip) for _ in range(rng.randint(0, 4))])

    def attack_traversal(ip):
        return ([traversal_line(rng, ip) for _ in range(rng.randint(1, 8))]
                + [benign_line(rng, ip) for _ in range(rng.randint(0, 4))])

    def attack_scanner(ip):
        return ([scanner_line(rng, ip) for _ in range(rng.randint(1, 8))]
                + [benign_line(rng, ip) for _ in range(rng.randint(0, 4))])

    def attack_mixed(ip):  # what a live log_attack IP window really looks like
        pool = (sqli_line, traversal_line, scanner_line)
        lines = [rng.choice(pool)(rng, ip) for _ in range(rng.randint(2, 12))]
        lines += [auth_fail_line(rng, ip, rng.randint(2, 40))
                  for _ in range(rng.randint(0, 3))]
        return lines

    def cred_storm(ip):
        base = rng.randint(1, 12)
        return ([auth_fail_line(rng, ip, base + i)
                 for i in range(rng.randint(AUTH_FAIL_STORM, 40))]
                + [benign_line(rng, ip) for _ in range(rng.randint(0, 3))])

    return [
        (benign_quiet, 0.22),
        (benign_active, 0.13),
        (benign_burst, 0.10),
        (benign_declines, 0.05),
        (schema_rejects, 0.05),
        (unknown_benign, 0.04),
        (auth_trickle, 0.10),
        (unknown_4xx, 0.07),
        (attack_sqli, 0.05),
        (attack_traversal, 0.05),
        (attack_scanner, 0.05),
        (attack_mixed, 0.04),
        (cred_storm, 0.05),
    ]


def build_dataset(n_windows: int, seed: int) -> tuple[np.ndarray, np.ndarray, Counter]:
    rng = random.Random(seed)
    miner = build_miner()  # one warm miner across the run, like a live service
    recipes = _recipes(rng)
    renderers = [r for r, _ in recipes]
    weights = [w for _, w in recipes]
    X = np.zeros((n_windows, len(FEATURE_NAMES)), dtype=np.float32)
    y = np.zeros(n_windows, dtype=np.int32)
    labels: Counter = Counter()
    for i in range(n_windows):
        ip = f"{rng.randint(10, 45)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        renderer = rng.choices(renderers, weights=weights, k=1)[0]
        lines = []
        for raw in renderer(ip):
            parsed = parse_log_line(raw)
            assert parsed is not None, f"unparseable training line: {raw!r}"
            lines.append(analyze_line(parsed, miner))
        feats = window_features(lines)
        X[i] = [feats[name] for name in FEATURE_NAMES]
        y[i] = window_rule_level(feats, AUTH_FAIL_STORM)
        labels[CLASSES[y[i]]] += 1
    return X, y, labels


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--windows", type=int, default=9000,
                        help="synthetic windows to generate (default 9000)")
    parser.add_argument("--seed", type=int, default=1337,
                        help="RNG seed; keep the default for a reproducible artifact")
    parser.add_argument("--out", default=str(_SENTINEL_DIR / "model"),
                        help="output directory (default services/sentinel/model)")
    args = parser.parse_args()

    print(f"generating {args.windows} windows (seed={args.seed})...")
    X, y, labels = build_dataset(args.windows, args.seed)
    print(f"class mix: {dict(labels)}")

    # Deterministic split + single-threaded hist training: byte-identical
    # artifact on every rerun with the same seed.
    rng = np.random.default_rng(args.seed)
    order = rng.permutation(len(y))
    cut = int(len(y) * 0.8)
    train_idx, hold_idx = order[:cut], order[cut:]
    dtrain = xgb.DMatrix(X[train_idx], label=y[train_idx], feature_names=list(FEATURE_NAMES))
    dhold = xgb.DMatrix(X[hold_idx], label=y[hold_idx], feature_names=list(FEATURE_NAMES))
    params = {
        "objective": "multi:softprob",
        "num_class": len(CLASSES),
        "max_depth": 3,
        "eta": 0.3,
        "tree_method": "hist",
        "seed": args.seed,
        "nthread": 1,
    }
    num_boost_round = 40
    booster = xgb.train(params, dtrain, num_boost_round=num_boost_round)

    hold_pred = booster.predict(dhold).argmax(axis=1)
    hold_true = y[hold_idx]
    accuracy = float((hold_pred == hold_true).mean())
    confusion = np.zeros((len(CLASSES), len(CLASSES)), dtype=int)
    for t, p in zip(hold_true, hold_pred):
        confusion[t][p] += 1
    print(f"holdout accuracy: {accuracy:.4f} ({len(hold_idx)} windows)")
    print("confusion (rows=truth, cols=predicted, order benign/suspicious/malicious):")
    for row in confusion:
        print("   ", row.tolist())
    if accuracy < 0.97:
        print("holdout accuracy below 0.97 — refusing to write a bad artifact")
        return 1

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = out_dir / "sentinel_xgb.json"
    booster.save_model(str(model_path))
    metadata = {
        "model": "sentinel",
        "classes": list(CLASSES),
        "feature_names": list(FEATURE_NAMES),
        "seed": args.seed,
        "windows": args.windows,
        "num_boost_round": num_boost_round,
        "max_depth": params["max_depth"],
        "holdout_accuracy": round(accuracy, 4),
        "xgboost_version": xgb.__version__,
    }
    (out_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    size_kb = model_path.stat().st_size / 1024
    print(f"wrote {model_path} ({size_kb:.0f} KB) + metadata.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
