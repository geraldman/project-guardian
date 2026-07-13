"""Offline validation of the pure SENTINEL pipeline (no aiokafka, no stack).

Feeds synthetic normalized events — every pinned benign family, every attack
technique, a benign burst, legacy events without a log object — through
Pipeline.add_event/finalize and asserts the score/alert envelopes match the
docs/architecture.md contract. Runs on host Python:

    python -m pytest services/sentinel/tests -q
"""
import uuid
from datetime import datetime, timezone

import pytest

from app.config import Settings
from app.model import SentinelModel
from app.pipeline import Pipeline

MODEL_PATH = __file__.rsplit("tests", 1)[0] + "model/sentinel_xgb.json"

# One window at a fixed minute; a later event advances the watermark.
MINUTE = int(datetime(2026, 7, 13, 8, 40, tzinfo=timezone.utc).timestamp())


@pytest.fixture(scope="module")
def model() -> SentinelModel:
    return SentinelModel.load(MODEL_PATH)


@pytest.fixture()
def pipeline(model: SentinelModel) -> Pipeline:
    p = Pipeline(Settings(), model)
    p.register_partitions([0])
    return p


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _doc(ip: str, log_message: str | None, offset: float = 1.0, minute: int = MINUTE) -> dict:
    """A normalized event as Vector indexes it (shape verified against live
    guardian-traffic-* documents)."""
    doc = {
        "@timestamp": _iso(minute + offset),
        "error": False,
        "event": {"id": str(uuid.uuid4()), "type": "transaction"},
        "ingest": {"pipeline_stage": "vector", "processed_at": _iso(minute + offset)},
        "network": {"client_ip": ip},
        "security": {"attack_pattern": None, "is_attack": False, "is_malformed": False},
        "source": {"service": "mock-lti"},
        "transaction": {
            "amount": 125000.0, "channel": "ecommerce", "currency": "IDR",
            "latency_ms": 12.7, "payee_id": "merchant-0015",
            "payer_id": "wallet-user-0031", "status": "approved",
        },
    }
    if log_message is not None:
        doc["log"] = {"message": log_message}
    return doc


def _gateway(ip: str, method: str, path: str, code: int, msg: str,
             payer: str = "wallet-user-0031") -> str:
    return (f'{ip} - {payer} [13/Jul/2026:08:40:01 +0000] "{method} {path} HTTP/1.1" '
            f'{code} 512 12ms "{msg}"')


def _benign_lines(ip: str) -> list[str]:
    return [
        _gateway(ip, "POST", "/api/v1/transactions/route", 200,
                 "routed ecommerce payment wallet-user-0031->merchant-0015"),
        _gateway(ip, "GET", "/api/v1/accounts/wallet-user-0031/balance", 200,
                 "balance inquiry ok"),
        _gateway(ip, "GET", "/api/v1/transactions/79579b80/status", 200,
                 "status poll approved"),
        _gateway(ip, "POST", "/api/v1/settlements/wallet", 201,
                 "settlement batch accepted"),
        _gateway(ip, "POST", "/api/v1/transactions/route", 402,
                 "payment declined: insufficient_funds"),
    ]


def _run_window(pipeline: Pipeline, docs: list[dict]) -> tuple[list[dict], list[dict]]:
    for doc in docs:
        assert pipeline.add_event(doc, partition=0) == []
    # A later-minute event moves the watermark past MINUTE. If every event
    # was skipped (no log line), no bucket exists and nothing is ready —
    # finalize on a missing bucket is a no-op by contract.
    ready = pipeline.add_event(
        _doc("10.0.0.99", _benign_lines("10.0.0.99")[0], minute=MINUTE + 60), 0
    )
    assert ready in ([], [MINUTE])
    return pipeline.finalize(MINUTE)


# ── benign traffic stays quiet ──────────────────────────────────────────────


def test_benign_families_not_anomalous(pipeline):
    docs = [_doc(f"10.1.2.{i}", line, offset=i)
            for i in range(1, 6) for line in _benign_lines(f"10.1.2.{i}")]
    score_docs, alerts = _run_window(pipeline, docs)
    assert alerts == []
    assert score_docs, "5-event windows pass the score-doc volume floor"
    assert all(not d["score"]["is_anomalous"] for d in score_docs)
    assert all(d["score"]["anomaly_score"] < 0.4 for d in score_docs)


def test_benign_burst_stays_quiet(pipeline):
    """Rate spikes are ARGUS's niche: 400 benign events from one IP in one
    window must NOT trip the log classifier."""
    ip = "10.3.3.3"
    lines = _benign_lines(ip) * 80
    docs = [_doc(ip, line, offset=i * 0.1) for i, line in enumerate(lines)]
    score_docs, alerts = _run_window(pipeline, docs)
    assert alerts == []
    (doc,) = [d for d in score_docs if d["score"]["entity_id"] == ip]
    assert not doc["score"]["is_anomalous"]
    assert doc["score"]["features"]["window_events"] == 400


# ── each attack technique alerts ────────────────────────────────────────────


def _assert_attack(score_docs, alerts, ip, family):
    (doc,) = [d for d in score_docs if d["score"]["entity_id"] == ip]
    assert doc["score"]["is_anomalous"]
    assert doc["score"]["anomaly_score"] >= 0.85
    assert any(r.startswith(f"template={family}") for r in doc["score"]["reasons"])
    (alert,) = [a for a in alerts if a["alert"]["entity_id"] == ip]
    assert alert["alert"]["type"] == "log_classification"
    assert alert["alert"]["source"] == "sentinel"
    assert family in alert["alert"]["summary"]


def test_sqli(pipeline):
    ip = "45.148.10.19"
    lines = [
        _gateway(ip, "GET", "/api/v1/accounts?id=1' OR '1'='1", 200, "account lookup executed"),
        _gateway(ip, "GET", "/api/v1/accounts?id=1;DROP TABLE transactions;--", 200,
                 "account lookup executed"),
    ]
    docs = [_doc(ip, line, offset=i) for i, line in enumerate(lines, 1)]
    score_docs, alerts = _run_window(pipeline, docs)
    _assert_attack(score_docs, alerts, ip, "sqli_probe")


def test_path_traversal(pipeline):
    ip = "45.148.10.20"
    lines = [
        _gateway(ip, "GET", "/api/v1/reports/../../../../etc/passwd", 404, "route not found"),
        _gateway(ip, "GET", "/api/v1/exports/..%2f..%2f..%2f..%2fetc%2fshadow", 404,
                 "route not found"),
    ]
    docs = [_doc(ip, line, offset=i) for i, line in enumerate(lines, 1)]
    score_docs, alerts = _run_window(pipeline, docs)
    _assert_attack(score_docs, alerts, ip, "path_traversal")


def test_scanner_probes(pipeline):
    ip = "45.148.10.21"
    lines = [
        _gateway(ip, "GET", "/.env", 404, "unmatched route probe"),
        _gateway(ip, "GET", "/wp-login.php", 404, "unmatched route probe"),
        _gateway(ip, "GET", "/actuator/env", 404, "unmatched route probe"),
    ]
    docs = [_doc(ip, line, offset=i) for i, line in enumerate(lines, 1)]
    score_docs, alerts = _run_window(pipeline, docs)
    _assert_attack(score_docs, alerts, ip, "scanner_probe")


def test_credential_stuffing_storm(pipeline):
    ip = "45.148.10.22"
    lines = [
        _gateway(ip, "POST", "/api/v1/auth/login", 401,
                 f"authentication failed for wallet-user-0{400 + i} (attempt {i})",
                 payer=f"wallet-user-0{400 + i}")
        for i in range(2, 8)
    ]
    docs = [_doc(ip, line, offset=i) for i, line in enumerate(lines, 1)]
    score_docs, alerts = _run_window(pipeline, docs)
    _assert_attack(score_docs, alerts, ip, "auth_failure")
    (doc,) = [d for d in score_docs if d["score"]["entity_id"] == ip]
    assert any(r.startswith("auth_fail_ratio=") for r in doc["score"]["reasons"])


def test_single_auth_failure_is_only_suspicious(pipeline):
    """One 401 among benign traffic is the ambiguous middle: surfaced as a
    score doc, never an alert."""
    ip = "10.7.7.7"
    lines = _benign_lines(ip)[:3] + [
        _gateway(ip, "POST", "/api/v1/auth/login", 401,
                 "authentication failed for wallet-user-0031 (attempt 1)"),
    ]
    docs = [_doc(ip, line, offset=i) for i, line in enumerate(lines, 1)]
    score_docs, alerts = _run_window(pipeline, docs)
    assert alerts == []
    (doc,) = [d for d in score_docs if d["score"]["entity_id"] == ip]
    assert not doc["score"]["is_anomalous"]


def test_real_opensearch_lines_classify(pipeline):
    """Verbatim log lines captured from guardian-traffic-2026.07.13."""
    ip = "45.148.10.25"
    lines = [
        '45.148.10.25 - merchant-0141 [13/Jul/2026:03:51:54 +0000] "GET /admin.php HTTP/1.1" 404 555 19ms "unmatched route probe"',
        '45.148.10.25 - wallet-user-0404 [13/Jul/2026:03:52:07 +0000] "GET /api/v1/accounts?id=1;DROP TABLE transactions;-- HTTP/1.1" 200 798 18ms "account lookup executed"',
    ]
    docs = [_doc(ip, line, offset=i) for i, line in enumerate(lines, 1)]
    score_docs, alerts = _run_window(pipeline, docs)
    (doc,) = [d for d in score_docs if d["score"]["entity_id"] == ip]
    counts = doc["score"]["features"]["template_counts"]
    assert counts.get("scanner_probe") == 1 and counts.get("sqli_probe") == 1
    assert len(alerts) == 1


# ── envelope contracts ──────────────────────────────────────────────────────


def test_score_and_alert_envelopes(pipeline):
    ip = "45.148.10.23"
    docs = [_doc(ip, _gateway(ip, "GET", "/.git/config", 404, "unmatched route probe"))]
    score_docs, alerts = _run_window(pipeline, docs)

    (doc,) = [d for d in score_docs if d["score"]["entity_id"] == ip]
    score = doc["score"]
    assert doc["@timestamp"] == score["window"]["end"]
    assert score["model"] == "sentinel"
    assert score["entity_type"] == "client_ip"
    assert isinstance(score["anomaly_score"], float) and 0.0 <= score["anomaly_score"] <= 1.0
    assert isinstance(score["is_anomalous"], bool)
    assert isinstance(score["reasons"], list) and score["reasons"]
    assert isinstance(score["features"], dict)
    assert score["window"] == {
        "start": "2026-07-13T08:40:00Z",
        "end": "2026-07-13T08:41:00Z",
        "duration_seconds": 60,
    }

    (alert_doc,) = alerts
    alert = alert_doc["alert"]
    assert alert_doc["@timestamp"] == "2026-07-13T08:41:00Z"
    uuid.UUID(alert["id"])  # parseable uuid4, like ARGUS
    assert alert["type"] == "log_classification"
    assert alert["source"] == "sentinel"
    assert alert["severity"] in ("low", "medium", "high")
    assert alert["entity_type"] == "client_ip"
    assert alert["entity_id"] == ip
    assert 0.0 <= alert["score"] <= 1.0
    assert alert["summary"]
    assert alert["window"] == {"start": "2026-07-13T08:40:00Z", "end": "2026-07-13T08:41:00Z"}
    assert isinstance(alert["details"], dict)


def test_alert_flood_guard(pipeline):
    """More anomalous IPs than max_alerts_per_window: alerts are capped,
    score docs are not."""
    ips = [f"45.148.10.{i}" for i in range(11, 19)]  # 8 attacker IPs
    docs = [_doc(ip, _gateway(ip, "GET", "/.env", 404, "unmatched route probe"), offset=i)
            for i, ip in enumerate(ips, 1)]
    score_docs, alerts = _run_window(pipeline, docs)
    anomalous = [d for d in score_docs if d["score"]["is_anomalous"]]
    assert len(anomalous) == len(ips)
    assert len(alerts) == pipeline.cfg.max_alerts_per_window


# ── soak simulation (the Phase-3 success criteria, offline) ─────────────────


def test_log_attack_soak_simulation(pipeline):
    """5 minutes of generator-shaped traffic: 10 ev/s with log_attack
    probability 0.08 across 20 attacker IPs, then a benign burst minute.
    SENTINEL must alert on attacker IPs within the first minutes and stay
    silent for every benign IP, burst included."""
    import random

    rng = random.Random(7)
    attacker_pool = [f"45.148.10.{i}" for i in range(11, 31)]

    def benign_doc(minute_start, offset):
        ip = f"10.{rng.randint(0, 3)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        return _doc(ip, rng.choice(_benign_lines(ip)), offset=offset, minute=minute_start)

    def attack_doc(minute_start, offset):
        ip = rng.choice(attacker_pool)
        technique = rng.choice(("sqli", "traversal", "cred", "scanner"))
        if technique == "sqli":
            line = _gateway(ip, "GET", "/api/v1/accounts?id=admin'--", 200,
                            "account lookup executed")
        elif technique == "traversal":
            line = _gateway(ip, "GET", "/static/../../config/database.yml", 404,
                            "route not found")
        elif technique == "cred":
            line = _gateway(ip, "POST", "/api/v1/auth/login", 401,
                            f"authentication failed for wallet-user-0031 (attempt {rng.randint(2, 40)})")
        else:
            line = _gateway(ip, "GET", "/.env", 404, "unmatched route probe")
        return _doc(ip, line, offset=offset, minute=minute_start)

    alerts_by_minute: dict[int, list[dict]] = {}

    def feed(docs):
        for doc in sorted(docs, key=lambda d: d["@timestamp"]):
            for ready in pipeline.add_event(doc, partition=0):
                idx = (ready - MINUTE) // 60
                alerts_by_minute.setdefault(idx, []).extend(pipeline.finalize(ready)[1])

    for m in range(5):  # attack-mode minutes
        start = MINUTE + m * 60
        feed([
            attack_doc(start, o) if rng.random() < 0.08 else benign_doc(start, o)
            for o in (rng.uniform(0, 59.9) for _ in range(600))
        ])
    burst_ips = [f"10.2.14.{i}" for i in range(1, 5)]
    burst_start = MINUTE + 5 * 60
    burst_docs = [benign_doc(burst_start, rng.uniform(0, 59.9)) for _ in range(600)]
    burst_docs += [_doc(ip, rng.choice(_benign_lines(ip)), offset=rng.uniform(0, 59.9),
                        minute=burst_start)
                   for ip in burst_ips for _ in range(300)]  # 4 IPs flooding benign
    feed(burst_docs)
    # One event past the burst minute finalizes it too.
    feed([benign_doc(burst_start + 60, 1.0)])

    all_alerts = [a for alerts in alerts_by_minute.values() for a in alerts]
    assert all_alerts, "attack soak must raise alerts"
    assert all(a["alert"]["entity_id"].startswith("45.148.10.") for a in all_alerts), \
        "only attacker IPs may alert — benign volume (incl. the burst) must stay quiet"
    # Detection latency: the very first attack minute alerts as soon as it
    # finalizes (i.e. within ~2 minutes of the campaign starting).
    assert alerts_by_minute.get(0), "first attack windows must alert on finalization"
    assert alerts_by_minute.get(5, []) == [], "benign burst minute must be silent"
    distinct = {a["alert"]["entity_id"] for a in all_alerts}
    assert len(distinct) >= 10, f"campaign coverage too narrow: {sorted(distinct)}"


# ── robustness ──────────────────────────────────────────────────────────────


def test_legacy_events_without_log_are_skipped(pipeline):
    """Queued events predating the log_message envelope field must advance
    the stream without crashing or scoring."""
    docs = [_doc(f"10.9.9.{i}", None, offset=i) for i in range(1, 6)]
    score_docs, alerts = _run_window(pipeline, docs)
    assert pipeline.counters["events_skipped_no_log"] == 5
    assert [d for d in score_docs if d["score"]["entity_id"].startswith("10.9.9.")] == []
    assert alerts == []


def test_malformed_docs_and_late_events(pipeline):
    assert pipeline.add_event({"no_timestamp": True}, 0) == []
    assert pipeline.counters["events_dropped"] == 1

    ip = "10.8.8.8"
    _run_window(pipeline, [_doc(ip, _benign_lines(ip)[0])])
    # An event for the already-finalized minute is late, not re-bucketed.
    assert pipeline.add_event(_doc(ip, _benign_lines(ip)[0]), 0) == []
    assert pipeline.counters["events_late"] == 1


def test_unparseable_log_line_is_counted_not_fatal(pipeline):
    docs = [_doc("10.6.6.6", "totally not a gateway line")]
    score_docs, alerts = _run_window(pipeline, docs)
    assert pipeline.counters["lines_unparsed"] == 1
    assert alerts == []
