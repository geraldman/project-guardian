"""Windowed log classification — the heart of SENTINEL. Pure module: no aiokafka.

Normalized events are folded into 1-minute tumbling windows per client_ip,
keyed by event time. Finalization uses the same per-partition watermark
scheme as ARGUS (the producer round-robins across partitions, so a single
global watermark would finalize replayed minutes as fragments — see
services/argus/app/pipeline.py); a wall-clock flusher covers stalled streams.

Scoring a finalized window is a cascade:

  level 0  rule pre-filter — an unambiguous signature (SQLi metacharacters,
           `../` traversal, sensitive-file probe) or an auth-failure storm
           makes the window malicious immediately, model or not.
  model    XGBoost over the window's content-mix features handles the
           ambiguous middle (lone auth failures, unknown 4xx templates);
           the [suspicious_threshold, anomaly_threshold) band is surfaced in
           score docs but never alerts.

Volume is ARGUS's niche: benign bursts are in the training data as benign,
level-0 rules can't fire on benign templates, and model-only anomalies need
content evidence — so high benign volume alone never alerts here.

Events without a `log` object (legacy queued events predating the Week-3
envelope) still advance the stream's watermark but are skipped, never fatal.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .config import Settings
from .features import AnalyzedLine, analyze_line, window_features
from .logparse import build_miner, parse_log_line
from .model import SentinelModel
from .rules import AUTH_FAIL, LEVEL2_FAMILIES, window_rule_level

log = logging.getLogger("sentinel.pipeline")

_REASON_FAMILIES = LEVEL2_FAMILIES + (AUTH_FAIL,)


@dataclass
class _Bucket:
    minute: int  # epoch seconds of window start
    ips: dict[str, list[AnalyzedLine]] = field(default_factory=dict)
    last_append_wall: float = field(default_factory=time.monotonic)


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


class Pipeline:
    def __init__(self, cfg: Settings, model: SentinelModel) -> None:
        self.cfg = cfg
        self.model = model
        self.miner = build_miner()
        self._buckets: dict[int, _Bucket] = {}
        self._watermarks: dict[int, int] = {}  # partition -> newest minute seen
        self._finalized_watermark = 0
        self.counters = {
            "events_consumed": 0,
            "events_dropped": 0,
            "events_late": 0,
            "events_skipped_no_log": 0,
            "events_skipped_no_ip": 0,
            "lines_unparsed": 0,
            "windows_scored": 0,
            "buckets_finalized": 0,
            "scores_emitted": 0,
            "alerts_emitted": 0,
        }

    # -- ingest ---------------------------------------------------------------

    def register_partitions(self, partitions: list[int]) -> None:
        """Must be called with the full assignment before consuming — same
        early-finalization hazard as ARGUS (see its register_partitions)."""
        for p in partitions:
            self._watermarks.setdefault(p, 0)

    def add_event(self, doc: dict, partition: int) -> list[int]:
        """Fold one normalized event in; returns minutes ready to finalize."""
        try:
            ts = datetime.fromisoformat(str(doc["@timestamp"]).replace("Z", "+00:00")).timestamp()
        except (KeyError, TypeError, ValueError):
            self.counters["events_dropped"] += 1
            return []
        minute = int(ts // self.cfg.window_seconds) * self.cfg.window_seconds
        if minute <= self._finalized_watermark:
            self.counters["events_late"] += 1
            return []

        # Skipped events (no log line / no attributable IP) still advance the
        # watermark below: they establish stream time, and a legacy-heavy
        # stream must not stall finalization.
        log_obj = doc.get("log")
        message = log_obj.get("message") if isinstance(log_obj, dict) else None
        ip = (doc.get("network") or {}).get("client_ip")
        if not message:
            self.counters["events_skipped_no_log"] += 1
        elif not ip:
            self.counters["events_skipped_no_ip"] += 1
        else:
            parsed = parse_log_line(str(message))
            if parsed is None:
                self.counters["lines_unparsed"] += 1
            else:
                self.counters["events_consumed"] += 1
                bucket = self._buckets.get(minute)
                if bucket is None:
                    bucket = self._buckets[minute] = _Bucket(minute)
                bucket.last_append_wall = time.monotonic()
                bucket.ips.setdefault(str(ip), []).append(analyze_line(parsed, self.miner))

        if minute > self._watermarks.get(partition, 0):
            self._watermarks[partition] = minute
        low_watermark = min(self._watermarks.values())
        return [m for m in self._buckets if m < low_watermark]

    def stale_minutes(self) -> list[int]:
        """Wall-clock flush candidates: window long over AND recently idle
        (idle guard protects fast backdated replays, same as ARGUS)."""
        now_wall = time.time()
        now_mono = time.monotonic()
        return [
            m
            for m, b in self._buckets.items()
            if now_wall - (m + self.cfg.window_seconds) > self.cfg.flush_after_seconds
            and now_mono - b.last_append_wall > self.cfg.flush_idle_seconds
        ]

    # -- scoring --------------------------------------------------------------

    def finalize(self, minute: int) -> tuple[list[dict], list[dict]]:
        """Score every client_ip window in the bucket; returns (score_docs, alerts)."""
        bucket = self._buckets.pop(minute, None)
        if bucket is None:
            return [], []
        self._finalized_watermark = max(self._finalized_watermark, minute)
        cfg = self.cfg
        window = {
            "start": _iso(minute),
            "end": _iso(minute + cfg.window_seconds),
            "duration_seconds": cfg.window_seconds,
        }
        docs: list[dict] = []
        candidates: list[dict] = []
        for ip, lines in bucket.ips.items():
            doc, alert = self._score_window(ip, lines, window)
            self.counters["windows_scored"] += 1
            if doc is not None:
                docs.append(doc)
            if alert is not None:
                candidates.append(alert)

        # Flood guard mirroring ARGUS: a campaign elevates many IPs at once;
        # page about the worst few per window, the rest are still in
        # guardian-scores-* (and alert in later windows — dedup keys on
        # entity_id, so distinct IPs are never suppressed by each other).
        candidates.sort(key=lambda a: a["alert"]["score"], reverse=True)
        alerts = candidates[: cfg.max_alerts_per_window]
        self.counters["buckets_finalized"] += 1
        self.counters["scores_emitted"] += len(docs)
        self.counters["alerts_emitted"] += len(alerts)
        return docs, alerts

    def _score_window(
        self, ip: str, lines: list[AnalyzedLine], window: dict
    ) -> tuple[dict | None, dict | None]:
        cfg = self.cfg
        feats = window_features(lines)
        template_counts: dict[str, int] = feats["template_counts"]
        events = int(feats["window_events"])
        rule_level = window_rule_level(feats, cfg.auth_fail_storm)
        p_benign, p_suspicious, p_malicious = self.model.predict(feats)
        model_score = p_malicious + 0.5 * p_suspicious

        if rule_level == 2:
            # Level 0: signature hits scale the score; one SQLi line already
            # clears the alert bar, seven max it out.
            hits = sum(template_counts.get(f, 0) for f in LEVEL2_FAMILIES)
            if feats["n_auth_fail"] >= cfg.auth_fail_storm:
                hits += int(feats["n_auth_fail"])
            score = max(model_score, min(1.0, 0.85 + 0.03 * hits))
            anomalous = True
        else:
            score = model_score
            anomalous = model_score >= cfg.anomaly_threshold and events >= cfg.min_window_events

        reasons: list[str] = []
        for family in _REASON_FAMILIES:
            count = template_counts.get(family, 0)
            if count:
                reasons.append(f"template={family} count={count}")
        if feats["auth_fail_ratio"] > 0:
            reasons.append(f"auth_fail_ratio={feats['auth_fail_ratio']:.2f}")
        if anomalous and rule_level != 2:
            reasons.append(f"model_p_malicious={p_malicious:.2f}")
        elif not anomalous and model_score >= cfg.suspicious_threshold:
            reasons.append(f"model=suspicious score={model_score:.2f}")

        emit_doc = anomalous or rule_level >= 1 or events >= cfg.min_score_events
        score_doc = None
        if emit_doc:
            score_doc = {
                "@timestamp": window["end"],
                "score": {
                    "model": "sentinel",
                    "entity_type": "client_ip",
                    "entity_id": ip,
                    "anomaly_score": round(score, 4),
                    "is_anomalous": anomalous,
                    "reasons": reasons,
                    "features": {
                        "template_counts": template_counts,
                        "window_events": events,
                        "distinct_templates": int(feats["distinct_templates"]),
                        "auth_fail_ratio": round(feats["auth_fail_ratio"], 4),
                        "err_4xx_ratio": round(feats["err_4xx_ratio"], 4),
                        "rule_level": rule_level,
                        "p_malicious": round(p_malicious, 4),
                        "p_suspicious": round(p_suspicious, 4),
                    },
                    "window": window,
                },
            }

        alert = None
        if anomalous:
            attack_bits = ", ".join(
                f"{family} x{template_counts[family]}"
                for family in _REASON_FAMILIES
                if template_counts.get(family)
            )
            if rule_level == 2:
                summary = (
                    f"Malicious log content from client_ip {ip}: {attack_bits} "
                    f"({events} events in {window['duration_seconds']}s)."
                )
            else:
                summary = (
                    f"Log window for client_ip {ip} classified malicious by model "
                    f"(p={p_malicious:.2f}; {events} events"
                    + (f", {attack_bits}" if attack_bits else "")
                    + ")."
                )
            alert = self._alert(window, ip, round(score, 4), summary, {
                "rule_level": rule_level,
                "p_malicious": round(p_malicious, 3),
                "p_suspicious": round(p_suspicious, 3),
                "window_events": events,
            })
        return score_doc, alert

    @staticmethod
    def _alert(window: dict, ip: str, score: float, summary: str, details: dict) -> dict:
        # Same shape and severity bands as ARGUS's alerts — the alerting
        # service and guardian-alerts-* consume both interchangeably.
        severity = "high" if score >= 0.9 else "medium" if score >= 0.65 else "low"
        return {
            "@timestamp": window["end"],
            "alert": {
                "id": str(uuid.uuid4()),
                "type": "log_classification",
                "severity": severity,
                "entity_type": "client_ip",
                "entity_id": ip,
                "score": score,
                "source": "sentinel",
                "summary": summary,
                "window": {"start": window["start"], "end": window["end"]},
                "details": details,
            },
        }
