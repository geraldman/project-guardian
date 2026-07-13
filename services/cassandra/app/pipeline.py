"""Per-payer bucket aggregation + drift scoring — CASSANDRA's event loop core.

Events are folded into 1-minute tumbling buckets keyed by *event* time, per
payer. Watermarks are tracked **per partition** and a bucket for minute M
finalizes only when the slowest partition's watermark passes M — the producer
round-robins events across partitions, so during a fast backdated replay a
single global watermark would finalize buckets as fragments (bug observed
live on ARGUS; same fix here). A wall-clock flusher remains the safety net
for stalled streams and idle partitions.

On finalize, every *tracked* payer is scored — including payers absent from
the bucket, which are folded in as zero-count/zero-amount observations.
Absence is signal for a cumulative detector: the trickle's main effect is
more active minutes, and a baseline learned only over active minutes would
miss it. New payers start being tracked the first minute they appear.

finalize() is synchronous and pure (no awaits): on a single event loop the
consume loop and the flusher can never interleave inside it, and a double
finalize of the same minute pops nothing — so no lock is needed.

No aiokafka / pydantic imports: runs under host Python for the offline
validation suite.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .detector import Assessment, Params, PayerDrift

log = logging.getLogger("cassandra.pipeline")


@dataclass
class _Agg:
    count: int = 0
    amount_sum: float = 0.0
    payees: set = field(default_factory=set)

    def add(self, amount: float | None, payee: str | None) -> None:
        self.count += 1
        if amount is not None:
            self.amount_sum += abs(amount)  # attack traffic may carry negatives
        if payee:
            self.payees.add(payee)


_ZERO = _Agg()  # shared read-only zero bucket for absent payers


@dataclass
class _Bucket:
    minute: int  # epoch seconds of bucket start
    payers: dict[str, _Agg] = field(default_factory=dict)
    last_append_wall: float = field(default_factory=time.monotonic)


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


class Pipeline:
    def __init__(self, params: Params) -> None:
        self.p = params
        self._buckets: dict[int, _Bucket] = {}
        self._watermarks: dict[int, int] = {}  # partition -> newest minute seen
        self._finalized_watermark = 0  # newest finalized minute; older events are late
        self.payers: dict[str, PayerDrift] = {}
        self.counters = {
            "events_consumed": 0,
            "events_dropped": 0,
            "events_late": 0,
            "events_no_payer": 0,
            "buckets_finalized": 0,
            "scores_emitted": 0,
            "alerts_emitted": 0,
            "payers_rejected": 0,
        }

    # -- ingest ---------------------------------------------------------------

    def register_partitions(self, partitions: list[int]) -> None:
        """Must be called with the full assignment before consuming: a bucket
        may only finalize once EVERY partition's watermark passed it (see
        module docstring)."""
        for part in partitions:
            self._watermarks.setdefault(part, 0)

    def add_event(self, doc: dict, partition: int) -> list[int]:
        """Fold one normalized event in; returns minutes ready to finalize."""
        try:
            ts = datetime.fromisoformat(str(doc["@timestamp"]).replace("Z", "+00:00")).timestamp()
            tx = doc.get("transaction") or {}
            payer = tx.get("payer_id")
            payee = tx.get("payee_id")
            amount = tx.get("amount")
            amount = float(amount) if amount is not None else None
        except (KeyError, TypeError, ValueError):
            self.counters["events_dropped"] += 1
            return []
        if not payer:
            # Malformed attack traffic may omit the payer; nothing to attribute.
            self.counters["events_no_payer"] += 1
            return []

        minute = int(ts // self.p.bucket_seconds) * self.p.bucket_seconds
        if minute <= self._finalized_watermark:
            self.counters["events_late"] += 1
            return []
        self.counters["events_consumed"] += 1
        bucket = self._buckets.get(minute)
        if bucket is None:
            bucket = self._buckets[minute] = _Bucket(minute)
        bucket.last_append_wall = time.monotonic()
        if amount is not None:
            # Winsorize before summing — see Params.amount_event_cap.
            amount = min(abs(amount), self.p.amount_event_cap)
        bucket.payers.setdefault(payer, _Agg()).add(amount, payee)

        if minute > self._watermarks.get(partition, 0):
            self._watermarks[partition] = minute
        low_watermark = min(self._watermarks.values())
        return [m for m in self._buckets if m < low_watermark]

    def stale_minutes(self) -> list[int]:
        """Wall-clock flush: window long over AND no recent appends (the idle
        guard keeps a fast backdated replay from being flushed mid-minute)."""
        now_wall = time.time()
        now_mono = time.monotonic()
        return [
            m
            for m, b in self._buckets.items()
            if now_wall - (m + self.p.bucket_seconds) > self.p.flush_after_seconds
            and now_mono - b.last_append_wall > self.p.flush_idle_seconds
        ]

    # -- scoring --------------------------------------------------------------

    def finalize(self, minute: int) -> tuple[list[dict], list[dict]]:
        """Score every tracked payer against the bucket (zero-filled when
        absent); returns (score_docs, alerts)."""
        bucket = self._buckets.pop(minute, None)
        if bucket is None:
            return [], []
        self._finalized_watermark = max(self._finalized_watermark, minute)
        p = self.p
        end_epoch = minute + p.bucket_seconds
        end_iso = _iso(end_epoch)

        for pid in bucket.payers:
            if pid not in self.payers:
                if len(self.payers) >= p.max_tracked_payers:
                    self.counters["payers_rejected"] += 1
                    continue
                self.payers[pid] = PayerDrift(p)

        docs: list[dict] = []
        candidates: list[dict] = []
        for pid, drift in self.payers.items():
            agg = bucket.payers.get(pid, _ZERO)
            a = drift.update(agg.count, agg.amount_sum, len(agg.payees), minute, p)
            if a.is_anomalous or drift.s_max >= p.score_emit_floor:
                docs.append(self._score_doc(end_iso, end_epoch, pid, a))
            if a.is_anomalous:
                candidates.append(self._alert(end_iso, end_epoch, pid, a))

        self.counters["buckets_finalized"] += 1
        self.counters["scores_emitted"] += len(docs)
        # Flood guard (mirrors ARGUS): page about the worst few, the rest are
        # still visible in guardian-scores-*.
        candidates.sort(key=lambda alert: alert["alert"]["score"], reverse=True)
        alerts = candidates[: p.max_alerts_per_bucket]
        self.counters["alerts_emitted"] += len(alerts)
        return docs, alerts

    def _score_doc(self, end_iso: str, end_epoch: int, pid: str, a: Assessment) -> dict:
        return {
            "@timestamp": end_iso,
            "score": {
                "model": "cassandra",
                "entity_type": "payer",
                "entity_id": pid,
                "anomaly_score": a.anomaly_score,
                "is_anomalous": a.is_anomalous,
                "warming_up": a.warming,
                "reasons": a.reasons,
                "features": a.features,
                "baseline": a.baseline,
                "window": {
                    "start": _iso(a.window_start),
                    "end": end_iso,
                    "duration_seconds": end_epoch - a.window_start,
                },
            },
        }

    def _alert(self, end_iso: str, end_epoch: int, pid: str, a: Assessment) -> dict:
        score = a.anomaly_score
        severity = "high" if score >= 0.9 else "medium" if score >= 0.65 else "low"
        return {
            "@timestamp": end_iso,
            "alert": {
                "id": str(uuid.uuid4()),
                "type": "slow_exfiltration",
                "severity": severity,
                "entity_type": "payer",
                "entity_id": pid,
                "score": score,
                "source": "cassandra",
                "summary": f"Payer {pid} shows sustained low-and-slow drift: {a.summary}",
                "window": {"start": _iso(a.window_start), "end": end_iso},
                "details": a.details,
            },
        }

    # -- persistence ----------------------------------------------------------

    def state_dict(self) -> dict:
        return {
            "version": 1,
            "payers": {pid: drift.to_dict() for pid, drift in self.payers.items()},
        }

    def load_state(self, state: dict) -> None:
        for pid, d in (state.get("payers") or {}).items():
            self.payers[pid] = PayerDrift.from_dict(self.p, d)
        log.info("loaded drift state: %d payers", len(self.payers))
