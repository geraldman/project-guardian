"""Bucket aggregation + scoring — the heart of ARGUS.

Events are folded into 1-minute tumbling buckets keyed by *event* time, per
entity (global / payer / client_ip). Watermarks are tracked **per partition**
and a bucket for minute M finalizes only when the slowest partition's
watermark passes M: the producer round-robins events across partitions, so
during a fast backdated replay the consumer sees whole minutes "from the
past" of whichever partition it fetches next — a single global watermark
would finalize those buckets as fragments (observed live: 1.7 events/bucket
instead of ~600). A wall-clock flusher remains the safety net for stalled
streams and idle partitions.

Scoring is score-then-update: a bucket is judged against the baseline as it
was *before* that bucket, then folded in. client_ip baselines are cohort-wide
(random synthetic IPs rarely repeat; a flood IP towers over the cohort
instead of over its own empty history).
"""
from __future__ import annotations

import logging
import math
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .baseline import EWStats
from .config import Settings
from .models import MultivariateDetector, bucket_vector

log = logging.getLogger("argus.pipeline")

RATE, PAYLOAD, ERROR = "rate", "payload", "error"


@dataclass
class _Agg:
    count: int = 0
    payload_sum: float = 0.0
    amount_sum: float = 0.0
    amount_n: int = 0
    error_count: int = 0
    malformed_count: int = 0

    def add(self, payload_bytes: int, amount: float | None, error: bool, malformed: bool) -> None:
        self.count += 1
        self.payload_sum += payload_bytes
        if amount is not None:
            self.amount_sum += abs(amount)
            self.amount_n += 1
        self.error_count += int(error)
        self.malformed_count += int(malformed)

    def features(self) -> dict:
        return {
            "event_count": self.count,
            "mean_payload_bytes": round(self.payload_sum / self.count, 1) if self.count else 0.0,
            "mean_amount": round(self.amount_sum / self.amount_n, 2) if self.amount_n else 0.0,
            "error_ratio": round(self.error_count / self.count, 4) if self.count else 0.0,
            "malformed_count": self.malformed_count,
        }


@dataclass
class _Bucket:
    minute: int  # epoch seconds of bucket start
    global_agg: _Agg = field(default_factory=_Agg)
    payers: dict[str, _Agg] = field(default_factory=dict)
    ips: dict[str, _Agg] = field(default_factory=dict)
    last_append_wall: float = field(default_factory=time.monotonic)


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


class Pipeline:
    def __init__(self, cfg: Settings) -> None:
        self.cfg = cfg
        self._buckets: dict[int, _Bucket] = {}
        self._watermarks: dict[int, int] = {}  # partition -> newest minute seen
        self._finalized_watermark = 0  # newest finalized minute; older events are late
        # entity baselines: "global" / "payer:<id>" keyed dicts of EWStats per feature
        self.entities: dict[str, dict[str, EWStats]] = {}
        self.ip_cohort = EWStats(cfg.ew_halflife_buckets)
        self.detector = MultivariateDetector(
            cfg.reservoir_size, cfg.min_fit_samples, cfg.refit_interval_buckets
        )
        self.counters = {
            "events_consumed": 0,
            "events_dropped": 0,
            "events_late": 0,
            "buckets_finalized": 0,
            "scores_emitted": 0,
            "alerts_emitted": 0,
        }

    # -- ingest --------------------------------------------------------------

    def register_partitions(self, partitions: list[int]) -> None:
        """Must be called with the full assignment before consuming: a bucket
        may only finalize once EVERY partition's watermark passed it. Without
        pre-registration, a partition whose backlog hasn't been fetched yet is
        invisible to min(), its minutes finalize early, and its entire replay
        arrives 'late' as one-event fragment buckets (observed live)."""
        for p in partitions:
            self._watermarks.setdefault(p, 0)

    def add_event(self, doc: dict, payload_bytes: int, partition: int) -> list[int]:
        """Fold one normalized event in; returns minutes ready to finalize."""
        try:
            ts = datetime.fromisoformat(str(doc["@timestamp"]).replace("Z", "+00:00")).timestamp()
            tx = doc.get("transaction") or {}
            sec = doc.get("security") or {}
            payer = tx.get("payer_id")
            ip = (doc.get("network") or {}).get("client_ip")
            amount = tx.get("amount")
            amount = float(amount) if amount is not None else None
            error = bool(doc.get("error", False))
            malformed = bool(sec.get("is_malformed", False))
        except (KeyError, TypeError, ValueError):
            self.counters["events_dropped"] += 1
            return []

        minute = int(ts // self.cfg.bucket_seconds) * self.cfg.bucket_seconds
        if minute <= self._finalized_watermark:
            # Its bucket is already scored and gone; recreating it would spawn
            # a fragment bucket and poison the baseline. Count and move on.
            self.counters["events_late"] += 1
            return []
        self.counters["events_consumed"] += 1
        bucket = self._buckets.get(minute)
        if bucket is None:
            bucket = self._buckets[minute] = _Bucket(minute)
        bucket.last_append_wall = time.monotonic()

        bucket.global_agg.add(payload_bytes, amount, error, malformed)
        if payer:
            bucket.payers.setdefault(payer, _Agg()).add(payload_bytes, amount, error, malformed)
        if ip:
            bucket.ips.setdefault(ip, _Agg()).add(payload_bytes, amount, error, malformed)

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
            if now_wall - (m + self.cfg.bucket_seconds) > self.cfg.flush_after_seconds
            and now_mono - b.last_append_wall > self.cfg.flush_idle_seconds
        ]

    # -- scoring -------------------------------------------------------------

    def _stats_for(self, key: str) -> dict[str, EWStats]:
        stats = self.entities.get(key)
        if stats is None:
            hl = self.cfg.ew_halflife_buckets
            stats = self.entities[key] = {RATE: EWStats(hl), PAYLOAD: EWStats(hl), ERROR: EWStats(hl)}
        return stats

    @staticmethod
    def _z_component(z: float, threshold: float) -> float:
        return min(1.0, abs(z) / (2.0 * threshold))

    async def finalize(self, minute: int) -> tuple[list[dict], list[dict]]:
        """Score every entity in the bucket; returns (score_docs, alerts)."""
        bucket = self._buckets.pop(minute, None)
        if bucket is None:
            return [], []
        self._finalized_watermark = max(self._finalized_watermark, minute)
        cfg = self.cfg
        window = {
            "start": _iso(minute),
            "end": _iso(minute + cfg.bucket_seconds),
            "duration_seconds": cfg.bucket_seconds,
        }
        end_iso = window["end"]
        docs: list[dict] = []
        candidates: list[dict] = []

        # ── global + payers: personal baselines ─────────────────────────────
        entity_aggs = [("global", "global", bucket.global_agg)]
        entity_aggs += [("payer", pid, agg) for pid, agg in bucket.payers.items()]
        for etype, eid, agg in entity_aggs:
            key = "global" if etype == "global" else f"payer:{eid}"
            stats = self._stats_for(key)
            feats = agg.features()
            warming = stats[RATE].n < cfg.warmup_buckets
            reasons: list[str] = []
            components: list[float] = []

            rate_z = stats[RATE].z(agg.count, std_floor=max(1.0, 0.1 * stats[RATE].mean))
            payload_z = stats[PAYLOAD].z(
                feats["mean_payload_bytes"], std_floor=max(20.0, 0.1 * stats[PAYLOAD].mean)
            )
            error_z = stats[ERROR].z(feats["error_ratio"], std_floor=0.05)
            alert_type, summary = None, ""
            if rate_z > cfg.z_threshold:
                reasons.append(f"rate_z={rate_z:.1f}>{cfg.z_threshold:g}")
                components.append(self._z_component(rate_z, cfg.z_threshold))
                mult = agg.count / max(stats[RATE].mean, 0.1)
                alert_type = "rate_spike"
                summary = (
                    f"Request rate for {etype} {eid} is {mult:.1f}x its baseline "
                    f"({agg.count} events/min, baseline mean {stats[RATE].mean:.1f})."
                )
            if payload_z > cfg.z_threshold:
                reasons.append(f"payload_z={payload_z:.1f}>{cfg.z_threshold:g}")
                components.append(self._z_component(payload_z, cfg.z_threshold))
                if alert_type is None:
                    alert_type = "payload_anomaly"
                    summary = (
                        f"Mean payload size for {etype} {eid} is "
                        f"{feats['mean_payload_bytes']:.0f} bytes vs baseline "
                        f"{stats[PAYLOAD].mean:.0f} (z={payload_z:.1f})."
                    )
            if error_z > cfg.z_threshold:
                reasons.append(f"error_ratio_z={error_z:.1f}>{cfg.z_threshold:g}")
                components.append(self._z_component(error_z, cfg.z_threshold))
                if alert_type is None:
                    alert_type = "error_ratio_spike"
                    summary = (
                        f"Error ratio for {etype} {eid} is {feats['error_ratio']:.0%} "
                        f"vs baseline {stats[ERROR].mean:.0%} (z={error_z:.1f})."
                    )

            vec = bucket_vector(
                agg.count, feats["mean_payload_bytes"], feats["error_ratio"], agg.malformed_count
            )
            mv_score, iso_df, knn_ratio = self.detector.score(vec)
            if mv_score >= cfg.multivariate_threshold:
                reasons.append(f"multivariate={mv_score:.2f} (iforest_df={iso_df:.3f}, knn_ratio={knn_ratio:.1f})")
                components.append(mv_score)
                if alert_type is None:
                    alert_type = "multivariate_outlier"
                    summary = (
                        f"Traffic shape for {etype} {eid} is a multivariate outlier "
                        f"(Isolation Forest df={iso_df:.3f}, k-NN distance ratio {knn_ratio:.1f})."
                    )
            self.detector.observe(vec)

            score = round(max(components, default=0.0), 4)
            anomalous = bool(components) and not warming
            baseline = {
                "rate_mean": round(stats[RATE].mean, 3),
                "rate_std": round(math.sqrt(max(stats[RATE].var, 0.0)), 3),
                "payload_mean": round(stats[PAYLOAD].mean, 1),
                "payload_std": round(math.sqrt(max(stats[PAYLOAD].var, 0.0)), 1),
                "buckets_observed": stats[RATE].n,
            }
            # Update AFTER scoring; anomalous buckets still fold in (EW decay
            # re-normalizes if the "attack" becomes the new normal).
            stats[RATE].update(agg.count)
            stats[PAYLOAD].update(feats["mean_payload_bytes"])
            stats[ERROR].update(feats["error_ratio"])

            if etype == "global" or anomalous or agg.count >= cfg.min_bucket_events:
                docs.append(
                    {
                        "@timestamp": end_iso,
                        "score": {
                            "model": "argus",
                            "entity_type": etype,
                            "entity_id": eid,
                            "anomaly_score": score,
                            "is_anomalous": anomalous,
                            "warming_up": warming,
                            "reasons": reasons,
                            "features": feats,
                            "baseline": baseline,
                            "window": window,
                        },
                    }
                )
            # min_alert_events applies to global too: a fragment/stall-flushed
            # global bucket with 3 events and 1 error is a 33% "error spike".
            if anomalous and alert_type and agg.count >= cfg.min_alert_events:
                candidates.append(
                    self._alert(end_iso, alert_type, etype, eid, score, summary, window,
                                {"rate_z": round(rate_z, 1), "payload_z": round(payload_z, 1),
                                 "error_ratio_z": round(error_z, 1), "multivariate": round(mv_score, 2)})
                )

        # ── client IPs: cohort baseline ──────────────────────────────────────
        cohort_warming = self.ip_cohort.n < cfg.warmup_buckets * 10  # ~10 IPs seen per bucket min.
        ip_counts = [(ip, agg) for ip, agg in bucket.ips.items()]
        for ip, agg in ip_counts:
            z = self.ip_cohort.z(agg.count, std_floor=max(1.0, 0.5 * self.ip_cohort.mean))
            if z > cfg.z_threshold and agg.count >= cfg.min_alert_events and not cohort_warming:
                feats = agg.features()
                score = round(self._z_component(z, cfg.z_threshold), 4)
                mult = agg.count / max(self.ip_cohort.mean, 0.1)
                docs.append(
                    {
                        "@timestamp": end_iso,
                        "score": {
                            "model": "argus",
                            "entity_type": "client_ip",
                            "entity_id": ip,
                            "anomaly_score": score,
                            "is_anomalous": True,
                            "warming_up": False,
                            "reasons": [f"cohort_rate_z={z:.1f}>{cfg.z_threshold:g}"],
                            "features": feats,
                            "baseline": {
                                "rate_mean": round(self.ip_cohort.mean, 3),
                                "rate_std": round(math.sqrt(max(self.ip_cohort.var, 0.0)), 3),
                                "buckets_observed": self.ip_cohort.n,
                            },
                            "window": window,
                        },
                    }
                )
                candidates.append(
                    self._alert(
                        end_iso, "rate_spike", "client_ip", ip, score,
                        f"Request rate for client_ip {ip} is {mult:.1f}x the cohort baseline "
                        f"({agg.count} events/min, cohort mean {self.ip_cohort.mean:.1f}).",
                        window, {"cohort_rate_z": round(z, 1)},
                    )
                )
        for _, agg in ip_counts:
            self.ip_cohort.update(agg.count)

        await self.detector.maybe_refit()
        self.counters["buckets_finalized"] += 1
        self.counters["scores_emitted"] += len(docs)

        # Flood guard: a global burst elevates dozens of payers at once; page
        # about the worst few, the rest are still in guardian-scores-*.
        candidates.sort(key=lambda a: a["alert"]["score"], reverse=True)
        alerts = candidates[: cfg.max_alerts_per_bucket]
        self.counters["alerts_emitted"] += len(alerts)
        return docs, alerts

    @staticmethod
    def _alert(ts: str, atype: str, etype: str, eid: str, score: float,
               summary: str, window: dict, details: dict) -> dict:
        severity = "high" if score >= 0.9 else "medium" if score >= 0.65 else "low"
        return {
            "@timestamp": ts,
            "alert": {
                "id": str(uuid.uuid4()),
                "type": atype,
                "severity": severity,
                "entity_type": etype,
                "entity_id": eid,
                "score": score,
                "source": "argus",
                "summary": summary,
                "window": {"start": window["start"], "end": window["end"]},
                "details": details,
            },
        }

    # -- persistence ----------------------------------------------------------

    def state_dict(self) -> dict:
        return {
            "version": 1,
            "entities": {
                key: {feat: s.to_dict() for feat, s in stats.items()}
                for key, stats in self.entities.items()
            },
            "ip_cohort": self.ip_cohort.to_dict(),
        }

    def load_state(self, state: dict) -> None:
        hl = self.cfg.ew_halflife_buckets
        for key, stats in (state.get("entities") or {}).items():
            self.entities[key] = {
                feat: EWStats.from_dict(hl, d)
                for feat, d in stats.items()
                if feat in (RATE, PAYLOAD, ERROR)
            }
        if "ip_cohort" in state:
            self.ip_cohort = EWStats.from_dict(hl, state["ip_cohort"])
        log.info("loaded baseline state: %d entities", len(self.entities))
