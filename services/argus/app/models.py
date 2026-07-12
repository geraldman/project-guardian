"""Multivariate detector: Isolation Forest + k-NN over recent bucket vectors.

Both fit on the same rolling reservoir of standardized per-bucket feature
vectors and refit periodically in a worker thread (sklearn releases the GIL
but fit time still doesn't belong on the event loop). Isolation Forest is the
brief's suggested technique; the k-NN distance ratio is the extra-credit
"k-NN baseline profiling" item — its p99 self-distance at fit time becomes
the yardstick for "far from everything we've seen lately".

Not persisted across restarts: with min_fit_samples=200 at one global +
a handful of entity vectors per minute it re-arms in a few minutes, which is
cheaper than versioning pickled models (documented in the README).
"""
from __future__ import annotations

import asyncio
import logging
import math
from collections import deque

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler

log = logging.getLogger("argus.models")

K_NEIGHBORS = 5


def bucket_vector(count: int, mean_payload: float, error_ratio: float, malformed: int) -> list[float]:
    return [math.log1p(count), mean_payload, error_ratio, float(malformed)]


class MultivariateDetector:
    def __init__(self, reservoir_size: int, min_fit_samples: int, refit_interval_buckets: int) -> None:
        self.reservoir: deque[list[float]] = deque(maxlen=reservoir_size)
        self.min_fit_samples = min_fit_samples
        self.refit_interval = refit_interval_buckets
        self._buckets_since_fit = 0
        self._scaler: StandardScaler | None = None
        self._iforest: IsolationForest | None = None
        self._knn: NearestNeighbors | None = None
        self._knn_p99 = 1.0
        self.fitted = False
        self.fit_count = 0

    def observe(self, vec: list[float]) -> None:
        self.reservoir.append(vec)

    async def maybe_refit(self) -> None:
        """Called once per finalized global bucket; refits off the loop."""
        self._buckets_since_fit += 1
        if self._buckets_since_fit < self.refit_interval or len(self.reservoir) < self.min_fit_samples:
            return
        self._buckets_since_fit = 0
        snapshot = np.asarray(list(self.reservoir), dtype=float)
        await asyncio.get_running_loop().run_in_executor(None, self._fit, snapshot)

    def _fit(self, x: np.ndarray) -> None:
        scaler = StandardScaler().fit(x)
        xs = scaler.transform(x)
        iforest = IsolationForest(n_estimators=100, random_state=42).fit(xs)
        knn = NearestNeighbors(n_neighbors=K_NEIGHBORS + 1).fit(xs)
        # Self-distances: drop column 0 (each point's distance to itself).
        dist, _ = knn.kneighbors(xs)
        mean_self = dist[:, 1:].mean(axis=1)
        self._knn_p99 = float(max(np.percentile(mean_self, 99), 1e-6))
        self._scaler, self._iforest, self._knn = scaler, iforest, knn
        self.fitted = True
        self.fit_count += 1
        log.info("refit on %d samples (knn_p99=%.3f)", len(x), self._knn_p99)

    def score(self, vec: list[float]) -> tuple[float, float, float]:
        """Returns (combined 0..1 score, iforest decision_function, knn ratio)."""
        if not self.fitted:
            return 0.0, 0.0, 0.0
        xs = self._scaler.transform(np.asarray([vec], dtype=float))
        df = float(self._iforest.decision_function(xs)[0])  # negative = anomalous
        dist, _ = self._knn.kneighbors(xs, n_neighbors=K_NEIGHBORS)
        knn_ratio = float(dist.mean() / self._knn_p99)
        iso_score = min(1.0, max(0.0, -df / 0.15))
        knn_score = min(1.0, max(0.0, (knn_ratio - 1.0) / 2.0))
        return max(iso_score, knn_score), df, knn_ratio
