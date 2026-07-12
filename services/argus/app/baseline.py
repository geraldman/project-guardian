"""Exponentially-weighted running baselines.

One EWStats per (entity, feature). EW mean/variance instead of a windowed
deque: constant memory per entity, old traffic decays smoothly, and the whole
baseline serializes to a few floats for the state snapshot. Halflife is
expressed in observations (buckets), not wall time.
"""
from __future__ import annotations

import math


class EWStats:
    def __init__(self, halflife: float) -> None:
        self.alpha = 1.0 - 0.5 ** (1.0 / max(halflife, 1.0))
        self.n = 0
        self.mean = 0.0
        self.var = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        if self.n == 1:
            self.mean = x
            self.var = 0.0
            return
        delta = x - self.mean
        self.mean += self.alpha * delta
        self.var = (1.0 - self.alpha) * (self.var + self.alpha * delta * delta)

    def z(self, x: float, std_floor: float) -> float:
        """Z-score with a floor on std so near-constant baselines can't make
        ordinary fluctuations look like 50σ events."""
        if self.n < 2:
            return 0.0
        std = max(math.sqrt(max(self.var, 0.0)), std_floor)
        return (x - self.mean) / std

    def to_dict(self) -> dict:
        return {"n": self.n, "mean": self.mean, "var": self.var}

    @classmethod
    def from_dict(cls, halflife: float, d: dict) -> "EWStats":
        s = cls(halflife)
        s.n = int(d.get("n", 0))
        s.mean = float(d.get("mean", 0.0))
        s.var = float(d.get("var", 0.0))
        return s
