"""The 5-minute dedup window.

Key is (entity_type, entity_id, alert type): "this IP is flooding" repeats
every minute while a burst runs, but only the first occurrence per window may
page anyone. Suppressed occurrences are counted and surfaced on the next sent
alert for the same key ("+N similar suppressed"), so nothing is silently lost.
"""
from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class _Entry:
    last_sent: float
    suppressed: int = 0


class Deduper:
    def __init__(self, window_seconds: float) -> None:
        self.window = window_seconds
        self._entries: dict[tuple[str, str, str], _Entry] = {}
        self.sent = 0
        self.suppressed = 0

    def check(self, entity_type: str, entity_id: str, alert_type: str) -> tuple[bool, int]:
        """Returns (should_send, previously_suppressed_count)."""
        now = time.monotonic()
        key = (entity_type, entity_id, alert_type)
        entry = self._entries.get(key)
        if entry is not None and now - entry.last_sent < self.window:
            entry.suppressed += 1
            self.suppressed += 1
            return False, entry.suppressed
        prior = entry.suppressed if entry is not None else 0
        self._entries[key] = _Entry(last_sent=now)
        self.sent += 1
        self._prune(now)
        return True, prior

    def _prune(self, now: float) -> None:
        expired = [k for k, e in self._entries.items() if now - e.last_sent > self.window * 4]
        for k in expired:
            del self._entries[k]

    def stats(self) -> dict:
        return {"sent": self.sent, "suppressed": self.suppressed, "tracked_keys": len(self._entries)}
