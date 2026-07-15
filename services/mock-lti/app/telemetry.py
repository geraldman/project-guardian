"""Fire-and-forget telemetry emitter -> capture-agent POST /ingest.

One shared httpx.AsyncClient, short timeout, blanket try/except: a
capture-agent hiccup must never stall or crash traffic generation.
Failures are counted, never raised.
"""
import asyncio

import httpx

from .schemas import TelemetryEvent

# Safety valve: when capture is down, drop (and count) instead of
# accumulating an unbounded pile of pending send tasks.
_MAX_IN_FLIGHT = 1000

# A saturation flood (mass timeouts/cancellations) can leak httpx pool slots,
# leaving the shared client permanently unable to send — observed during the
# Week-4 load test at a 1000 ev/s target. After this many consecutive
# failures the client is swapped for a fresh one, which restores service.
_REBUILD_AFTER_FAILURES = 50


class TelemetryEmitter:
    def __init__(self, url: str, timeout_seconds: float) -> None:
        self.url = url
        self.sent = 0
        self.failed = 0
        self._timeout_seconds = timeout_seconds
        self._client = httpx.AsyncClient(timeout=timeout_seconds)
        self._in_flight: set[asyncio.Task] = set()
        self._consecutive_failures = 0

    async def send(self, event: TelemetryEvent) -> None:
        """POST one event out-of-band; never raises."""
        client = self._client
        try:
            response = await client.post(
                self.url,
                content=event.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            if response.status_code >= 400:
                self._record_failure()
            else:
                self.sent += 1
                self._consecutive_failures = 0
        except Exception:
            self._record_failure()

    def emit_nowait(self, event: TelemetryEvent) -> None:
        """Fire-and-forget entry point for the generator loop."""
        if len(self._in_flight) >= _MAX_IN_FLIGHT:
            self._record_failure()
            return
        task = asyncio.create_task(self.send(event))
        self._in_flight.add(task)
        task.add_done_callback(self._in_flight.discard)

    def _record_failure(self) -> None:
        self.failed += 1
        self._consecutive_failures += 1
        if self._consecutive_failures >= _REBUILD_AFTER_FAILURES:
            self._consecutive_failures = 0
            stale = self._client
            self._client = httpx.AsyncClient(timeout=self._timeout_seconds)
            asyncio.create_task(self._dispose(stale))

    @staticmethod
    async def _dispose(client: httpx.AsyncClient) -> None:
        try:
            await client.aclose()
        except Exception:
            pass

    async def aclose(self) -> None:
        for task in list(self._in_flight):
            task.cancel()
        await self._client.aclose()
