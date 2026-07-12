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


class TelemetryEmitter:
    def __init__(self, url: str, timeout_seconds: float) -> None:
        self.url = url
        self.sent = 0
        self.failed = 0
        self._client = httpx.AsyncClient(timeout=timeout_seconds)
        self._in_flight: set[asyncio.Task] = set()

    async def send(self, event: TelemetryEvent) -> None:
        """POST one event out-of-band; never raises."""
        try:
            response = await self._client.post(
                self.url,
                content=event.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            if response.status_code >= 400:
                self.failed += 1
            else:
                self.sent += 1
        except Exception:
            self.failed += 1

    def emit_nowait(self, event: TelemetryEvent) -> None:
        """Fire-and-forget entry point for the generator loop."""
        if len(self._in_flight) >= _MAX_IN_FLIGHT:
            self.failed += 1
            return
        task = asyncio.create_task(self.send(event))
        self._in_flight.add(task)
        task.add_done_callback(self._in_flight.discard)

    async def aclose(self) -> None:
        for task in list(self._in_flight):
            task.cancel()
        await self._client.aclose()
