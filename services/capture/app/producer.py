"""Redpanda producer lifecycle for the capture-agent.

Connects in the background with retry/backoff so the app comes up (and reports
degraded) while Redpanda is still booting under compose, instead of crash-looping.
On first successful contact it bootstraps the telemetry topic, then starts the
producer and flips `connected`.
"""
import asyncio
import json
import logging

from aiokafka import AIOKafkaProducer
from aiokafka.admin import AIOKafkaAdminClient, NewTopic
from aiokafka.errors import KafkaError, TopicAlreadyExistsError

log = logging.getLogger("capture.producer")

# Topic contract (docs/architecture.md): 3 partitions, replication 1,
# ~6h retention — OpenSearch is the durable store, not the queue.
TOPIC_PARTITIONS = 3
TOPIC_REPLICATION = 1
TOPIC_RETENTION_MS = 21_600_000

_BACKOFF_INITIAL_S = 1.0
_BACKOFF_MAX_S = 15.0


class TelemetryProducer:
    def __init__(self, brokers: str, topic: str) -> None:
        self._brokers = brokers
        self.topic = topic
        self._producer: AIOKafkaProducer | None = None
        self._connect_task: asyncio.Task | None = None
        self.connected = False

    def start(self) -> None:
        """Kick off the background connect loop; returns immediately."""
        self._connect_task = asyncio.create_task(self._connect_with_backoff())

    async def _connect_with_backoff(self) -> None:
        backoff = _BACKOFF_INITIAL_S
        while True:
            try:
                await self._ensure_topic()
                producer = AIOKafkaProducer(
                    bootstrap_servers=self._brokers,
                    acks=1,
                    linger_ms=10,
                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                )
                await producer.start()
            except (KafkaError, OSError) as exc:
                log.warning(
                    "Redpanda unreachable at %s (%s); retrying in %.0fs",
                    self._brokers, exc, backoff,
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, _BACKOFF_MAX_S)
            else:
                self._producer = producer
                self.connected = True
                log.info("connected to %s, producing to %s", self._brokers, self.topic)
                return

    async def _ensure_topic(self) -> None:
        admin = AIOKafkaAdminClient(bootstrap_servers=self._brokers)
        await admin.start()
        try:
            await admin.create_topics([
                NewTopic(
                    name=self.topic,
                    num_partitions=TOPIC_PARTITIONS,
                    replication_factor=TOPIC_REPLICATION,
                    topic_configs={"retention.ms": str(TOPIC_RETENTION_MS)},
                )
            ])
            log.info("created topic %s", self.topic)
        except TopicAlreadyExistsError:
            log.debug("topic %s already exists", self.topic)
        finally:
            await admin.close()

    async def send(self, event: dict) -> None:
        """Produce one event (send_and_wait for debuggability; raises on failure)."""
        if self._producer is None or not self.connected:
            raise RuntimeError("producer not connected")
        await self._producer.send_and_wait(self.topic, event)

    async def stop(self) -> None:
        if self._connect_task is not None:
            self._connect_task.cancel()
        if self._producer is not None:
            self.connected = False
            await self._producer.stop()  # flushes pending batches before closing
