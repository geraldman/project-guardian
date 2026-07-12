"""Kafka lifecycle for ARGUS: pure Kafka-in/Kafka-out (Vector owns the
OpenSearch write path).

Connects in the background with retry/backoff so the app comes up (and
reports degraded) while Redpanda is still booting under compose. On first
contact it bootstraps all three detection-layer topics — ARGUS is the first
consumer of guardian.telemetry.normalized and the producer of the other two.

auto_offset_reset="earliest": a brand-new consumer group replays the queue's
~6h retention window, so a seed run produced moments before ARGUS finished
connecting still lands in the baseline.
"""
import asyncio
import json
import logging

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.admin import AIOKafkaAdminClient, NewTopic
from aiokafka.errors import KafkaError, TopicAlreadyExistsError

from .pipeline import Pipeline

log = logging.getLogger("argus.kafka")

# Same topic contract as capture-agent (docs/architecture.md).
TOPIC_PARTITIONS = 3
TOPIC_REPLICATION = 1
TOPIC_RETENTION_MS = 21_600_000

_BACKOFF_INITIAL_S = 1.0
_BACKOFF_MAX_S = 15.0


class ArgusKafka:
    def __init__(self, brokers: str, input_topic: str, scores_topic: str,
                 alerts_topic: str, pipeline: Pipeline, finalize_lock: asyncio.Lock) -> None:
        self._brokers = brokers
        self.input_topic = input_topic
        self.scores_topic = scores_topic
        self.alerts_topic = alerts_topic
        self._pipeline = pipeline
        self._lock = finalize_lock
        self._producer: AIOKafkaProducer | None = None
        self._consumer: AIOKafkaConsumer | None = None
        self._task: asyncio.Task | None = None
        self.connected = False

    def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    async def _run(self) -> None:
        backoff = _BACKOFF_INITIAL_S
        while True:
            try:
                await self._ensure_topics()
                producer = AIOKafkaProducer(
                    bootstrap_servers=self._brokers,
                    acks=1,
                    linger_ms=10,
                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                )
                await producer.start()
                consumer = AIOKafkaConsumer(
                    self.input_topic,
                    bootstrap_servers=self._brokers,
                    group_id="guardian-argus",
                    auto_offset_reset="earliest",
                    enable_auto_commit=True,
                )
                await consumer.start()
            except (KafkaError, OSError) as exc:
                log.warning("Redpanda unreachable at %s (%s); retrying in %.0fs",
                            self._brokers, exc, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, _BACKOFF_MAX_S)
                continue
            self._producer, self._consumer = producer, consumer
            self.connected = True
            log.info("connected; consuming %s", self.input_topic)
            try:
                await self._consume_loop(consumer)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("consume loop crashed; reconnecting")
                self.connected = False
                await self._safe_close()
                backoff = _BACKOFF_INITIAL_S

    async def _consume_loop(self, consumer: AIOKafkaConsumer) -> None:
        async for msg in consumer:
            try:
                doc = json.loads(msg.value)
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._pipeline.counters["events_dropped"] += 1
                continue
            ready = self._pipeline.add_event(doc, len(msg.value))
            for minute in sorted(ready):
                await self.finalize_and_emit(minute)

    async def finalize_and_emit(self, minute: int) -> None:
        """Shared by the consume loop and the wall-clock flusher."""
        async with self._lock:
            docs, alerts = await self._pipeline.finalize(minute)
        if self._producer is None:
            return
        for doc in docs:
            await self._producer.send(self.scores_topic, doc)
        for alert in alerts:
            await self._producer.send_and_wait(self.alerts_topic, alert)
            log.info("alert %s %s/%s score=%.2f", alert["alert"]["type"],
                     alert["alert"]["entity_type"], alert["alert"]["entity_id"],
                     alert["alert"]["score"])

    async def _ensure_topics(self) -> None:
        admin = AIOKafkaAdminClient(bootstrap_servers=self._brokers)
        await admin.start()
        try:
            for topic in (self.input_topic, self.scores_topic, self.alerts_topic):
                try:
                    await admin.create_topics([
                        NewTopic(
                            name=topic,
                            num_partitions=TOPIC_PARTITIONS,
                            replication_factor=TOPIC_REPLICATION,
                            topic_configs={"retention.ms": str(TOPIC_RETENTION_MS)},
                        )
                    ])
                    log.info("created topic %s", topic)
                except TopicAlreadyExistsError:
                    log.debug("topic %s already exists", topic)
        finally:
            await admin.close()

    async def _safe_close(self) -> None:
        for client in (self._consumer, self._producer):
            if client is not None:
                try:
                    await client.stop()
                except Exception:  # already broken; nothing useful to do
                    pass
        self._consumer = self._producer = None

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self.connected = False
        await self._safe_close()
