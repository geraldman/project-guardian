"""Kafka lifecycle for CASSANDRA: pure Kafka-in/Kafka-out (Vector owns the
OpenSearch write path).

Connects in the background with retry/backoff so the app comes up (and
reports degraded) while Redpanda is still booting under compose. On first
contact it idempotently ensures the three detection-layer topics — ARGUS and
the alerting service also create them; first one up wins.

auto_offset_reset="earliest", deliberately: a brand-new guardian-cassandra
group replays the queue's ~6h retention window, which warms the per-payer
CUSUM baselines from *real* history — for a cumulative drift detector that
replay is the primary cold-start bootstrap (training/seed_history.py covers
the fresh-stack case where the queue itself is empty). Offsets commit after
first consumption, so restarts do not replay again.
"""
import asyncio
import json
import logging

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.admin import AIOKafkaAdminClient, NewTopic
from aiokafka.errors import KafkaError, TopicAlreadyExistsError

from .pipeline import Pipeline

log = logging.getLogger("cassandra.kafka")

# Same topic contract as capture-agent / ARGUS (docs/architecture.md).
TOPIC_PARTITIONS = 3
TOPIC_REPLICATION = 1
TOPIC_RETENTION_MS = 21_600_000

_BACKOFF_INITIAL_S = 1.0
_BACKOFF_MAX_S = 15.0


class CassandraKafka:
    def __init__(self, brokers: str, input_topic: str, scores_topic: str,
                 alerts_topic: str, pipeline: Pipeline) -> None:
        self._brokers = brokers
        self.input_topic = input_topic
        self.scores_topic = scores_topic
        self.alerts_topic = alerts_topic
        self._pipeline = pipeline
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
                    group_id="guardian-cassandra",
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
            # The full assignment must be registered before the first message
            # (see Pipeline.register_partitions); the join usually completes
            # inside consumer.start(), the loop covers a slow rebalance.
            for _ in range(100):
                if consumer.assignment():
                    break
                await asyncio.sleep(0.1)
            self._pipeline.register_partitions(
                [tp.partition for tp in consumer.assignment()]
            )
            self.connected = True
            log.info("connected; consuming %s (partitions %s)", self.input_topic,
                     sorted(tp.partition for tp in consumer.assignment()))
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
            ready = self._pipeline.add_event(doc, msg.partition)
            for minute in sorted(ready):
                await self.finalize_and_emit(minute)

    async def finalize_and_emit(self, minute: int) -> None:
        """Shared by the consume loop and the wall-clock flusher. finalize()
        is synchronous (no awaits inside), so the two callers can never
        interleave within it on one event loop, and a second call for the
        same minute pops nothing — no lock needed."""
        docs, alerts = self._pipeline.finalize(minute)
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
