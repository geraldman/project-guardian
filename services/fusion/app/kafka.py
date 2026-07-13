"""Kafka lifecycle for fusion: consumes the scorer fleet's output
(guardian.scores, group guardian-fusion) and publishes the unified
score.model="guardian" documents back to the same topic, plus
threat_level_change alerts to guardian.alerts. Pure Kafka-in/Kafka-out —
Vector owns the OpenSearch write path.

Connects in the background with retry/backoff so the app comes up (and
reports degraded) while Redpanda is still booting under compose; topic
creation is idempotent (first service up wins, same contract as
ARGUS/alerting).

auto_offset_reset="latest": fusion models the CURRENT threat state. A brand-
new consumer group starting at "earliest" would replay up to ~6h of retained
scores, lighting up today's threat picture with attacks that ended hours ago.
Skipping that history costs nothing — the state has a minutes-scale half-life
and re-forms from the live stream within a couple of minutes. Committed group
offsets still resume normally across restarts, and the engine's stale-score
guard drops any replayed backlog older than stale_after_seconds.
"""
import asyncio
import json
import logging
import time

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.admin import AIOKafkaAdminClient, NewTopic
from aiokafka.errors import KafkaError, TopicAlreadyExistsError

from .engine import FusionEngine

log = logging.getLogger("fusion.kafka")

# Same topic contract as capture-agent / ARGUS (docs/architecture.md).
TOPIC_PARTITIONS = 3
TOPIC_REPLICATION = 1
TOPIC_RETENTION_MS = 21_600_000

_BACKOFF_INITIAL_S = 1.0
_BACKOFF_MAX_S = 15.0


class FusionKafka:
    def __init__(self, brokers: str, input_topic: str, scores_topic: str,
                 alerts_topic: str, engine: FusionEngine) -> None:
        self._brokers = brokers
        self.input_topic = input_topic
        self.scores_topic = scores_topic
        self.alerts_topic = alerts_topic
        self._engine = engine
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
                    group_id="guardian-fusion",
                    auto_offset_reset="latest",
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
            log.info("connected; consuming %s (group guardian-fusion)", self.input_topic)
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
                self._engine.counters["scores_dropped"] += 1
                continue
            # ingest() is defensive (self-filter, floors, staleness) and
            # never raises on malformed-but-parseable docs.
            self._engine.ingest(doc, time.time())

    async def publish(self, docs: list[dict], alerts: list[dict]) -> None:
        """Called by the ticker with whatever the engine decided to emit."""
        if self._producer is None:
            self._engine.counters["emissions_dropped"] += len(docs) + len(alerts)
            return
        try:
            for doc in docs:
                await self._producer.send(self.scores_topic, doc)
            for alert in alerts:
                await self._producer.send_and_wait(self.alerts_topic, alert)
                log.info("alert threat_level_change %s -> %s score=%.2f",
                         alert["alert"]["details"]["from"],
                         alert["alert"]["details"]["to"],
                         alert["alert"]["score"])
        except (KafkaError, OSError):
            log.exception("publish failed; emission dropped")
            self._engine.counters["emissions_dropped"] += len(docs) + len(alerts)

    async def _ensure_topics(self) -> None:
        admin = AIOKafkaAdminClient(bootstrap_servers=self._brokers)
        await admin.start()
        try:
            # input == scores in production; the set keeps creates idempotent.
            for topic in {self.input_topic, self.scores_topic, self.alerts_topic}:
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
