"""Kafka consumer lifecycle for the alerting service.

Background connect with retry/backoff (same pattern as capture-agent/ARGUS);
ensures guardian.alerts exists so start order vs ARGUS doesn't matter.
auto_offset_reset="latest": on a brand-new group, old queued alerts are
history, not something to page about at boot.
"""
import asyncio
import json
import logging

from aiokafka import AIOKafkaConsumer
from aiokafka.admin import AIOKafkaAdminClient, NewTopic
from aiokafka.errors import KafkaError, TopicAlreadyExistsError

from .notifier import Notifier

log = logging.getLogger("alerting.kafka")

TOPIC_PARTITIONS = 3
TOPIC_REPLICATION = 1
TOPIC_RETENTION_MS = 21_600_000

_BACKOFF_INITIAL_S = 1.0
_BACKOFF_MAX_S = 15.0


class AlertConsumer:
    def __init__(self, brokers: str, topic: str, notifier: Notifier) -> None:
        self._brokers = brokers
        self.topic = topic
        self._notifier = notifier
        self._consumer: AIOKafkaConsumer | None = None
        self._task: asyncio.Task | None = None
        self.connected = False
        self.malformed = 0

    def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    async def _run(self) -> None:
        backoff = _BACKOFF_INITIAL_S
        while True:
            try:
                await self._ensure_topic()
                consumer = AIOKafkaConsumer(
                    self.topic,
                    bootstrap_servers=self._brokers,
                    group_id="guardian-alerting",
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
            self._consumer = consumer
            self.connected = True
            log.info("connected; consuming %s", self.topic)
            try:
                async for msg in consumer:
                    try:
                        doc = json.loads(msg.value)
                        alert = doc.get("alert") or {}
                        if not isinstance(alert, dict) or not alert:
                            raise ValueError("no alert object")
                    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                        self.malformed += 1
                        continue
                    await self._notifier.process(alert)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("consume loop crashed; reconnecting")
                self.connected = False
                await self._safe_close()
                backoff = _BACKOFF_INITIAL_S

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

    async def _safe_close(self) -> None:
        if self._consumer is not None:
            try:
                await self._consumer.stop()
            except Exception:
                pass
            self._consumer = None

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self.connected = False
        await self._safe_close()
