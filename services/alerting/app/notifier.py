"""Alert delivery: dedup gate → Slack and/or Discord webhooks.

With no webhook configured the formatted message goes to the container log
instead (log-only mode) — the pipeline stays fully demoable with zero secrets,
and `docker compose logs alerting` is the "inbox".

Delivery failures are logged and counted, never retried into the dedup
window: a Slack outage shouldn't turn one alert into thirty on recovery.
"""
from __future__ import annotations

import logging

import httpx

from .config import Settings
from .dedup import Deduper

log = logging.getLogger("alerting.notifier")

_SEVERITY_BADGE = {"high": "🔴", "medium": "🟠", "low": "🟡"}


def format_message(alert: dict, suppressed_prior: int) -> str:
    severity = str(alert.get("severity", "low"))
    badge = _SEVERITY_BADGE.get(severity, "🟡")
    lines = [
        f"{badge} *GUARDIAN {severity.upper()}* — {alert.get('type', 'unknown')} "
        f"({alert.get('entity_type', '?')} `{alert.get('entity_id', '?')}`)",
        str(alert.get("summary", "")).strip() or "(no summary)",
    ]
    meta = [f"source: {alert.get('source', '?')}"]
    if alert.get("score") is not None:
        meta.append(f"score: {alert['score']}")
    window = alert.get("window") or {}
    if window.get("start"):
        meta.append(f"window: {window['start']} → {window.get('end', '?')}")
    if suppressed_prior:
        meta.append(f"+{suppressed_prior} similar suppressed in the last window")
    lines.append(" | ".join(meta))
    return "\n".join(lines)


class Notifier:
    def __init__(self, cfg: Settings, deduper: Deduper) -> None:
        self.cfg = cfg
        self.deduper = deduper
        self._client = httpx.AsyncClient(timeout=cfg.webhook_timeout_seconds)
        self.delivered = 0
        self.delivery_failures = 0

    @property
    def mode(self) -> str:
        targets = [name for name, url in
                   (("slack", self.cfg.slack_webhook_url), ("discord", self.cfg.discord_webhook_url)) if url]
        return "+".join(targets) if targets else "log-only"

    async def process(self, alert: dict) -> bool:
        """Dedup-gate one alert (topic contract's `alert` object); send if it
        passes. Returns whether it was sent (vs suppressed)."""
        entity_type = str(alert.get("entity_type", "unknown"))
        entity_id = str(alert.get("entity_id", "unknown"))
        alert_type = str(alert.get("type", "unknown"))
        should_send, suppressed_prior = self.deduper.check(entity_type, entity_id, alert_type)
        if not should_send:
            log.debug("suppressed %s %s/%s", alert_type, entity_type, entity_id)
            return False
        message = format_message(alert, suppressed_prior)
        if self.cfg.slack_webhook_url:
            await self._post(self.cfg.slack_webhook_url, {"text": message}, "slack")
        if self.cfg.discord_webhook_url:
            # Discord renders markdown but not Slack's *bold*; close enough.
            await self._post(self.cfg.discord_webhook_url, {"content": message[:1900]}, "discord")
        if not (self.cfg.slack_webhook_url or self.cfg.discord_webhook_url):
            log.info("ALERT (log-only mode):\n%s", message)
            self.delivered += 1
        return True

    async def _post(self, url: str, payload: dict, target: str) -> None:
        try:
            resp = await self._client.post(url, json=payload)
            if resp.status_code // 100 == 2:
                self.delivered += 1
            else:
                self.delivery_failures += 1
                log.warning("%s webhook answered %d: %s", target, resp.status_code, resp.text[:200])
        except httpx.HTTPError as exc:
            self.delivery_failures += 1
            log.warning("%s webhook delivery failed: %s", target, exc)

    async def aclose(self) -> None:
        await self._client.aclose()
