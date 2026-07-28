"use client";

// Alert feed — the emitted alert stream from guardian-alerts-*, newest first.
// This is what the detectors and fusion actually raised (pre-dedup); the
// context strip's sent/deduped counters tell the delivery half. Entities in
// the feed open the same case-file drawer as everywhere else, so an alert is
// two clicks from its evidence.

import { useEffect, useState } from "react";
import type { AlertFeedData, AlertItem, SourceResult } from "@/lib/types";
import styles from "./AlertFeed.module.css";

const POLL_MS = 10_000;
const LIMIT = 30;

// Model identity hues (same vocabulary as the Top Entities badges); fusion's
// meta-alerts ride the neutral ink. Severity is carried by the row's edge.
const SOURCE_CLASS: Record<string, string> = {
  argus: styles.srcArgus,
  sentinel: styles.srcSentinel,
  cassandra: styles.srcCassandra,
  guardian: styles.srcGuardian,
};

const SEVERITY_CLASS: Record<string, string> = {
  high: styles.sevHigh,
  medium: styles.sevMedium,
  low: styles.sevLow,
};

function clock(iso: string): string {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? "—" : new Date(t).toLocaleTimeString("en-GB");
}

interface AlertFeedProps {
  onSelect?: (entityType: string, entityId: string) => void;
}

function AlertRow({ alert, onSelect }: { alert: AlertItem; onSelect?: AlertFeedProps["onSelect"] }) {
  const drillable =
    onSelect !== undefined &&
    alert.entity_id !== null &&
    (alert.entity_type === "payer" || alert.entity_type === "client_ip");
  return (
    <li
      className={`${styles.row} ${SEVERITY_CLASS[alert.severity] ?? styles.sevLow}`}
      title={alert.summary ?? undefined}
    >
      <div className={styles.line}>
        <span className={styles.time}>{clock(alert.t)}</span>
        <span className={`${styles.source} ${SOURCE_CLASS[alert.source] ?? styles.srcGuardian}`}>
          {alert.source}
        </span>
        <span className={styles.type}>{alert.type.replace(/_/g, " ")}</span>
      </div>
      {alert.entity_id && (
        <div className={styles.line}>
          {drillable ? (
            <button
              className={styles.entity}
              onClick={() => onSelect?.(alert.entity_type as string, alert.entity_id as string)}
              title={`open case file for ${alert.entity_id}`}
            >
              {alert.entity_id}
            </button>
          ) : (
            <span className={styles.entityStatic}>{alert.entity_id}</span>
          )}
          {alert.score !== null && <span className={styles.score}>{alert.score.toFixed(2)}</span>}
        </div>
      )}
    </li>
  );
}

export default function AlertFeed({ onSelect }: AlertFeedProps) {
  const [result, setResult] = useState<SourceResult<AlertFeedData> | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const res = await fetch(`/api/alerts?limit=${LIMIT}`, { cache: "no-store" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const body = (await res.json()) as SourceResult<AlertFeedData>;
        if (!cancelled) setResult(body); // last good render holds on later failures
      } catch (err) {
        if (!cancelled) {
          setResult((prev) =>
            prev?.ok ? prev : { ok: false, error: err instanceof Error ? err.message : String(err) },
          );
        }
      }
    }
    load();
    const timer = setInterval(load, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  const data = result?.ok ? result.data : null;

  return (
    <div className={`panel ${styles.root}`}>
      <div className={styles.head}>
        <div className="panel-title">Alert Feed</div>
        {data && <span className={styles.count}>{data.total_24h} in 24h</span>}
      </div>

      {result && !result.ok ? (
        <div className={styles.empty}>alert history unavailable — {result.error}</div>
      ) : !data ? (
        <div className={styles.empty}>querying OpenSearch…</div>
      ) : data.alerts.length === 0 ? (
        <div className={styles.empty}>no alerts in the last 24h</div>
      ) : (
        <ol className={styles.list}>
          {data.alerts.map((a, i) => (
            <AlertRow key={a.id || `${a.t}-${i}`} alert={a} onSelect={onSelect} />
          ))}
        </ol>
      )}
    </div>
  );
}
