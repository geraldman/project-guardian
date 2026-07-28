"use client";

// Header context strip: the pipeline's vital signs at a glance. These come from
// fusion's counters plus the client-derived scorer rates, and answer "is the
// thing actually running?" — which no panel showed before.

import { useEffect, useState } from "react";
import type { ContextStripProps, ModelName } from "@/lib/types";
import styles from "./ContextStrip.module.css";

const MODELS: readonly ModelName[] = ["argus", "sentinel", "cassandra"];

function fmtInt(n: number | null): string {
  return n === null ? "—" : new Intl.NumberFormat("en-US").format(n);
}

export default function ContextStrip({ snapshot, rates }: ContextStripProps) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const threat = snapshot?.fusion.ok ? snapshot.fusion.data : null;
  const counters = threat?.counters ?? null;

  const num = (key: string): number | null => {
    const v = counters?.[key];
    return typeof v === "number" && Number.isFinite(v) ? v : null;
  };

  // Sum only the scorers that reported a usable delta; all-unknown stays "—"
  // rather than collapsing to a misleading 0.0.
  let total: number | null = null;
  if (rates) {
    for (const m of MODELS) {
      const eps = rates[m].eventsPerSecond;
      if (eps !== null) total = (total ?? 0) + eps;
    }
  }

  const fetchedAt = snapshot ? Date.parse(snapshot.fetched_at) : NaN;
  const ageSeconds = Number.isNaN(fetchedAt) ? null : Math.max(0, Math.round((now - fetchedAt) / 1000));

  const unknown = threat?.unknown_models ?? [];

  // The alerting service's dedup counters: "sent/suppressed" is the 5-minute
  // dedup window doing its job, visible instead of implied.
  const alerting = snapshot?.alerting?.ok ? snapshot.alerting.data : null;

  return (
    <div className={styles.root}>
      <span className={styles.metric}>
        <span className={styles.value}>{total === null ? "—" : total.toFixed(1)}</span>
        <span className={styles.label}>ev/s</span>
      </span>
      <span className={styles.sep} aria-hidden="true" />
      <span className={styles.metric}>
        <span className={styles.value}>{fmtInt(threat?.entities_tracked ?? null)}</span>
        <span className={styles.label}>entities</span>
      </span>
      <span className={styles.sep} aria-hidden="true" />
      <span className={styles.metric}>
        <span className={styles.value}>{fmtInt(num("scores_folded"))}</span>
        <span className={styles.label}>folded</span>
      </span>
      <span className={styles.sep} aria-hidden="true" />
      <span className={styles.metric}>
        <span className={styles.value}>{fmtInt(num("alerts_emitted"))}</span>
        <span className={styles.label}>alerts</span>
      </span>
      {alerting && (
        <>
          <span className={styles.sep} aria-hidden="true" />
          <span
            className={styles.metric}
            title={`alert dedup: ${alerting.sent} sent, ${alerting.suppressed} suppressed by the 5-minute window`}
          >
            <span className={styles.value}>
              {fmtInt(alerting.sent)}
              <span className={styles.valueDim}>/{fmtInt(alerting.suppressed)}</span>
            </span>
            <span className={styles.label}>sent/deduped</span>
          </span>
        </>
      )}
      <span className={styles.sep} aria-hidden="true" />
      <span className={styles.metric}>
        <span className={styles.value}>{ageSeconds === null ? "—" : `${ageSeconds}s`}</span>
        <span className={styles.label}>ago</span>
      </span>
      {unknown.length > 0 && (
        <span className={styles.unknown} title={`fusion saw unweighted models: ${unknown.join(", ")}`}>
          {unknown.length} unknown model{unknown.length > 1 ? "s" : ""}
        </span>
      )}
    </div>
  );
}
