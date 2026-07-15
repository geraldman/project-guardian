// Heartbeat panel (WP-B): one scorer's live vitals — status, key stats, and
// its current contribution to the fused threat score. Upstream payloads are
// index-signature typed, so every field is picked defensively and missing
// values render as "—".

import type { DriftTop, ScorerPulse, SourceResult } from "@/lib/types";
import styles from "./HeartbeatPanel.module.css";

type Model = "argus" | "sentinel" | "cassandra";

interface HeartbeatPanelProps {
  model: Model;
  pulse: ScorerPulse | null; // null while the first snapshot is loading
  contribution: number | null; // fusion contributors[model]; null omits the bar
}

const META: Record<Model, { name: string; caption: string }> = {
  argus: { name: "ARGUS", caption: "statistical anomaly" },
  sentinel: { name: "SENTINEL", caption: "behavioral ML" },
  cassandra: { name: "CASSANDRA", caption: "drift / CUSUM" },
};

type Payload = Record<string, unknown> | null;

function payload<T>(res: SourceResult<T> | undefined): Payload {
  return res?.ok ? (res.data as Record<string, unknown>) : null;
}

function num(obj: Payload, key: string): number | null {
  const v = obj?.[key];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function bool(obj: Payload, key: string): boolean | null {
  const v = obj?.[key];
  return typeof v === "boolean" ? v : null;
}

const intFmt = new Intl.NumberFormat("en-US");

function fmtInt(n: number | null): string {
  return n === null ? "—" : intFmt.format(n);
}

function fmtFixed(n: number | null): string {
  return n === null ? "—" : n.toFixed(2);
}

function fmtBool(b: boolean | null): string {
  return b === null ? "—" : b ? "yes" : "no";
}

type PanelStatus = "loading" | "offline" | "ok" | "warming" | "degraded" | "error";

function deriveStatus(pulse: ScorerPulse | null, health: Payload): PanelStatus {
  if (pulse === null) return "loading";
  if (!pulse.health.ok) return "offline";
  const status = health?.["status"];
  if (status === "ok") return bool(health, "warming_up") === true ? "warming" : "ok";
  if (status === "degraded") return "degraded";
  return "error";
}

const DOT_CLASS: Record<PanelStatus, string> = {
  loading: styles.dotOffline,
  offline: styles.dotOffline,
  ok: styles.dotOk,
  warming: styles.dotWarn,
  degraded: styles.dotWarn,
  error: styles.dotError,
};

interface TopDrift {
  payer: string;
  volume: number | null;
  amount: number | null;
  elevated: number | null;
}

// Pick the payer with the highest max(cusum) from /drift/top's ranked list.
function topDrift(res: SourceResult<DriftTop> | undefined): TopDrift | null {
  if (!res?.ok || !Array.isArray(res.data.top)) return null;
  let best: TopDrift | null = null;
  let bestPeak = -Infinity;
  for (const p of res.data.top) {
    const volume = Number.isFinite(p.cusum_volume) ? p.cusum_volume : null;
    const amount = Number.isFinite(p.cusum_amount) ? p.cusum_amount : null;
    if (volume === null && amount === null) continue;
    const peak = Math.max(volume ?? -Infinity, amount ?? -Infinity);
    if (peak > bestPeak) {
      bestPeak = peak;
      best = {
        payer: p.payer_id,
        volume,
        amount,
        elevated: Number.isFinite(p.buckets_elevated) ? p.buckets_elevated : null,
      };
    }
  }
  return best;
}

interface Row {
  label: string;
  value: string;
}

function rowsFor(model: Model, pulse: ScorerPulse | null, health: Payload, stats: Payload): Row[] {
  const pick = (key: string) => num(health, key) ?? num(stats, key);
  switch (model) {
    case "argus": {
      const observed = num(health, "buckets_observed");
      return [
        {
          label: "buckets observed",
          value: observed === null ? "—" : `${fmtInt(observed)} / ${fmtInt(num(health, "warmup_buckets"))}`,
        },
        { label: "model fitted", value: fmtBool(bool(health, "model_fitted")) },
      ];
    }
    case "sentinel":
      return [
        { label: "model loaded", value: fmtBool(bool(health, "model_loaded")) },
        { label: "model trees", value: fmtInt(pick("model_trees")) },
        { label: "windows scored", value: fmtInt(pick("windows_scored")) },
        { label: "templates mined", value: fmtInt(pick("templates_mined")) },
      ];
    case "cassandra": {
      const drift = topDrift(pulse?.drift_top);
      const rows: Row[] = [
        { label: "payers tracked", value: fmtInt(pick("payers_tracked")) },
        { label: "payers warm", value: fmtInt(pick("payers_warm")) },
        { label: "top drift", value: drift === null ? "—" : drift.payer },
      ];
      if (drift !== null) {
        rows.push({
          label: "cusum vol / amt / elev",
          value: `${fmtFixed(drift.volume)} / ${fmtFixed(drift.amount)} / ${fmtInt(drift.elevated)}`,
        });
      }
      return rows;
    }
  }
}

export default function HeartbeatPanel({ model, pulse, contribution }: HeartbeatPanelProps) {
  const meta = META[model];
  const health = payload(pulse?.health);
  const stats = payload(pulse?.stats);
  const status = deriveStatus(pulse, health);
  const consumerDown = bool(health, "consumer_connected") === false;
  const barWidth = contribution === null ? null : Math.min(1, Math.max(0, contribution));

  return (
    <div className={status === "offline" ? `${styles.card} ${styles.offline}` : styles.card}>
      <div className={styles.head}>
        <span className={styles.name}>{meta.name}</span>
        <span className={styles.caption}>{meta.caption}</span>
        <span className={styles.status}>
          <span className={`${styles.dot} ${DOT_CLASS[status]}`} aria-hidden="true" />
          {status}
        </span>
      </div>
      <div className={styles.rows}>
        {rowsFor(model, pulse, health, stats).map((r) => (
          <div key={r.label} className={styles.row}>
            <span className={styles.rowLabel}>{r.label}</span>
            <span className={styles.rowValue}>{r.value}</span>
          </div>
        ))}
      </div>
      {consumerDown && <div className={styles.warnLine}>consumer disconnected</div>}
      {contribution !== null && barWidth !== null && (
        <div className={styles.contrib}>
          <span className={styles.contribLabel}>fusion contrib</span>
          <span className={styles.track} aria-hidden="true">
            <span className={styles.fill} style={{ width: `${barWidth * 100}%` }} />
          </span>
          <span className={styles.contribValue}>{contribution.toFixed(2)}</span>
        </div>
      )}
    </div>
  );
}
