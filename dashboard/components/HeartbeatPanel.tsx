// Heartbeat panel (WP-B): one scorer's live vitals — is it consuming, is it
// warm, and what is it currently contributing to the fused score. Upstream
// payloads are index-signature typed, so every field is picked defensively and
// missing values render as "—".
//
// Build-time facts (model_trees, templates_mined, fit_count) are deliberately
// not rows: they never change during an incident. They ride along as tooltip
// detail on the caption instead.

import type { DriftTop, ScorerPulse, ScorerRate, SourceResult } from "@/lib/types";
import styles from "./HeartbeatPanel.module.css";

type Model = "argus" | "sentinel" | "cassandra";

interface HeartbeatPanelProps {
  model: Model;
  pulse: ScorerPulse | null; // null while the first snapshot is loading
  contribution: number | null; // fusion contributors[model]; null omits the bar
  rate: ScorerRate | null;
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

/** Scorers nest their tuning under stats.config. */
function cfg(stats: Payload, key: string): number | null {
  const c = stats?.["config"];
  if (typeof c !== "object" || c === null) return null;
  const v = (c as Record<string, unknown>)[key];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

const intFmt = new Intl.NumberFormat("en-US");

function fmtInt(n: number | null): string {
  return n === null ? "—" : intFmt.format(n);
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

function Meter({
  label,
  value,
  ratio,
  tone = "neutral",
}: {
  label: string;
  value: string;
  ratio: number | null;
  tone?: "neutral" | "warn" | "crit";
}) {
  const width = ratio === null ? 0 : Math.min(1, Math.max(0, ratio)) * 100;
  const toneClass =
    tone === "crit" ? styles.meterCrit : tone === "warn" ? styles.meterWarn : "";
  return (
    <div className={styles.meter}>
      <span className={styles.meterLabel}>{label}</span>
      <span className={styles.meterTrack} aria-hidden="true">
        <span className={`${styles.meterFill} ${toneClass}`} style={{ width: `${width}%` }} />
      </span>
      <span className={styles.meterValue}>{value}</span>
    </div>
  );
}

// Pick the payer with the highest max(cusum) from /drift/top's ranked list.
function topDrift(res: SourceResult<DriftTop> | undefined) {
  if (!res?.ok || !Array.isArray(res.data.top)) return null;
  let best: DriftTop["top"][number] | null = null;
  let bestPeak = -Infinity;
  for (const p of res.data.top) {
    const peak = Math.max(
      Number.isFinite(p.cusum_volume) ? p.cusum_volume : -Infinity,
      Number.isFinite(p.cusum_amount) ? p.cusum_amount : -Infinity,
    );
    if (peak > bestPeak) {
      bestPeak = peak;
      best = p;
    }
  }
  return best;
}

function detailTitle(model: Model, health: Payload, stats: Payload): string {
  const pick = (k: string) => num(health, k) ?? num(stats, k);
  switch (model) {
    case "argus":
      return `model fitted: ${bool(health, "model_fitted") ? "yes" : "no"} · fits: ${fmtInt(
        pick("fit_count"),
      )}`;
    case "sentinel":
      return `model loaded: ${bool(health, "model_loaded") ? "yes" : "no"} · trees: ${fmtInt(
        pick("model_trees"),
      )} · templates mined: ${fmtInt(pick("templates_mined"))}`;
    case "cassandra":
      return `k=${cfg(stats, "cusum_k") ?? "—"} · h=${cfg(stats, "cusum_h") ?? "—"} · h_single=${
        cfg(stats, "cusum_h_single") ?? "—"
      }`;
  }
}

function Body({
  model,
  pulse,
  health,
  stats,
}: {
  model: Model;
  pulse: ScorerPulse | null;
  health: Payload;
  stats: Payload;
}) {
  const pick = (key: string) => num(health, key) ?? num(stats, key);

  switch (model) {
    case "argus": {
      const observed = pick("buckets_observed");
      const warmup = pick("warmup_buckets");
      const warm = observed !== null && warmup !== null && observed >= warmup;
      return (
        <>
          <Meter
            label="warmup"
            value={warm ? "warm" : `${fmtInt(observed)}/${fmtInt(warmup)}`}
            ratio={observed !== null && warmup ? observed / warmup : null}
            tone={warm ? "neutral" : "warn"}
          />
          <div className={styles.stat}>
            <span className={styles.statLabel}>entities</span>
            <span className={styles.statValue}>{fmtInt(pick("entities_tracked"))}</span>
          </div>
        </>
      );
    }
    case "sentinel":
      return (
        <>
          <div className={styles.stat}>
            <span className={styles.statLabel}>windows scored</span>
            <span className={styles.statValue}>{fmtInt(pick("windows_scored"))}</span>
          </div>
          <div className={styles.stat}>
            <span className={styles.statLabel}>unparsed lines</span>
            <span className={styles.statValue}>{fmtInt(pick("lines_unparsed"))}</span>
          </div>
        </>
      );
    case "cassandra": {
      const tracked = pick("payers_tracked");
      const warm = pick("payers_warm");
      const drift = topDrift(pulse?.drift_top);
      const h = cfg(stats, "cusum_h") ?? 6;
      const hSingle = cfg(stats, "cusum_h_single") ?? 10;
      return (
        <>
          <Meter
            label="payers warm"
            value={`${fmtInt(warm)}/${fmtInt(tracked)}`}
            ratio={warm !== null && tracked ? warm / tracked : null}
            tone={warm !== null && tracked && warm < tracked ? "warn" : "neutral"}
          />
          {drift ? (
            <>
              <div className={styles.stat}>
                <span className={styles.statLabel}>top drift</span>
                <span className={styles.statValue} title={drift.payer_id}>
                  {drift.payer_id}
                </span>
              </div>
              <Meter
                label="cusum vol"
                value={drift.cusum_volume.toFixed(1)}
                ratio={drift.cusum_volume / hSingle}
                tone={drift.cusum_volume >= hSingle ? "crit" : "neutral"}
              />
              <Meter
                label="cusum amt"
                value={drift.cusum_amount.toFixed(1)}
                ratio={drift.cusum_amount / h}
                tone={drift.cusum_amount >= h ? "crit" : "neutral"}
              />
            </>
          ) : (
            <div className={styles.stat}>
              <span className={styles.statLabel}>top drift</span>
              <span className={styles.statValue}>—</span>
            </div>
          )}
        </>
      );
    }
  }
}

export default function HeartbeatPanel({ model, pulse, contribution, rate }: HeartbeatPanelProps) {
  const meta = META[model];
  const health = payload(pulse?.health);
  const stats = payload(pulse?.stats);
  const status = deriveStatus(pulse, health);
  const consumerDown = bool(health, "consumer_connected") === false;
  const barWidth = contribution === null ? null : Math.min(1, Math.max(0, contribution));
  const eps = rate?.eventsPerSecond ?? null;

  return (
    <div className={status === "offline" ? `${styles.card} ${styles.offline}` : styles.card}>
      <div className={styles.head}>
        <span className={styles.name}>{meta.name}</span>
        <span className={styles.status}>
          <span className={`${styles.dot} ${DOT_CLASS[status]}`} aria-hidden="true" />
          {status}
        </span>
      </div>
      <div className={styles.caption} title={detailTitle(model, health, stats)}>
        {meta.caption}
      </div>

      <div className={styles.throughput}>
        <span className={styles.eps}>{eps === null ? "—" : eps.toFixed(1)}</span>
        <span className={styles.epsUnit}>ev/s</span>
        <span className={styles.alerts}>{fmtInt(rate?.alerts ?? null)} alerts</span>
      </div>

      <div className={styles.body}>
        <Body model={model} pulse={pulse} health={health} stats={stats} />
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
