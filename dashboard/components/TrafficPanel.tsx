"use client";

// Traffic overview — what is actually happening on the wire, from OpenSearch,
// not from browser memory. Two series only (total vs attack-flagged): the
// blue/red pair survives every CVD simulation the amber/red pair fails, and
// the story this chart tells is "attack bursts riding on steady traffic".
// Declines and errors stay in the crosshair tooltip, the totals row, and the
// heartbeat strip (ARGUS owns error anomalies as a detection signal).
//
// SVG geometry uses preserveAspectRatio="none" + non-scaling strokes (the
// Sparkline pattern); axis text lives in HTML so it never distorts.

import { useCallback, useEffect, useRef, useState } from "react";
import type { SourceResult, TrafficPanelProps, TrafficSummary, TrafficWindow } from "@/lib/types";
import styles from "./TrafficPanel.module.css";

const WINDOWS: readonly TrafficWindow[] = ["15m", "1h", "6h", "24h"];
const POLL_MS = 15_000;
const W = 760;
const H = 170;

interface ChartPoint {
  t: number;
  totalEps: number;
  attackEps: number;
  raw: { total: number; attacks: number; errors: number; declined: number };
}

function niceCeil(v: number): number {
  if (v <= 0) return 1;
  const mag = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) {
    if (v <= m * mag) return m * mag;
  }
  return 10 * mag;
}

function fmtCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 10_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

function fmtEps(n: number): string {
  return n >= 100 ? n.toFixed(0) : n >= 10 ? n.toFixed(1) : n.toFixed(2);
}

function clockLabel(t: number, window: TrafficWindow): string {
  const d = new Date(t);
  const hm = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  return window === "24h" || window === "6h" ? hm : `${hm}:${String(d.getSeconds()).padStart(2, "0")}`;
}

function toPoints(data: TrafficSummary): ChartPoint[] {
  // The trailing histogram bucket is still filling, so its rate would read as
  // a phantom dip — drop it once there is enough data for that to be safe.
  const buckets = data.buckets.length > 3 ? data.buckets.slice(0, -1) : data.buckets;
  return buckets.map((b) => ({
    t: b.t,
    totalEps: b.total / data.interval_seconds,
    attackEps: b.attacks / data.interval_seconds,
    raw: { total: b.total, attacks: b.attacks, errors: b.errors, declined: b.declined },
  }));
}

export default function TrafficPanel({ onSelect }: TrafficPanelProps) {
  const [window_, setWindow] = useState<TrafficWindow>("1h");
  const [result, setResult] = useState<SourceResult<TrafficSummary> | null>(null);
  const [hover, setHover] = useState<number | null>(null); // point index
  const plotRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setInterval> | null = null;
    async function load() {
      try {
        const res = await fetch(`/api/traffic?window=${window_}`, { cache: "no-store" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const body = (await res.json()) as SourceResult<TrafficSummary>;
        if (!cancelled) setResult(body); // previous render holds until this lands — no skeleton flash
      } catch (err) {
        if (!cancelled && result === null) {
          setResult({ ok: false, error: err instanceof Error ? err.message : String(err) });
        }
      }
    }
    load();
    timer = setInterval(load, POLL_MS);
    return () => {
      cancelled = true;
      if (timer) clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [window_]);

  const data = result?.ok ? result.data : null;
  const points = data ? toPoints(data) : [];
  const n = points.length;
  const yMax = niceCeil(Math.max(...points.map((p) => p.totalEps), 1) * 1.05);

  const px = (i: number) => (n < 2 ? W : (i / (n - 1)) * W);
  const py = (eps: number) => H - (Math.min(eps, yMax) / yMax) * H;

  const linePath = (pick: (p: ChartPoint) => number) =>
    points.map((p, i) => `${i === 0 ? "M" : "L"}${px(i).toFixed(1)},${py(pick(p)).toFixed(1)}`).join(" ");

  const areaPath =
    n > 1
      ? `${linePath((p) => p.totalEps)} L${W},${H} L0,${H} Z`
      : "";

  const onMove = useCallback(
    (e: React.MouseEvent) => {
      const el = plotRef.current;
      if (!el || n < 2) return;
      const rect = el.getBoundingClientRect();
      const frac = Math.min(Math.max((e.clientX - rect.left) / rect.width, 0), 1);
      setHover(Math.round(frac * (n - 1)));
    },
    [n],
  );

  const hovered = hover !== null && hover < n ? points[hover] : null;

  const yTicks = [0, yMax / 2, yMax];
  const xTickIdx = n > 1 ? [0, Math.floor((n - 1) / 2), n - 1] : [];

  return (
    <div className={`panel ${styles.root}`}>
      <div className={styles.head}>
        <div className="panel-title">Wire Traffic</div>
        <div className={styles.legend} aria-hidden="true">
          <span className={styles.keyTraffic} /> traffic
          <span className={styles.keyAttack} /> attack-flagged
        </div>
        <div className={styles.windows} role="tablist" aria-label="time window">
          {WINDOWS.map((w) => (
            <button
              key={w}
              role="tab"
              aria-selected={w === window_}
              className={`${styles.windowBtn} ${w === window_ ? styles.windowActive : ""}`}
              onClick={() => setWindow(w)}
            >
              {w}
            </button>
          ))}
        </div>
      </div>

      {result && !result.ok ? (
        <div className={styles.empty}>traffic history unavailable — {result.error}</div>
      ) : !data ? (
        <div className={styles.empty}>querying OpenSearch…</div>
      ) : (
        <>
          <div className={styles.chartRow}>
            <div className={styles.yAxis} aria-hidden="true">
              {yTicks
                .slice()
                .reverse()
                .map((v) => (
                  <span key={v}>{fmtEps(v)}</span>
                ))}
            </div>
            <div
              ref={plotRef}
              className={styles.plot}
              onMouseMove={onMove}
              onMouseLeave={() => setHover(null)}
            >
              <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="none" role="img"
                aria-label={`events per second over the last ${window_}, total and attack-flagged`}>
                {yTicks.slice(1).map((v) => (
                  <line key={v} x1={0} y1={py(v)} x2={W} y2={py(v)} stroke="var(--line)" strokeWidth={1}
                    vectorEffect="non-scaling-stroke" />
                ))}
                {n > 1 && <path d={areaPath} fill="var(--viz-traffic)" fillOpacity={0.1} />}
                {n > 1 && (
                  <path d={linePath((p) => p.totalEps)} fill="none" stroke="var(--viz-traffic)" strokeWidth={2}
                    strokeLinecap="round" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
                )}
                {n > 1 && (
                  <path d={linePath((p) => p.attackEps)} fill="none" stroke="var(--viz-attack)" strokeWidth={2}
                    strokeLinecap="round" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
                )}
                {hovered && (
                  <line x1={px(hover as number)} y1={0} x2={px(hover as number)} y2={H}
                    stroke="var(--text-2)" strokeWidth={1} vectorEffect="non-scaling-stroke" />
                )}
              </svg>

              {hovered && (
                <div
                  className={styles.tooltip}
                  style={{
                    left: `${((hover as number) / Math.max(n - 1, 1)) * 100}%`,
                    ["--flip" as string]: (hover as number) / Math.max(n - 1, 1) > 0.62 ? "-100%" : "0%",
                  }}
                >
                  <div className={styles.tooltipTime}>{clockLabel(hovered.t, window_)}</div>
                  <div><span className={styles.keyTraffic} /> {fmtEps(hovered.totalEps)} ev/s <span className={styles.tooltipDim}>({hovered.raw.total})</span></div>
                  <div><span className={styles.keyAttack} /> {fmtEps(hovered.attackEps)} ev/s <span className={styles.tooltipDim}>({hovered.raw.attacks})</span></div>
                  <div className={styles.tooltipDim}>errors {hovered.raw.errors} · declined {hovered.raw.declined}</div>
                </div>
              )}
            </div>
          </div>

          <div className={styles.xAxis} aria-hidden="true">
            {xTickIdx.map((i) => (
              <span key={i}>{clockLabel(points[i].t, window_)}</span>
            ))}
          </div>

          <div className={styles.totals}>
            <span>
              <b>{fmtCount(data.totals.events)}</b> events
            </span>
            <span>
              <b>{fmtCount(data.totals.attacks)}</b> attack-flagged
            </span>
            <span>
              <b>{fmtCount(data.totals.errors)}</b> errors
            </span>
            <span>
              <b>{fmtCount(data.totals.declined)}</b> declined
            </span>
          </div>

          <div className={styles.tables}>
            <TopList title="top payers" items={data.top_payers} onPick={onSelect ? (id) => onSelect("payer", id) : undefined} />
            <TopList title="top sources" items={data.top_ips} onPick={onSelect ? (id) => onSelect("client_ip", id) : undefined} />
            <TopList title="attack patterns" items={data.top_patterns} />
          </div>
        </>
      )}
    </div>
  );
}

function TopList({
  title,
  items,
  onPick,
}: {
  title: string;
  items: { key: string; count: number }[];
  onPick?: (id: string) => void;
}) {
  return (
    <div className={styles.topList}>
      <div className={styles.topTitle}>{title}</div>
      {items.length === 0 ? (
        <div className={styles.topEmpty}>none in window</div>
      ) : (
        <ul>
          {items.map((it) => (
            <li key={it.key}>
              {onPick ? (
                <button className={styles.topKey} onClick={() => onPick(it.key)} title={`open case file for ${it.key}`}>
                  {it.key}
                </button>
              ) : (
                <span className={`${styles.topKey} ${styles.topKeyStatic}`}>{it.key.replace(/_/g, " ")}</span>
              )}
              <span className={styles.topCount}>{fmtCount(it.count)}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
