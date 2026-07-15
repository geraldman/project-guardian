"use client";

// Hero threat panel (WP-A): fusion level lamp, decayed score gauge with
// threshold ticks, "in this state for" ticker and score-history sparkline.

import { useEffect, useState } from "react";
import type { ThreatIndicatorProps, ThreatLevel } from "@/lib/types";
import Sparkline from "./Sparkline";
import styles from "./ThreatIndicator.module.css";

const LEVEL_CLASS: Record<ThreatLevel, string> = {
  normal: styles.levelNormal,
  elevated: styles.levelElevated,
  critical: styles.levelCritical,
};

function formatDuration(totalSeconds: number): string {
  const s = Math.max(0, Math.floor(totalSeconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h > 0) return `${h}h ${String(m).padStart(2, "0")}m`;
  if (m > 0) return `${m}m ${String(s % 60).padStart(2, "0")}s`;
  return `${s}s`;
}

export default function ThreatIndicator({ snapshot, history, status }: ThreatIndicatorProps) {
  const fusion = snapshot?.fusion;
  const threat = fusion?.ok ? fusion.data : null;
  const levelSince = threat?.level_since ?? null;
  const [elapsed, setElapsed] = useState<number | null>(null);

  useEffect(() => {
    const started = levelSince ? Date.parse(levelSince) : NaN;
    if (Number.isNaN(started)) {
      setElapsed(null);
      return;
    }
    const update = () => setElapsed((Date.now() - started) / 1000);
    update();
    const timer = setInterval(update, 1000);
    return () => clearInterval(timer);
  }, [levelSince]);

  const thresholds = threat?.config.thresholds;
  const score = threat ? Math.min(1, Math.max(0, threat.anomaly_score)) : 0;

  return (
    <div className={`panel ${styles.root}`}>
      <div className={styles.head}>
        <div className="panel-title">Threat Level</div>
        {status === "stale" && <span className={`${styles.badge} ${styles.badgeStale}`}>STALE</span>}
        {status === "connecting" && (
          <span className={`${styles.badge} ${styles.badgeConnecting}`}>CONNECTING</span>
        )}
      </div>

      {threat ? (
        <>
          <div className={`${styles.lamp} ${LEVEL_CLASS[threat.threat_level]}`}>
            <span
              className={`${styles.lampDot} ${threat.threat_level !== "normal" ? styles.lampPulse : ""}`}
            />
            <span className={styles.lampLabel}>{threat.threat_level.toUpperCase()}</span>
          </div>
          <div className={styles.score}>{threat.anomaly_score.toFixed(3)}</div>
          <div className={`${styles.gauge} ${LEVEL_CLASS[threat.threat_level]}`}>
            <div className={styles.gaugeTrack}>
              <span className={styles.gaugeFill} style={{ width: `${score * 100}%` }} />
              {thresholds && (
                <>
                  <span
                    className={styles.gaugeTick}
                    style={{ left: `${thresholds.elevated_up * 100}%` }}
                  />
                  <span
                    className={styles.gaugeTick}
                    style={{ left: `${thresholds.critical_up * 100}%` }}
                  />
                </>
              )}
            </div>
            {thresholds && (
              <div className={styles.gaugeScale}>
                <span className={styles.gaugeScaleMin}>0</span>
                <span style={{ left: `${thresholds.elevated_up * 100}%` }}>
                  {thresholds.elevated_up}
                </span>
                <span style={{ left: `${thresholds.critical_up * 100}%` }}>
                  {thresholds.critical_up}
                </span>
                <span className={styles.gaugeScaleMax}>1</span>
              </div>
            )}
          </div>
          <div className={styles.ticker}>
            {elapsed !== null ? `in this state for ${formatDuration(elapsed)}` : " "}
          </div>
        </>
      ) : (
        <div className={`${styles.lamp} ${styles.offline}`}>
          <span className={styles.lampDot} />
          <span className={styles.lampLabel}>FUSION OFFLINE</span>
          <span className={styles.offlineDetail}>
            {fusion && !fusion.ok ? fusion.error : "awaiting first snapshot"}
          </span>
        </div>
      )}

      <div className={styles.spark}>
        <div className={styles.sparkLabel}>score history</div>
        {history.length > 0 ? (
          <Sparkline
            points={history}
            thresholds={
              thresholds
                ? { elevated: thresholds.elevated_up, critical: thresholds.critical_up }
                : undefined
            }
          />
        ) : (
          <div className={styles.sparkEmpty}>collecting history…</div>
        )}
      </div>
    </div>
  );
}
