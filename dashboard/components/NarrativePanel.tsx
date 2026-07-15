// Incident narrative panel (WP-C): renders the deterministic template
// narrative for the current snapshot. Template-based, not generative — see
// lib/narrative.

import { buildNarrative } from "@/lib/narrative";
import type { NarrativePanelProps, ThreatLevel } from "@/lib/types";
import styles from "./NarrativePanel.module.css";

const HEADLINE_CLASS: Record<ThreatLevel, string> = {
  normal: styles.headlineNormal,
  elevated: styles.headlineElevated,
  critical: styles.headlineCritical,
};

export default function NarrativePanel({ snapshot }: NarrativePanelProps) {
  if (snapshot === null) {
    return (
      <div className="panel">
        <div className="panel-title">Incident Narrative</div>
        <div className={styles.empty}>awaiting first snapshot</div>
      </div>
    );
  }

  const report = buildNarrative(snapshot);
  const headlineClass = snapshot.fusion.ok
    ? HEADLINE_CLASS[snapshot.fusion.data.threat_level]
    : styles.headlineOffline;

  return (
    <div className={`panel ${styles.root}`}>
      <div className="panel-title">Incident Narrative</div>
      <p className={`${styles.headline} ${headlineClass}`}>{report.headline}</p>
      {report.paragraphs.map((p, i) => (
        <p key={i} className={styles.para}>
          {p}
        </p>
      ))}
      {report.bullets.length > 0 && (
        <ul className={styles.bullets}>
          {report.bullets.map((b, i) => (
            <li key={i}>{b}</li>
          ))}
        </ul>
      )}
      <div className={styles.footer}>template narrative — deterministic, not generative</div>
    </div>
  );
}
