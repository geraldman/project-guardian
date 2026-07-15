// Transition strip (WP-A): fusion level changes this session, newest first.

import type { ThreatLevel, TransitionLogProps } from "@/lib/types";
import styles from "./TransitionLog.module.css";

const LEVEL_CLASS: Record<ThreatLevel, string> = {
  normal: styles.levelNormal,
  elevated: styles.levelElevated,
  critical: styles.levelCritical,
};

function utcTime(iso: string): string {
  const t = new Date(iso);
  return Number.isNaN(t.getTime()) ? "--:--:--" : t.toISOString().slice(11, 19);
}

export default function TransitionLog({ snapshot }: TransitionLogProps) {
  const fusion = snapshot?.fusion;
  const transitions = fusion?.ok
    ? [...fusion.data.recent_transitions].sort(
        (a, b) => (Date.parse(b.at) || 0) - (Date.parse(a.at) || 0),
      )
    : null;

  return (
    <div className="panel">
      <div className="panel-title">Transitions</div>
      {transitions === null ? (
        <div className={styles.empty}>fusion offline</div>
      ) : transitions.length === 0 ? (
        <div className={styles.empty}>no transitions this session</div>
      ) : (
        <ul className={styles.list}>
          {transitions.map((t, i) => (
            <li key={`${t.at}-${i}`} className={styles.row}>
              <span className={styles.time}>{utcTime(t.at)}</span>
              <span className={`${styles.levelBadge} ${LEVEL_CLASS[t.from]}`}>{t.from}</span>
              <span className={styles.arrow}>→</span>
              <span className={`${styles.levelBadge} ${LEVEL_CLASS[t.to]}`}>{t.to}</span>
              <span className={styles.score}>{t.score.toFixed(3)}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
