// Heartbeat column (WP-B): one panel per scorer, fed from the shared
// snapshot. Props are frozen contract (lib/types.ts HeartbeatRowProps).

import type { HeartbeatRowProps } from "@/lib/types";
import HeartbeatPanel from "./HeartbeatPanel";
import styles from "./HeartbeatPanel.module.css";

const MODELS = ["argus", "sentinel", "cassandra"] as const;

export default function HeartbeatRow({ snapshot }: HeartbeatRowProps) {
  const contributors = snapshot?.fusion.ok ? snapshot.fusion.data.contributors : null;
  return (
    <div className="panel">
      <div className="panel-title">Model Heartbeats</div>
      <div className={styles.stack}>
        {MODELS.map((m) => {
          const raw = contributors?.[m];
          return (
            <HeartbeatPanel
              key={m}
              model={m}
              pulse={snapshot ? snapshot.scorers[m] : null}
              contribution={typeof raw === "number" && Number.isFinite(raw) ? raw : null}
            />
          );
        })}
      </div>
    </div>
  );
}
