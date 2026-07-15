// Stub — rewritten by WP-B (feat/pulse-heartbeats). Props are frozen contract.

import type { HeartbeatRowProps } from "@/lib/types";

const MODELS = ["argus", "sentinel", "cassandra"] as const;

export default function HeartbeatRow({ snapshot }: HeartbeatRowProps) {
  return (
    <div className="panel">
      <div className="panel-title">Model Heartbeats</div>
      {MODELS.map((m) => (
        <div key={m} className="stub">
          {m}: {snapshot?.scorers[m].health.ok ? "reachable" : "offline"} — pending WP-B
        </div>
      ))}
    </div>
  );
}
