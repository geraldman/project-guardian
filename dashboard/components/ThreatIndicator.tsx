// Stub — rewritten by WP-A (feat/pulse-threat). Props are frozen contract.

import type { ThreatIndicatorProps } from "@/lib/types";

export default function ThreatIndicator({ snapshot, history, status }: ThreatIndicatorProps) {
  const fusion = snapshot?.fusion;
  return (
    <div className="panel">
      <div className="panel-title">Threat Level</div>
      <div className="stub">
        {fusion?.ok
          ? `${fusion.data.threat_level} · score ${fusion.data.anomaly_score.toFixed(3)}`
          : `fusion offline · ${status} · ${history.length} samples`}
        {" — pending WP-A"}
      </div>
    </div>
  );
}
