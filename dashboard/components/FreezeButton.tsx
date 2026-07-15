// Stub — rewritten by WP-D (feat/pulse-freeze). Props are frozen contract.

import type { FreezeButtonProps } from "@/lib/types";

export default function FreezeButton({ snapshot, history }: FreezeButtonProps) {
  return (
    <div className="panel">
      <div className="panel-title">Compliance Snapshot</div>
      <div className="stub">
        freeze-to-PDF ({history.length} samples{snapshot ? "" : ", no snapshot"}) — pending WP-D
      </div>
    </div>
  );
}
