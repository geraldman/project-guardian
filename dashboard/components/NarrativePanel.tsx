// Stub — rewritten by WP-C (feat/pulse-narrative). Props are frozen contract.

import { buildNarrative } from "@/lib/narrative";
import type { NarrativePanelProps } from "@/lib/types";

export default function NarrativePanel({ snapshot }: NarrativePanelProps) {
  const report = snapshot ? buildNarrative(snapshot) : null;
  return (
    <div className="panel">
      <div className="panel-title">Incident Narrative</div>
      <div className="stub">{report?.headline ?? "awaiting first snapshot"} — pending WP-C</div>
    </div>
  );
}
