// Stub — rewritten by WP-D (feat/pulse-freeze): the print-only compliance
// report rendered from a frozen PulseSnapshot + NarrativeReport.

import type { NarrativeReport, PulseSnapshot, ScorePoint } from "@/lib/types";

export default function SnapshotReport({
  snapshot,
  narrative,
}: {
  snapshot: PulseSnapshot;
  history: ScorePoint[];
  narrative: NarrativeReport;
}) {
  return (
    <div className="print-only">
      {narrative.headline} · {snapshot.fetched_at}
    </div>
  );
}
