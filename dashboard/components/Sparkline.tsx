// Stub — rewritten by WP-A (feat/pulse-threat): hand-rolled SVG sparkline of
// ScorePoint history (no chart library).

import type { ScorePoint } from "@/lib/types";

export default function Sparkline({ points }: { points: ScorePoint[] }) {
  return <svg width="100%" height="40" data-points={points.length} />;
}
