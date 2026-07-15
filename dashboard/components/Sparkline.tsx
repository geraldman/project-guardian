// Hand-rolled SVG sparkline of fusion score history (WP-A, no chart library).
// Fixed 0..1 y-domain: threshold guides stay meaningful and the scale never
// jumps between polls. Latest value is also rendered as text.

import type { ScorePoint } from "@/lib/types";

interface SparklineProps {
  points: ScorePoint[];
  thresholds?: { elevated: number; critical: number };
}

const W = 300;
const H = 48;
const PAD = 5;

function x(i: number, n: number): number {
  return n < 2 ? W - PAD : PAD + (i / (n - 1)) * (W - 2 * PAD);
}

function y(score: number): number {
  return H - PAD - Math.min(1, Math.max(0, score)) * (H - 2 * PAD);
}

export default function Sparkline({ points, thresholds }: SparklineProps) {
  const n = points.length;
  const last = n > 0 ? points[n - 1] : null;
  const path = points
    .map((p, i) => `${i === 0 ? "M" : "L"}${x(i, n).toFixed(1)},${y(p.score).toFixed(1)}`)
    .join(" ");
  const guides = thresholds ? [thresholds.elevated, thresholds.critical] : [];
  const dot = last ? `M${x(n - 1, n).toFixed(1)},${y(last.score).toFixed(1)} h0` : "";

  return (
    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        height={H}
        preserveAspectRatio="none"
        role="img"
        aria-label="fusion anomaly score history"
      >
        {guides.map((g, i) => (
          <line key={i} x1={PAD} y1={y(g)} x2={W - PAD} y2={y(g)} stroke="var(--text-2)"
            strokeOpacity={0.4} strokeDasharray="3 5" vectorEffect="non-scaling-stroke" />
        ))}
        {n > 1 && (
          <path d={path} fill="none" stroke="var(--accent)" strokeWidth={2}
            strokeLinecap="round" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
        )}
        {/* end marker: zero-length round-cap strokes give an undistorted dot with a 2px surface ring */}
        {last && <path d={dot} stroke="var(--bg-1)" strokeWidth={12} strokeLinecap="round" vectorEffect="non-scaling-stroke" />}
        {last && <path d={dot} stroke="var(--accent)" strokeWidth={8} strokeLinecap="round" vectorEffect="non-scaling-stroke" />}
      </svg>
      {last && (
        <span style={{ color: "var(--text-1)", fontSize: "12px", whiteSpace: "nowrap" }}>
          {last.score.toFixed(3)}
        </span>
      )}
    </div>
  );
}
