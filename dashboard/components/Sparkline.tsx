// Hand-rolled SVG sparkline of fusion score history (WP-A, no chart library).
// Fixed 0..1 y-domain: threshold guides stay meaningful and the scale never
// jumps between polls. Latest value is also rendered as text.
//
// The hysteresis thresholds are drawn as labeled, status-colored reference
// lines (dashed on purpose — dashing is the threshold idiom, the solid line
// is the data), so a viewer can see WHY the level flipped at the moment the
// score crossed one. Labels are HTML, not SVG text: the svg stretches with
// preserveAspectRatio="none", which would distort glyphs.

import type { ScorePoint } from "@/lib/types";

interface SparklineProps {
  points: ScorePoint[];
  thresholds?: { elevated: number; critical: number };
}

const W = 300;
const H = 56;
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
  const guides = thresholds
    ? [
        { value: thresholds.critical, color: "var(--level-critical)", label: "crit" },
        { value: thresholds.elevated, color: "var(--level-elevated)", label: "elev" },
      ]
    : [];
  const dot = last ? `M${x(n - 1, n).toFixed(1)},${y(last.score).toFixed(1)} h0` : "";

  return (
    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
      <div style={{ position: "relative", flex: 1, minWidth: 0 }}>
        <svg
          viewBox={`0 0 ${W} ${H}`}
          width="100%"
          height={H}
          preserveAspectRatio="none"
          role="img"
          aria-label="fusion anomaly score history against the elevated and critical thresholds"
          style={{ display: "block" }}
        >
          {guides.map((g) => (
            <line key={g.label} x1={PAD} y1={y(g.value)} x2={W - PAD} y2={y(g.value)}
              stroke={g.color} strokeOpacity={0.55} strokeDasharray="3 5"
              vectorEffect="non-scaling-stroke" />
          ))}
          {n > 1 && (
            <path d={path} fill="none" stroke="var(--accent)" strokeWidth={2}
              strokeLinecap="round" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
          )}
          {/* end marker: zero-length round-cap strokes give an undistorted dot with a 2px surface ring */}
          {last && <path d={dot} stroke="var(--bg-0)" strokeWidth={12} strokeLinecap="round" vectorEffect="non-scaling-stroke" />}
          {last && <path d={dot} stroke="var(--accent)" strokeWidth={8} strokeLinecap="round" vectorEffect="non-scaling-stroke" />}
        </svg>
        {guides.map((g) => (
          <span
            key={g.label}
            aria-hidden="true"
            style={{
              position: "absolute",
              right: 0,
              top: `${(y(g.value) / H) * 100}%`,
              transform: "translateY(-100%)",
              fontSize: "9px",
              lineHeight: 1.4,
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              color: "var(--text-2)",
              pointerEvents: "none",
            }}
          >
            {g.label} {g.value}
          </span>
        ))}
      </div>
      {last && (
        <span style={{ color: "var(--text-1)", fontSize: "12px", whiteSpace: "nowrap" }}>
          {last.score.toFixed(3)}
        </span>
      )}
    </div>
  );
}
