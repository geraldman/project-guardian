"use client";

// WP-D: one-click Freeze-to-PDF compliance snapshot.
// On click the live snapshot + history are deep-cloned (the FREEZE — later
// polls never touch the clones), a deterministic narrative is computed, and
// the print-only report is portalled to document.body. The portal target is
// load-bearing: the report must live OUTSIDE .hud-root, because print.css
// hides .hud-root with display:none and descendants of a display:none subtree
// can never be made visible again.

import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { buildNarrative } from "@/lib/narrative";
import SnapshotReport from "./SnapshotReport";
import type {
  FreezeButtonProps,
  NarrativeReport,
  PulseSnapshot,
  ScorePoint,
} from "@/lib/types";

interface FrozenCapture {
  snapshot: PulseSnapshot;
  history: ScorePoint[];
  narrative: NarrativeReport;
}

export default function FreezeButton({ snapshot, history }: FreezeButtonProps) {
  const [frozen, setFrozen] = useState<FrozenCapture | null>(null);

  function freeze() {
    if (snapshot === null) return;
    const frozenSnapshot = structuredClone(snapshot);
    const frozenHistory = structuredClone(history);
    setFrozen({
      snapshot: frozenSnapshot,
      history: frozenHistory,
      narrative: buildNarrative(frozenSnapshot),
    });
  }

  // Runs after the report has been committed to the DOM; one rAF later the
  // layout is flushed and the browser print dialog captures the report.
  useEffect(() => {
    if (frozen === null) return;

    const originalTitle = document.title;
    let printed = false;

    const restore = () => {
      document.title = originalTitle;
      setFrozen(null); // a later manual Ctrl+P must not print a stale report
    };
    window.addEventListener("afterprint", restore);

    const raf = requestAnimationFrame(() => {
      // Colons/dots are illegal in Windows filenames; a sanitized ISO stamp
      // keeps the browser's default PDF filename valid and audit-friendly.
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      document.title = `guardian-pulse-snapshot-${stamp}`;
      printed = true;
      window.print();
    });

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("afterprint", restore);
      if (printed) document.title = originalTitle;
    };
  }, [frozen]);

  return (
    <div className="panel">
      <div className="panel-title">Compliance Snapshot</div>
      <button
        type="button"
        onClick={freeze}
        disabled={snapshot === null}
        style={{
          display: "block",
          width: "100%",
          padding: "12px 16px",
          font: "inherit",
          fontSize: "15px",
          fontWeight: 600,
          letterSpacing: "0.04em",
          color: snapshot === null ? "var(--text-2)" : "var(--bg-0)",
          background: snapshot === null ? "var(--bg-2)" : "var(--accent)",
          border: "1px solid var(--line)",
          borderRadius: "var(--radius)",
          cursor: snapshot === null ? "not-allowed" : "pointer",
        }}
      >
        Freeze to PDF
      </button>
      <p style={{ marginTop: "8px", fontSize: "12px", color: "var(--text-2)" }}>
        {snapshot === null
          ? "Waiting for first snapshot…"
          : "Captures the current state and opens the print dialog — choose “Save as PDF”."}
      </p>
      {frozen !== null &&
        createPortal(
          <div className="print-only">
            <SnapshotReport
              snapshot={frozen.snapshot}
              history={frozen.history}
              narrative={frozen.narrative}
            />
          </div>,
          document.body,
        )}
    </div>
  );
}
