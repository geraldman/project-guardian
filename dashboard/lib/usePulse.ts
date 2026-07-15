"use client";

// Shared polling hook (WP-0, frozen). Single consumer: app/page.tsx.
// Accumulates its own score history because fusion exposes no history endpoint.

import { useEffect, useRef, useState } from "react";
import type { PulseSnapshot, PulseStatus, ScorePoint } from "./types";

const HISTORY_LIMIT = 120;
const STALE_AFTER_INTERVALS = 3;

export function usePulse(intervalMs = 5000): {
  snapshot: PulseSnapshot | null;
  history: ScorePoint[];
  status: PulseStatus;
} {
  const [snapshot, setSnapshot] = useState<PulseSnapshot | null>(null);
  const [history, setHistory] = useState<ScorePoint[]>([]);
  const [status, setStatus] = useState<PulseStatus>("connecting");
  const lastSuccess = useRef(0);
  const inFlight = useRef(false);

  useEffect(() => {
    let cancelled = false;

    async function tick() {
      if (inFlight.current) return; // overlap guard: never stack requests
      inFlight.current = true;
      try {
        const res = await fetch("/api/pulse", { cache: "no-store" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const snap = (await res.json()) as PulseSnapshot;
        if (cancelled) return;
        lastSuccess.current = Date.now();
        setSnapshot(snap); // last good snapshot is retained on later failures
        setStatus("live");
        if (snap.fusion.ok) {
          const point: ScorePoint = {
            t: Date.now(),
            score: snap.fusion.data.anomaly_score,
            level: snap.fusion.data.threat_level,
          };
          setHistory((h) => [...h.slice(-(HISTORY_LIMIT - 1)), point]);
        }
      } catch {
        if (cancelled) return;
        if (lastSuccess.current === 0) {
          setStatus("connecting");
        } else if (Date.now() - lastSuccess.current > STALE_AFTER_INTERVALS * intervalMs) {
          setStatus("stale");
        }
      } finally {
        inFlight.current = false;
      }
    }

    tick();
    const timer = setInterval(tick, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [intervalMs]);

  return { snapshot, history, status };
}
