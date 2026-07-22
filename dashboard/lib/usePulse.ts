"use client";

// Shared polling hook (WP-0, frozen). Single consumer: app/page.tsx.
// Accumulates its own score history because fusion exposes no history endpoint.

import { useEffect, useRef, useState } from "react";
import type {
  ModelName,
  PulseSnapshot,
  PulseStatus,
  ScorePoint,
  ScorerRates,
} from "./types";

const HISTORY_LIMIT = 120;
const STALE_AFTER_INTERVALS = 3;
const MODELS: readonly ModelName[] = ["argus", "sentinel", "cassandra"];

function counter(snap: PulseSnapshot, model: ModelName, key: string): number | null {
  const stats = snap.scorers[model].stats;
  if (!stats.ok) return null;
  const v = (stats.data as Record<string, unknown>)[key];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/** Cumulative counters -> per-second rates. A negative delta means the scorer
 *  restarted and its counters reset, so the rate is reported as unknown rather
 *  than as a nonsensical negative. */
function deriveRates(
  prev: { at: number; consumed: Record<ModelName, number | null> } | null,
  snap: PulseSnapshot,
  at: number,
): ScorerRates {
  const dt = prev ? (at - prev.at) / 1000 : 0;
  const out = {} as ScorerRates;
  for (const m of MODELS) {
    const now = counter(snap, m, "events_consumed");
    const before = prev?.consumed[m] ?? null;
    let eps: number | null = null;
    if (now !== null && before !== null && dt > 0 && now >= before) {
      eps = (now - before) / dt;
    }
    out[m] = { eventsPerSecond: eps, alerts: counter(snap, m, "alerts_emitted") };
  }
  return out;
}

export function usePulse(intervalMs = 5000): {
  snapshot: PulseSnapshot | null;
  history: ScorePoint[];
  status: PulseStatus;
  rates: ScorerRates | null;
} {
  const [snapshot, setSnapshot] = useState<PulseSnapshot | null>(null);
  const [history, setHistory] = useState<ScorePoint[]>([]);
  const [status, setStatus] = useState<PulseStatus>("connecting");
  const [rates, setRates] = useState<ScorerRates | null>(null);
  const lastSuccess = useRef(0);
  const inFlight = useRef(false);
  const prevCounters = useRef<{ at: number; consumed: Record<ModelName, number | null> } | null>(
    null,
  );

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
        const at = Date.now();
        lastSuccess.current = at;
        setSnapshot(snap); // last good snapshot is retained on later failures
        setStatus("live");
        setRates(deriveRates(prevCounters.current, snap, at));
        prevCounters.current = {
          at,
          consumed: {
            argus: counter(snap, "argus", "events_consumed"),
            sentinel: counter(snap, "sentinel", "events_consumed"),
            cassandra: counter(snap, "cassandra", "events_consumed"),
          },
        };
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

  return { snapshot, history, status, rates };
}
