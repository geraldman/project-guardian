// Server-only upstream fetch layer (WP-0, frozen).
// Env vars come from the guardian-pulse compose block (docker-internal
// hostnames); the localhost fallbacks make `npm run dev` on the host work
// against the published ports with zero config. These URLs must never reach
// client code — the browser only ever talks to /api/*.

import type {
  DriftTop,
  FusionThreat,
  PulseSnapshot,
  ScorerHealth,
  ScorerStats,
  SourceResult,
} from "./types";

const UPSTREAM_TIMEOUT_MS = 2500;

function baseUrls() {
  return {
    fusion: process.env.FUSION_URL ?? "http://localhost:8006",
    argus: process.env.ARGUS_URL ?? "http://localhost:8002",
    sentinel: process.env.SENTINEL_URL ?? "http://localhost:8004",
    cassandra: process.env.CASSANDRA_URL ?? "http://localhost:8005",
  };
}

// Every failure mode (timeout, refused, non-2xx, bad JSON) is caught here and
// becomes { ok: false }, so one dead scorer can never sink the whole snapshot.
async function getJson<T>(url: string): Promise<SourceResult<T>> {
  try {
    const res = await fetch(url, {
      cache: "no-store",
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    return { ok: true, data: (await res.json()) as T };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

export async function fetchPulse(): Promise<PulseSnapshot> {
  const u = baseUrls();
  const [
    fusion,
    argusHealth,
    argusStats,
    sentinelHealth,
    sentinelStats,
    cassandraHealth,
    cassandraStats,
    driftTop,
  ] = await Promise.all([
    getJson<FusionThreat>(`${u.fusion}/threat`),
    getJson<ScorerHealth>(`${u.argus}/health`),
    getJson<ScorerStats>(`${u.argus}/stats`),
    getJson<ScorerHealth>(`${u.sentinel}/health`),
    getJson<ScorerStats>(`${u.sentinel}/stats`),
    getJson<ScorerHealth>(`${u.cassandra}/health`),
    getJson<ScorerStats>(`${u.cassandra}/stats`),
    getJson<DriftTop>(`${u.cassandra}/drift/top`),
  ]);

  return {
    fetched_at: new Date().toISOString(),
    fusion,
    scorers: {
      argus: { health: argusHealth, stats: argusStats },
      sentinel: { health: sentinelHealth, stats: sentinelStats },
      cassandra: { health: cassandraHealth, stats: cassandraStats, drift_top: driftTop },
    },
  };
}
