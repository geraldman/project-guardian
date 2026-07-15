// Test fixtures for the narrative engine (WP-C). Shapes mirror lib/types.ts,
// which in turn mirrors fusion's snapshot() and the scorers' endpoints.

import type {
  FusionThreat,
  PulseSnapshot,
  ScorerHealth,
  ScorerPulse,
  SourceResult,
} from "../types";

const FETCHED_AT = "2026-07-15T04:00:00.000Z";

type ScorerName = "argus" | "sentinel" | "cassandra";

function okHealth(service: string): SourceResult<ScorerHealth> {
  return { ok: true, data: { status: "ok", service, consumer_connected: true } };
}

function scorer(service: string): ScorerPulse {
  return { health: okHealth(service), stats: { ok: true, data: {} } };
}

function offlineScorer(): ScorerPulse {
  return {
    health: { ok: false, error: "fetch failed" },
    stats: { ok: false, error: "fetch failed" },
  };
}

export function baseThreat(overrides: Partial<FusionThreat> = {}): FusionThreat {
  return {
    threat_level: "normal",
    anomaly_score: 0.02,
    is_anomalous: false,
    level_since: "2026-07-15T03:00:00Z",
    contributors: {},
    corroboration: 0,
    reasons: [],
    top_entities: [],
    recent_transitions: [],
    entities_tracked: 42,
    unknown_models: [],
    counters: {},
    config: {
      weights: { argus: 1, sentinel: 1, cassandra: 1, default: 0.6 },
      half_life_seconds: 300,
      corroboration_boost: 0.15,
      breadth_weight: 0.1,
      min_contrib_events: 3,
      thresholds: {
        elevated_up: 0.45,
        elevated_down: 0.35,
        critical_up: 0.7,
        critical_down: 0.55,
      },
    },
    ...overrides,
  };
}

export function snapshotWith(
  threat: FusionThreat | null,
  opts: { offline?: ScorerName[] } = {},
): PulseSnapshot {
  const offline = new Set(opts.offline ?? []);
  const s = (name: ScorerName) => (offline.has(name) ? offlineScorer() : scorer(name));
  return {
    fetched_at: FETCHED_AT,
    fusion: threat === null ? { ok: false, error: "fetch failed" } : { ok: true, data: threat },
    scorers: { argus: s("argus"), sentinel: s("sentinel"), cassandra: s("cassandra") },
  };
}

export const QUIET = snapshotWith(baseThreat());

export const ELEVATED_SINGLE = snapshotWith(
  baseThreat({
    threat_level: "elevated",
    anomaly_score: 0.52,
    is_anomalous: true,
    level_since: "2026-07-15T03:58:00Z",
    contributors: { argus: 0.61 },
    corroboration: 1,
    reasons: ["argus:rate_spike"],
    top_entities: [
      {
        entity_type: "ip",
        entity_id: "10.9.8.7",
        score: 0.61,
        models: { argus: 0.61 },
        corroborated: false,
        reasons: ["argus:rate_spike"],
        last_update: "2026-07-15T03:59:30Z",
      },
    ],
    recent_transitions: [
      { at: "2026-07-15T03:58:00Z", from: "normal", to: "elevated", score: 0.47 },
    ],
  }),
);

export const CRITICAL_CORROBORATED = snapshotWith(
  baseThreat({
    threat_level: "critical",
    anomaly_score: 0.83,
    is_anomalous: true,
    level_since: "2026-07-15T03:52:00Z",
    contributors: { argus: 0.82, sentinel: 0.74, cassandra: 0.41 },
    corroboration: 2,
    reasons: ["argus:rate_spike", "sentinel:sqli_probe", "corroborated:2 models"],
    top_entities: [
      {
        entity_type: "ip",
        entity_id: "203.0.113.9",
        score: 0.88,
        models: { argus: 0.82, sentinel: 0.74 },
        corroborated: true,
        reasons: ["argus:rate_spike", "sentinel:sqli_probe"],
        last_update: "2026-07-15T03:59:40Z",
      },
      {
        entity_type: "payer",
        entity_id: "acct-201",
        score: 0.44,
        models: { cassandra: 0.41 },
        corroborated: false,
        reasons: ["cassandra:slow_exfiltration"],
        last_update: "2026-07-15T03:59:10Z",
      },
    ],
    recent_transitions: [
      { at: "2026-07-15T03:40:00Z", from: "normal", to: "elevated", score: 0.5 },
      { at: "2026-07-15T03:52:00Z", from: "elevated", to: "critical", score: 0.74 },
    ],
  }),
);

export const SENTINEL_OFFLINE = snapshotWith(
  baseThreat({
    threat_level: "elevated",
    anomaly_score: 0.5,
    is_anomalous: true,
    contributors: { argus: 0.55 },
    corroboration: 1,
    reasons: ["argus:error_ratio_spike"],
  }),
  { offline: ["sentinel"] },
);

export const FUSION_DOWN = snapshotWith(null);

export const EVERYTHING_DOWN = snapshotWith(null, {
  offline: ["argus", "sentinel", "cassandra"],
});

export const UNKNOWN_TAG = snapshotWith(
  baseThreat({
    threat_level: "elevated",
    anomaly_score: 0.5,
    is_anomalous: true,
    contributors: { argus: 0.5 },
    corroboration: 1,
    reasons: ["argus:weird_new_tag"],
    top_entities: [
      {
        entity_type: "ip",
        entity_id: "192.0.2.1",
        score: 0.5,
        models: { argus: 0.5 },
        corroborated: false,
        reasons: ["argus:weird_new_tag"],
        last_update: "2026-07-15T03:59:00Z",
      },
    ],
  }),
);
