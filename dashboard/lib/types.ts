// Frozen internal contract for Guardian Pulse (WP-0).
// Upstream shapes mirror services/fusion/app/engine.py snapshot() and the
// scorers' /health + /stats responses. Do not edit without orchestrator sign-off.

export type ThreatLevel = "normal" | "elevated" | "critical";

export interface FusionThreat {
  threat_level: ThreatLevel;
  anomaly_score: number; // decayed global score 0..1
  is_anomalous: boolean;
  level_since: string | null; // ISO timestamp
  contributors: Record<string, number>; // model -> strongest decayed unweighted claim
  corroboration: number; // max simultaneous active models on one entity
  reasons: string[]; // "model:reason_tag" strings
  top_entities: TopEntity[];
  recent_transitions: Transition[];
  entities_tracked: number;
  unknown_models: string[];
  counters: Record<string, number>;
  config: {
    weights: Record<string, number>;
    half_life_seconds: number;
    corroboration_boost: number;
    breadth_weight: number;
    min_contrib_events: number;
    thresholds: {
      elevated_up: number;
      elevated_down: number;
      critical_up: number;
      critical_down: number;
    };
  };
}

export interface TopEntity {
  entity_type: string;
  entity_id: string;
  score: number;
  models: Record<string, number>;
  corroborated: boolean;
  reasons: string[];
  last_update: string;
}

export interface Transition {
  at: string;
  from: ThreatLevel;
  to: ThreatLevel;
  score: number;
}

// Common core of every scorer's /health; per-scorer extras arrive via the
// index signature and are picked defensively by the panels.
export interface ScorerHealth {
  status: "ok" | "degraded";
  service: string;
  consumer_connected: boolean;
  [k: string]: unknown;
}

export interface ScorerStats {
  [k: string]: unknown;
}

// Shape of cassandra's GET /drift/top (services/cassandra/app/main.py):
// a ranked list under "top", not a payer-keyed record.
export interface DriftPayer {
  payer_id: string;
  cusum_volume: number;
  cusum_amount: number;
  buckets_elevated: number;
  warming_up: boolean;
  buckets_observed: number;
}

export interface DriftTop {
  top: DriftPayer[];
}

export type SourceResult<T> = { ok: true; data: T } | { ok: false; error: string };

export interface ScorerPulse {
  health: SourceResult<ScorerHealth>;
  stats: SourceResult<ScorerStats>;
  drift_top?: SourceResult<DriftTop>; // cassandra only
}

export interface PulseSnapshot {
  fetched_at: string; // server-side ISO timestamp; every source below is from this instant
  fusion: SourceResult<FusionThreat>;
  scorers: {
    argus: ScorerPulse;
    sentinel: ScorerPulse;
    cassandra: ScorerPulse;
  };
}

// Client-side score history (fusion keeps no history; the HUD accumulates its own).
export interface ScorePoint {
  t: number; // epoch ms
  score: number;
  level: ThreatLevel;
}

export type PulseStatus = "connecting" | "live" | "stale";

export interface NarrativeReport {
  headline: string;
  paragraphs: string[];
  bullets: string[];
  generated_at: string;
}

// Component prop contracts (frozen — page.tsx passes exactly these).
export interface ThreatIndicatorProps {
  snapshot: PulseSnapshot | null;
  history: ScorePoint[];
  status: PulseStatus;
}

export interface TransitionLogProps {
  snapshot: PulseSnapshot | null;
}

export interface HeartbeatRowProps {
  snapshot: PulseSnapshot | null;
}

export interface NarrativePanelProps {
  snapshot: PulseSnapshot | null;
}

export interface FreezeButtonProps {
  snapshot: PulseSnapshot | null;
  history: ScorePoint[];
}
