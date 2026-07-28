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

// Shape of alerting's GET /stats (services/alerting/app/main.py): the deduper
// counters spread at the top level plus delivery bookkeeping. This is what
// makes the brief's 5-minute dedup window visible instead of implied.
export interface AlertingStats {
  sent: number;
  suppressed: number;
  tracked_keys: number;
  delivered: number;
  delivery_failures: number;
  malformed_messages: number;
  mode: string;
  [k: string]: unknown;
}

export interface ScorerPulse {
  health: SourceResult<ScorerHealth>;
  stats: SourceResult<ScorerStats>;
  drift_top?: SourceResult<DriftTop>; // cassandra only
}

export interface PulseSnapshot {
  fetched_at: string; // server-side ISO timestamp; every source below is from this instant
  fusion: SourceResult<FusionThreat>;
  alerting: SourceResult<AlertingStats>;
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

export type ModelName = "argus" | "sentinel" | "cassandra";

// Derived client-side by differencing each scorer's cumulative `events_consumed`
// between polls; fusion exposes no rate of its own. null while a first delta is
// still unavailable, or after a counter reset (service restart) makes it bogus.
export interface ScorerRate {
  eventsPerSecond: number | null;
  alerts: number | null;
}

export type ScorerRates = Record<ModelName, ScorerRate>;

// ── Traffic overview (GET /api/traffic) ─────────────────────────────────────
// Server-side aggregations over guardian-traffic-*; the browser never sees a
// raw OpenSearch response, only this reduced shape.

export type TrafficWindow = "15m" | "1h" | "6h" | "24h";

export interface TrafficBucket {
  t: number; // bucket start, epoch ms
  total: number;
  declined: number;
  errors: number;
  attacks: number; // security.is_attack docs (overlay, subset of total)
}

export interface TopCount {
  key: string;
  count: number;
}

export interface TrafficSummary {
  window: TrafficWindow;
  interval_seconds: number;
  buckets: TrafficBucket[];
  totals: { events: number; declined: number; errors: number; attacks: number };
  top_payers: TopCount[];
  top_ips: TopCount[];
  top_patterns: TopCount[]; // attack_pattern breakdown within the window
}

// ── Entity drilldown (GET /api/entity?type=..&id=..) ────────────────────────
// The "case file" behind a Top Entities row: each detector's own baseline
// state plus the raw events, so the verdict is inspectable, not asserted.

export interface EwStatsState {
  n: number;
  mean: number;
  var: number;
}

// ARGUS _baseline(): feature name -> EW stats (rate / error_rate / payload…,
// keys are the pipeline's choice — render defensively).
export interface ArgusBaseline {
  entity_type: string;
  entity_id: string;
  warming_up: boolean;
  features: Record<string, EwStatsState>;
}

// ARGUS /baseline/client_ip: cohort-wide, not per-IP (see docs/architecture.md).
export interface ArgusIpCohort {
  entity_type: "client_ip";
  cohort: Record<string, unknown>;
}

// cassandra CusumSeries.to_dict()
export interface CusumSeriesState {
  baseline: EwStatsState;
  s: number;
  run: number;
  ewma_z: number;
  excursion_start: number | null; // epoch seconds
}

export interface CassandraBaseline {
  entity_type: "payer";
  entity_id: string;
  warming_up: boolean;
  buckets_observed: number;
  volume: CusumSeriesState;
  amount: CusumSeriesState;
}

// One normalized guardian-traffic-* doc, flattened for display.
export interface EntityEvent {
  t: string; // @timestamp
  event_type: string | null;
  service: string | null;
  client_ip: string | null;
  payer_id: string | null;
  status: string | null;
  amount: number | null;
  currency: string | null;
  latency_ms: number | null;
  error: boolean;
  is_attack: boolean;
  attack_pattern: string | null;
  message: string | null;
}

export interface EntityCaseFile {
  entity_type: string;
  entity_id: string;
  fetched_at: string;
  // null = structurally not applicable for this entity type (e.g. cassandra
  // only baselines payers); SourceResult failure = applicable but unavailable.
  argus: SourceResult<ArgusBaseline | ArgusIpCohort> | null;
  cassandra: SourceResult<CassandraBaseline> | null;
  events: SourceResult<EntityEvent[]>;
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
  rates: ScorerRates | null;
}

export interface TopEntitiesProps {
  snapshot: PulseSnapshot | null;
}

export interface ContextStripProps {
  snapshot: PulseSnapshot | null;
  rates: ScorerRates | null;
}

export interface NarrativePanelProps {
  snapshot: PulseSnapshot | null;
}

export interface FreezeButtonProps {
  snapshot: PulseSnapshot | null;
  history: ScorePoint[];
}
