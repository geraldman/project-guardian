// Server-only upstream fetch layer (WP-0, frozen).
// Env vars come from the guardian-pulse compose block (docker-internal
// hostnames); the localhost fallbacks make `npm run dev` on the host work
// against the published ports with zero config. These URLs must never reach
// client code — the browser only ever talks to /api/*.

import { osSearch } from "./opensearch";
import type {
  AlertFeedData,
  AlertItem,
  AlertingStats,
  ArgusBaseline,
  ArgusIpCohort,
  CassandraBaseline,
  DriftTop,
  EntityCaseFile,
  EntityEvent,
  FusionThreat,
  PulseSnapshot,
  ScorerHealth,
  ScorerStats,
  SourceResult,
  TopCount,
  TrafficBucket,
  TrafficSummary,
  TrafficWindow,
} from "./types";

const UPSTREAM_TIMEOUT_MS = 2500;

function baseUrls() {
  return {
    fusion: process.env.FUSION_URL ?? "http://localhost:8006",
    argus: process.env.ARGUS_URL ?? "http://localhost:8002",
    sentinel: process.env.SENTINEL_URL ?? "http://localhost:8004",
    cassandra: process.env.CASSANDRA_URL ?? "http://localhost:8005",
    alerting: process.env.ALERTING_URL ?? "http://localhost:8003",
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
    alerting,
    argusHealth,
    argusStats,
    sentinelHealth,
    sentinelStats,
    cassandraHealth,
    cassandraStats,
    driftTop,
  ] = await Promise.all([
    getJson<FusionThreat>(`${u.fusion}/threat`),
    getJson<AlertingStats>(`${u.alerting}/stats`),
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
    alerting,
    scorers: {
      argus: { health: argusHealth, stats: argusStats },
      sentinel: { health: sentinelHealth, stats: sentinelStats },
      cassandra: { health: cassandraHealth, stats: cassandraStats, drift_top: driftTop },
    },
  };
}

// ── Traffic overview ────────────────────────────────────────────────────────

const WINDOWS: Record<TrafficWindow, { gte: string; intervalSeconds: number }> = {
  // Interval keeps every window near ~120 buckets so the timeline's density
  // is constant regardless of zoom.
  "15m": { gte: "now-15m", intervalSeconds: 10 },
  "1h": { gte: "now-1h", intervalSeconds: 30 },
  "6h": { gte: "now-6h", intervalSeconds: 180 },
  "24h": { gte: "now-24h", intervalSeconds: 600 },
};

export function isTrafficWindow(w: string): w is TrafficWindow {
  return w in WINDOWS;
}

interface OsAggsResponse {
  aggregations?: {
    timeline?: {
      buckets: Array<{
        key: number;
        doc_count: number;
        declined: { doc_count: number };
        errors: { doc_count: number };
        attacks: { doc_count: number };
      }>;
    };
    top_payers?: { buckets: Array<{ key: string; doc_count: number }> };
    top_ips?: { buckets: Array<{ key: string; doc_count: number }> };
    top_patterns?: { buckets: Array<{ key: string; doc_count: number }> };
  };
}

function terms(agg: { buckets: Array<{ key: string; doc_count: number }> } | undefined): TopCount[] {
  return (agg?.buckets ?? []).map((b) => ({ key: String(b.key), count: b.doc_count }));
}

export async function fetchTraffic(window: TrafficWindow): Promise<SourceResult<TrafficSummary>> {
  const { gte, intervalSeconds } = WINDOWS[window];
  const res = await osSearch<OsAggsResponse>("guardian-traffic-*", {
    size: 0,
    query: { range: { "@timestamp": { gte, lte: "now" } } },
    aggs: {
      timeline: {
        date_histogram: {
          field: "@timestamp",
          fixed_interval: `${intervalSeconds}s`,
          min_doc_count: 0,
          extended_bounds: { min: gte, max: "now" },
        },
        aggs: {
          declined: { filter: { term: { "transaction.status": "declined" } } },
          errors: { filter: { term: { error: true } } },
          attacks: { filter: { term: { "security.is_attack": true } } },
        },
      },
      top_payers: { terms: { field: "transaction.payer_id", size: 5 } },
      top_ips: { terms: { field: "network.client_ip", size: 5 } },
      top_patterns: { terms: { field: "security.attack_pattern", size: 6 } },
    },
  });
  if (!res.ok) return res;

  const buckets: TrafficBucket[] = (res.data.aggregations?.timeline?.buckets ?? []).map((b) => ({
    t: b.key,
    total: b.doc_count,
    declined: b.declined.doc_count,
    errors: b.errors.doc_count,
    attacks: b.attacks.doc_count,
  }));
  const totals = buckets.reduce(
    (acc, b) => {
      acc.events += b.total;
      acc.declined += b.declined;
      acc.errors += b.errors;
      acc.attacks += b.attacks;
      return acc;
    },
    { events: 0, declined: 0, errors: 0, attacks: 0 },
  );

  return {
    ok: true,
    data: {
      window,
      interval_seconds: intervalSeconds,
      buckets,
      totals,
      top_payers: terms(res.data.aggregations?.top_payers),
      top_ips: terms(res.data.aggregations?.top_ips),
      top_patterns: terms(res.data.aggregations?.top_patterns),
    },
  };
}

// ── Alert feed ──────────────────────────────────────────────────────────────

interface OsAlertsResponse {
  hits?: {
    total?: { value?: number };
    hits: Array<{ _source: Record<string, unknown> }>;
  };
}

function toAlert(src: Record<string, unknown>): AlertItem {
  return {
    t: str(pick(src, ["@timestamp"])) ?? "",
    id: str(pick(src, ["alert", "id"])) ?? "",
    source: str(pick(src, ["alert", "source"])) ?? "unknown",
    type: str(pick(src, ["alert", "type"])) ?? "unknown",
    severity: str(pick(src, ["alert", "severity"])) ?? "low",
    score: num(pick(src, ["alert", "score"])),
    entity_type: str(pick(src, ["alert", "entity_type"])),
    entity_id: str(pick(src, ["alert", "entity_id"])),
    summary: str(pick(src, ["alert", "summary"])),
  };
}

export async function fetchAlerts(limit: number): Promise<SourceResult<AlertFeedData>> {
  const res = await osSearch<OsAlertsResponse>("guardian-alerts-*", {
    size: Math.max(1, Math.min(limit, 100)),
    query: { range: { "@timestamp": { gte: "now-24h", lte: "now" } } },
    sort: [{ "@timestamp": { order: "desc" } }],
    track_total_hits: true,
  });
  if (!res.ok) return res;
  return {
    ok: true,
    data: {
      total_24h: res.data.hits?.total?.value ?? 0,
      alerts: (res.data.hits?.hits ?? []).map((h) => toAlert(h._source ?? {})),
    },
  };
}

// ── Entity drilldown ────────────────────────────────────────────────────────

interface OsHitsResponse {
  hits?: { hits: Array<{ _source: Record<string, unknown> }> };
}

// Defensive picks over the normalized doc: any missing field renders as null
// rather than breaking the case file.
function pick(src: Record<string, unknown>, path: string[]): unknown {
  let cur: unknown = src;
  for (const key of path) {
    if (typeof cur !== "object" || cur === null) return null;
    cur = (cur as Record<string, unknown>)[key];
  }
  return cur ?? null;
}

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function str(v: unknown): string | null {
  return typeof v === "string" && v !== "" ? v : null;
}

function toEvent(src: Record<string, unknown>): EntityEvent {
  return {
    t: str(pick(src, ["@timestamp"])) ?? "",
    event_type: str(pick(src, ["event", "type"])),
    service: str(pick(src, ["source", "service"])),
    client_ip: str(pick(src, ["network", "client_ip"])),
    payer_id: str(pick(src, ["transaction", "payer_id"])),
    status: str(pick(src, ["transaction", "status"])),
    amount: num(pick(src, ["transaction", "amount"])),
    currency: str(pick(src, ["transaction", "currency"])),
    latency_ms: num(pick(src, ["transaction", "latency_ms"])),
    error: pick(src, ["error"]) === true,
    is_attack: pick(src, ["security", "is_attack"]) === true,
    attack_pattern: str(pick(src, ["security", "attack_pattern"])),
    message: str(pick(src, ["log", "message"])),
  };
}

async function fetchEntityEvents(
  entityType: string,
  entityId: string,
): Promise<SourceResult<EntityEvent[]>> {
  const query =
    entityType === "payer"
      ? { term: { "transaction.payer_id": entityId } }
      : entityType === "client_ip"
        ? { term: { "network.client_ip": entityId } }
        : { match_all: {} }; // global: just the latest slice of traffic
  const res = await osSearch<OsHitsResponse>("guardian-traffic-*", {
    size: 20,
    query,
    sort: [{ "@timestamp": { order: "desc" } }],
  });
  if (!res.ok) return res;
  return { ok: true, data: (res.data.hits?.hits ?? []).map((h) => toEvent(h._source ?? {})) };
}

export async function fetchEntityCase(
  entityType: string,
  entityId: string,
): Promise<EntityCaseFile> {
  const u = baseUrls();

  const argusUrl =
    entityType === "payer"
      ? `${u.argus}/baseline/payer/${encodeURIComponent(entityId)}`
      : entityType === "client_ip"
        ? `${u.argus}/baseline/client_ip` // cohort-wide by design
        : entityType === "global"
          ? `${u.argus}/baseline/global`
          : null;

  const [argus, cassandra, events] = await Promise.all([
    argusUrl ? getJson<ArgusBaseline | ArgusIpCohort>(argusUrl) : Promise.resolve(null),
    entityType === "payer"
      ? getJson<CassandraBaseline>(`${u.cassandra}/baseline/payer/${encodeURIComponent(entityId)}`)
      : Promise.resolve(null), // cassandra only baselines payers
    fetchEntityEvents(entityType, entityId),
  ]);

  return {
    entity_type: entityType,
    entity_id: entityId,
    fetched_at: new Date().toISOString(),
    argus,
    cassandra,
    events,
  };
}
