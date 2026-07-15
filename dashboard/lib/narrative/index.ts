// Deterministic, template-based incident narrative — explicitly NOT an LLM.
// Same snapshot in, same words out: every sentence is assembled from the
// fixed fragments in templates.ts, and `now` defaults to the snapshot's own
// server timestamp so repeated calls over one frozen snapshot are identical.
// Constraint: this directory stays erasable-syntax-only TypeScript (no
// enums/namespaces) with explicit .ts extensions on value imports, so
// `node --test` runs it directly via type stripping.

import type { FusionThreat, NarrativeReport, PulseSnapshot, ThreatLevel } from "../types";
import { HEADLINES, MODEL_NAMES, OFFLINE_HEADLINE, REASON_TEXT } from "./templates.ts";

const SCORERS = ["argus", "sentinel", "cassandra"] as const;

function modelName(model: string): string {
  return MODEL_NAMES[model] ?? model.toUpperCase();
}

// "argus:rate_spike" -> "a spike in request rate"; unknown tags are humanized
// (underscores dropped) instead of leaking raw machine tags to the operator.
export function humanizeReason(reason: string): { model: string | null; text: string } {
  const idx = reason.indexOf(":");
  const model = idx > 0 ? reason.slice(0, idx) : null;
  const tag = idx > 0 ? reason.slice(idx + 1) : reason;
  const text = REASON_TEXT[tag] ?? tag.replace(/_/g, " ").trim();
  return { model: model !== null ? modelName(model) : null, text };
}

function utcClock(iso: string): string | null {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : `${new Date(t).toISOString().slice(11, 19)} UTC`;
}

function listJoin(parts: string[]): string {
  if (parts.length <= 1) return parts[0] ?? "";
  return `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}

function severity(level: ThreatLevel): number {
  return level === "critical" ? 2 : level === "elevated" ? 1 : 0;
}

function statusParagraph(threat: FusionThreat): string {
  const score = threat.anomaly_score.toFixed(3);
  const since = threat.level_since !== null ? utcClock(threat.level_since) : null;
  const sinceText = since !== null ? ` since ${since}` : "";
  if (threat.threat_level === "normal") {
    return (
      `No corroborated anomalous activity. The fused anomaly score is ${score} ` +
      `and the platform has been at normal${sinceText}, with ` +
      `${threat.entities_tracked} entities under observation.`
    );
  }
  const corr =
    threat.corroboration >= 2
      ? `${threat.corroboration} models corroborate the activity`
      : "a single model is driving the signal";
  return (
    `The platform has been at ${threat.threat_level.toUpperCase()}${sinceText} ` +
    `with a fused anomaly score of ${score}; ${corr}, with ` +
    `${threat.entities_tracked} entities under observation.`
  );
}

function driversParagraph(threat: FusionThreat): string | null {
  const ranked = Object.entries(threat.contributors)
    .filter(([, v]) => typeof v === "number" && v > 0)
    .sort(([, a], [, b]) => b - a);
  if (ranked.length === 0) return null;
  const [leadModel, leadScore] = ranked[0];
  let text = `The signal is driven primarily by ${modelName(leadModel)} (${leadScore.toFixed(2)})`;
  if (ranked.length > 1) {
    const rest = ranked.slice(1).map(([m, v]) => `${modelName(m)} (${v.toFixed(2)})`);
    text += `, with supporting signal from ${listJoin(rest)}`;
  }
  const seen = new Set<string>();
  const observed: string[] = [];
  for (const r of threat.reasons) {
    // "corroborated:N models" is fusion's own pseudo-reason; the corroboration
    // count already carries that information in the status paragraph.
    if (r.startsWith("corroborated:")) continue;
    const { text: t } = humanizeReason(r);
    if (t.length > 0 && !seen.has(t)) {
      seen.add(t);
      observed.push(t);
    }
  }
  if (observed.length > 0) text += `. Observed: ${listJoin(observed)}`;
  return `${text}.`;
}

function transitionSentence(threat: FusionThreat): string | null {
  const last = threat.recent_transitions[threat.recent_transitions.length - 1];
  if (last === undefined) return null;
  const clock = utcClock(last.at);
  const verb = severity(last.to) > severity(last.from) ? "escalated" : "de-escalated";
  return (
    `The threat level last ${verb} from ${last.from} to ${last.to}` +
    `${clock !== null ? ` at ${clock}` : ""} (score ${last.score.toFixed(3)} at the transition).`
  );
}

function entityBullets(threat: FusionThreat): string[] {
  const interesting = threat.top_entities.filter((e) => e.corroborated || e.score > 0);
  const picked = (interesting.length > 0 ? interesting : threat.top_entities).slice(0, 5);
  return picked.map((e) => {
    const models = Object.entries(e.models)
      .sort(([, a], [, b]) => b - a)
      .map(([m]) => modelName(m));
    const seen = new Set<string>();
    const reasons: string[] = [];
    for (const r of e.reasons) {
      const { text } = humanizeReason(r);
      if (text.length > 0 && !seen.has(text)) {
        seen.add(text);
        reasons.push(text);
      }
    }
    const flaggedBy = models.length > 0 ? `flagged by ${listJoin(models)}` : "flagged";
    const corrNote = e.corroborated ? ", corroborated" : "";
    const reasonNote = reasons.length > 0 ? `: ${listJoin(reasons)}` : "";
    return `${e.entity_type} ${e.entity_id} (score ${e.score.toFixed(2)}${corrNote}) — ${flaggedBy}${reasonNote}`;
  });
}

function offlineNames(snapshot: PulseSnapshot): string[] {
  return SCORERS.filter((s) => !snapshot.scorers[s].health.ok).map(modelName);
}

export function buildNarrative(
  snapshot: PulseSnapshot,
  now: Date = new Date(snapshot.fetched_at),
): NarrativeReport {
  const generated_at = Number.isNaN(now.getTime()) ? snapshot.fetched_at : now.toISOString();
  const offline = offlineNames(snapshot);

  if (!snapshot.fusion.ok) {
    const reachable = SCORERS.filter((s) => snapshot.scorers[s].health.ok).map(modelName);
    const paragraphs = [
      `The fusion engine could not be reached at snapshot time (${snapshot.fusion.error}), ` +
        "so no fused threat picture is available.",
      reachable.length > 0
        ? `${listJoin(reachable)} ${reachable.length === 1 ? "was" : "were"} still reachable and scoring independently.`
        : "No scorer was reachable either — the monitoring pipeline is down or unreachable from the HUD.",
    ];
    return { headline: OFFLINE_HEADLINE, paragraphs, bullets: [], generated_at };
  }

  const threat = snapshot.fusion.data;
  const paragraphs: string[] = [statusParagraph(threat)];
  const drivers = driversParagraph(threat);
  if (drivers !== null) paragraphs.push(drivers);
  const transition = transitionSentence(threat);
  if (transition !== null) paragraphs.push(transition);
  if (offline.length > 0) {
    paragraphs.push(
      `${listJoin(offline)} ${offline.length === 1 ? "was" : "were"} unreachable at snapshot time; ` +
        "the fused picture may understate activity those models would have seen.",
    );
  }

  return {
    headline: HEADLINES[threat.threat_level],
    paragraphs,
    bullets: entityBullets(threat),
    generated_at,
  };
}
