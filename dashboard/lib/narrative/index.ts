// Deterministic, template-based incident narrative — explicitly NOT an LLM.
// Full engine lands in WP-C (feat/pulse-narrative); this stub freezes the
// signature. Constraint: this directory must stay erasable-syntax-only
// TypeScript (no enums/namespaces) and use explicit .ts extensions on value
// imports, so `node --test` can run it directly via type stripping.

import type { NarrativeReport, PulseSnapshot } from "../types";

export function buildNarrative(snapshot: PulseSnapshot, now: Date = new Date()): NarrativeReport {
  return {
    headline: "Narrative engine pending",
    paragraphs: [`Snapshot captured ${snapshot.fetched_at}.`],
    bullets: [],
    generated_at: now.toISOString(),
  };
}
