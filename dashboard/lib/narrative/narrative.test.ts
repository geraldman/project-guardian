// Run with: node --test lib/narrative/
// Replaced wholesale by WP-C; this proves the runner + type stripping work.

import { test } from "node:test";
import assert from "node:assert/strict";
import { buildNarrative } from "./index.ts";
import type { PulseSnapshot } from "../types";

const emptySnapshot: PulseSnapshot = {
  fetched_at: "2026-07-15T00:00:00.000Z",
  fusion: { ok: false, error: "unreachable" },
  scorers: {
    argus: { health: { ok: false, error: "unreachable" }, stats: { ok: false, error: "unreachable" } },
    sentinel: { health: { ok: false, error: "unreachable" }, stats: { ok: false, error: "unreachable" } },
    cassandra: { health: { ok: false, error: "unreachable" }, stats: { ok: false, error: "unreachable" } },
  },
};

test("buildNarrative is deterministic for a fixed now", () => {
  const now = new Date("2026-07-15T12:00:00.000Z");
  const a = buildNarrative(emptySnapshot, now);
  const b = buildNarrative(emptySnapshot, now);
  assert.deepEqual(a, b);
  assert.equal(a.generated_at, now.toISOString());
  assert.ok(a.headline.length > 0);
});
