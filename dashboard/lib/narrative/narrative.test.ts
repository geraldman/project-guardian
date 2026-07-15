// Run with: node --test lib/narrative/*.test.ts

import { test } from "node:test";
import assert from "node:assert/strict";
import { buildNarrative, humanizeReason } from "./index.ts";
import {
  CRITICAL_CORROBORATED,
  ELEVATED_SINGLE,
  EVERYTHING_DOWN,
  FUSION_DOWN,
  QUIET,
  SENTINEL_OFFLINE,
  UNKNOWN_TAG,
} from "./fixtures.ts";

function fullText(snapshotReport: ReturnType<typeof buildNarrative>): string {
  return [snapshotReport.headline, ...snapshotReport.paragraphs, ...snapshotReport.bullets].join(
    "\n",
  );
}

test("quiet snapshot reads calm and reports the tracked entities", () => {
  const r = buildNarrative(QUIET);
  assert.match(r.headline, /Situation normal/);
  assert.match(fullText(r), /No corroborated anomalous activity/);
  assert.match(fullText(r), /42 entities/);
  assert.equal(r.bullets.length, 0);
});

test("elevated single-model snapshot names the driver and the entity", () => {
  const r = buildNarrative(ELEVATED_SINGLE);
  assert.match(r.headline, /ELEVATED/);
  assert.match(fullText(r), /driven primarily by ARGUS/);
  assert.match(fullText(r), /a spike in request rate/);
  assert.match(fullText(r), /10\.9\.8\.7/);
  assert.match(fullText(r), /escalated from normal to elevated at 03:58:00 UTC/);
});

test("critical corroborated snapshot names entities, models and corroboration", () => {
  const r = buildNarrative(CRITICAL_CORROBORATED);
  assert.match(r.headline, /CRITICAL/);
  const text = fullText(r);
  assert.match(text, /2 models corroborate/);
  assert.match(text, /driven primarily by ARGUS \(0\.82\)/);
  assert.match(text, /SENTINEL \(0\.74\)/);
  assert.match(text, /203\.0\.113\.9/);
  assert.match(text, /flagged by ARGUS and SENTINEL/);
  assert.match(text, /SQL-injection probing/);
  assert.match(text, /acct-201/);
  assert.match(text, /slow data-exfiltration/);
  // the pseudo-reason must not leak verbatim
  assert.doesNotMatch(text, /corroborated:2 models/);
});

test("offline scorer is acknowledged", () => {
  const r = buildNarrative(SENTINEL_OFFLINE);
  assert.match(fullText(r), /SENTINEL was unreachable at snapshot time/);
});

test("fusion down produces an outage narrative listing reachable scorers", () => {
  const r = buildNarrative(FUSION_DOWN);
  assert.match(r.headline, /fusion engine unreachable/);
  assert.match(fullText(r), /ARGUS, SENTINEL and CASSANDRA were still reachable/);

  const dark = buildNarrative(EVERYTHING_DOWN);
  assert.match(fullText(dark), /No scorer was reachable either/);
});

test("unknown reason tags are humanized, never leaked raw", () => {
  const r = buildNarrative(UNKNOWN_TAG);
  const text = fullText(r);
  assert.match(text, /weird new tag/);
  assert.doesNotMatch(text, /argus:weird_new_tag/);
  assert.deepEqual(humanizeReason("argus:weird_new_tag"), {
    model: "ARGUS",
    text: "weird new tag",
  });
});

test("deterministic: identical output for the same snapshot", () => {
  const a = buildNarrative(CRITICAL_CORROBORATED);
  const b = buildNarrative(CRITICAL_CORROBORATED);
  assert.deepEqual(a, b);
  // generated_at derives from the snapshot, not the wall clock
  assert.equal(a.generated_at, "2026-07-15T04:00:00.000Z");
});
