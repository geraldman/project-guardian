// Alert feed proxy: the newest slice of guardian-alerts-* (the emitted alert
// stream, pre-dedup — the notifier's sent/suppressed counters cover delivery).
// Always 200 with a SourceResult body. force-dynamic is load-bearing — see
// app/api/pulse/route.ts.

import { fetchAlerts } from "@/lib/upstream";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const raw = new URL(req.url).searchParams.get("limit");
  const limit = raw === null ? 30 : Number.parseInt(raw, 10);
  if (!Number.isFinite(limit) || limit < 1) {
    return Response.json({ ok: false, error: "limit must be a positive integer" }, { status: 400 });
  }
  return Response.json(await fetchAlerts(limit));
}
