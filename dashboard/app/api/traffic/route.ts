// Traffic overview proxy: reduces OpenSearch aggregations over
// guardian-traffic-* to the TrafficSummary contract. Always 200 with a
// SourceResult body (same degradation contract as /api/pulse); only an
// unknown window is a caller error. force-dynamic is load-bearing — see
// app/api/pulse/route.ts.

import { fetchTraffic, isTrafficWindow } from "@/lib/upstream";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const window = new URL(req.url).searchParams.get("window") ?? "1h";
  if (!isTrafficWindow(window)) {
    return Response.json({ ok: false, error: `unknown window ${window}` }, { status: 400 });
  }
  return Response.json(await fetchTraffic(window));
}
