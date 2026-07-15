// Aggregate proxy (frozen contract): one poll from the browser fans out to all
// upstreams server-side and always returns 200 with per-source ok/error, so the
// HUD degrades per-panel instead of failing wholesale. force-dynamic is
// load-bearing — without it Next prerenders GET handlers at build time, which
// would try to reach the scorers during `docker build`.

import { fetchPulse } from "@/lib/upstream";

export const dynamic = "force-dynamic";

export async function GET() {
  return Response.json(await fetchPulse());
}
