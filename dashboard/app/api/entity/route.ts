// Entity drilldown proxy: assembles the "case file" behind one Top Entities
// row — each detector's own baseline for the entity plus its recent raw
// events. Query params instead of a dynamic segment because entity ids are
// upstream-controlled strings (IPs, payer ids) and belong in the querystring.
// force-dynamic is load-bearing — see app/api/pulse/route.ts.

import { fetchEntityCase } from "@/lib/upstream";

export const dynamic = "force-dynamic";

const KNOWN_TYPES = new Set(["payer", "client_ip", "global"]);

export async function GET(req: Request) {
  const params = new URL(req.url).searchParams;
  const type = params.get("type") ?? "";
  const id = params.get("id") ?? "";
  if (!KNOWN_TYPES.has(type) || (type !== "global" && id === "")) {
    return Response.json({ ok: false, error: "need type=payer|client_ip|global and id" }, {
      status: 400,
    });
  }
  return Response.json(await fetchEntityCase(type, type === "global" ? "global" : id));
}
