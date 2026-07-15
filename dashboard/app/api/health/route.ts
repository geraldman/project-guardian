// Liveness for the compose healthcheck (frozen contract: GET /api/health on
// :3000 must return 2xx while the server is up). Deliberately NOT gated on
// upstream reachability — compose depends_on already gates startup, and tying
// liveness to scorers would flap the container whenever one restarts.

export const dynamic = "force-dynamic";

export function GET() {
  return Response.json({
    status: "ok",
    service: "guardian-pulse",
    time: new Date().toISOString(),
  });
}
