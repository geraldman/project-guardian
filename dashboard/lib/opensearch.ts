// Server-only OpenSearch query client (read-only _search, nothing else).
//
// Uses node:https instead of fetch for one reason: the dev cluster ships the
// bundled self-signed certificate, and Node's fetch offers no per-request way
// to accept it without a process-wide NODE_TLS_REJECT_UNAUTHORIZED=0 hammer.
// Scoping the exception to this client keeps every other upstream call strict.
// Like lib/upstream.ts, these env vars must never reach client code.

import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import type { SourceResult } from "./types";

const OS_TIMEOUT_MS = 4000;

function osConfig() {
  return {
    url: process.env.OPENSEARCH_URL ?? "https://localhost:9200",
    user: process.env.OPENSEARCH_USER ?? "admin",
    password: process.env.OPENSEARCH_PASSWORD ?? "Guardian!Lti2026",
  };
}

/** POST /<index>/_search with the given body. Every failure mode (refused,
 *  timeout, non-2xx, bad JSON) becomes { ok: false } — same degradation
 *  contract as getJson() in upstream.ts, so a down OpenSearch can never sink
 *  a snapshot or a route. */
export function osSearch<T>(index: string, body: unknown): Promise<SourceResult<T>> {
  const { url, user, password } = osConfig();
  const target = new URL(`${url.replace(/\/$/, "")}/${index}/_search`);
  const payload = JSON.stringify(body);
  const req = target.protocol === "https:" ? httpsRequest : httpRequest;

  return new Promise((resolve) => {
    const r = req(
      target,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(payload),
          authorization: `Basic ${Buffer.from(`${user}:${password}`).toString("base64")}`,
        },
        // Dev-only trust exception for the cluster's self-signed cert; scoped
        // to this one client on purpose (see file header).
        rejectUnauthorized: false,
        timeout: OS_TIMEOUT_MS,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
            resolve({ ok: false, error: `HTTP ${res.statusCode ?? "?"}` });
            return;
          }
          try {
            resolve({ ok: true, data: JSON.parse(text) as T });
          } catch {
            resolve({ ok: false, error: "bad JSON from OpenSearch" });
          }
        });
      },
    );
    r.on("timeout", () => r.destroy(new Error("timeout")));
    r.on("error", (err) => resolve({ ok: false, error: err.message }));
    r.end(payload);
  });
}
